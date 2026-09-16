// La carte des processus, côté données. Deux requêtes, deux natures.
//
// ── Ce que ces requêtes montrent, et ce qu'elles ne montrent pas ────────────
//
// `catscale_proc_status` porte `timestamp_kind = 'inventory'` et AUCUN
// horodatage : c'est une photographie prise au moment de la collecte, pas une
// chronologie. Tout ce qui est construit dessus hérite de cette nature, et
// l'interface ne doit jamais le présenter comme une suite d'événements.
//
// ── Pourquoi aucune jointure vers le journal ────────────────────────────────
//
// Le journal systemd porte `_PID`, et la jointure paraît évidente. Mesuré sur
// l'hôte de référence le 2026-09-15 : 142 625 événements portent un PID présent
// dans l'instantané, répartis sur **35 démarrages distincts** et quatre mois.
// L'instantané n'en couvre qu'un seul, et les PID Linux se recyclent. Joindre
// sur le seul PID attribuerait à ces processus l'activité de 34 autres boots —
// faux par construction, et avec l'aplomb d'une vraie réponse.
//
// Un pivot vers les événements devra être contraint par `_BOOT_ID` et refuser
// de répondre quand la contrainte n'est pas satisfiable. Il n'est pas ici.
//
// ── Le partage, que l'arbre ne peut pas dire ────────────────────────────────
//
// Un arbre donne un parent par nœud. « Qui tient quel fichier » est un graphe
// biparti : sur l'hôte de référence, 262 des 364 fichiers supprimés sont tenus
// par plusieurs processus, jusqu'à 48 pour une même bibliothèque. C'est la
// seule relation que la hiérarchie est structurellement incapable d'exprimer.

// Sept chiffres au plus : un PID Linux plafonne à 4 194 304, et un `::int` sur
// une chaîne plus longue ferait déborder la requête entière au lieu d'ignorer
// une ligne. La borne est donc un garde-fou, pas une commodité.
const PID_NUM = `raw->>'pid' ~ '^[0-9]{1,7}$'`;

const FICHIERS = `
    SELECT (raw->>'pid')::int AS pid,
           raw->>'target'        AS target,
           artifact_type         AS kind,
           coalesce((raw->>'deleted')::boolean, false) AS deleted
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type IN ('catscale_proc_open_fd', 'catscale_proc_mapped_file')
       AND ${PID_NUM}`;

// Mesuré le 2026-09-15 : l'arbre nu coûte **88 ms**, les comptes de fichiers
// **4,8 s**. Les fusionner faisait payer le second au premier, pour un écran
// vide pendant cinq secondes alors que l'essentiel était prêt en un dixième.
// Les deux sont donc séparés, et l'interface affiche l'arbre sans attendre.
//
// L'index partiel idx_ct_proc_files ne change rien à ce coût : les comptes
// doivent lire les 89 582 lignes, et Postgres refuse l'Index Only Scan sur un
// index d'expression. Le partage, lui, passe de 3 231 à 860 ms.
/** Un processus par ligne, avec sa filiation. Sans les comptes : voir plus bas. */
export function processTreeSql(): string {
  return `
    WITH p AS (
      SELECT (raw->>'pid')::int  AS pid,
             coalesce((CASE WHEN raw->>'ppid' ~ '^[0-9]{1,7}$' THEN raw->>'ppid' END)::int, 0) AS ppid,
             description            AS name,
             split_part(coalesce(raw->>'state', ''), ' ', 1) AS state,
             raw->>'uid'            AS uid
        FROM collection_timeline
       WHERE case_id = $1 AND evidence_id = $2
         AND artifact_type = 'catscale_proc_status'
         AND ${PID_NUM}
    ),
    c AS (
      SELECT (raw->>'pid')::int AS pid,
             max(raw->>'command')  AS command_line,
             max(raw->>'user')     AS user_name
        FROM collection_timeline
       WHERE case_id = $1 AND evidence_id = $2
         AND artifact_type = 'catscale_process' AND ${PID_NUM}
       GROUP BY 1
    )
    SELECT p.pid, p.ppid, p.name, p.state, p.uid,
           c.command_line, c.user_name
      FROM p
      LEFT JOIN c ON c.pid = p.pid
     ORDER BY p.pid`;
}

/**
 * Un fichier supprimé par ligne, avec tous les processus qui le tiennent encore
 * ouvert. Les PID absents de l'arbre sont conservés : ils décrivent un décalage
 * entre les étapes de la collecte, ce qui est une information et non un déchet.
 */
export function sharedResourcesSql(): string {
  return `
    WITH d AS (
      SELECT DISTINCT pid, target FROM (${FICHIERS}) x WHERE deleted
    )
    SELECT target,
           count(*)          AS holders,
           array_agg(pid ORDER BY pid) AS pids
      FROM d
     GROUP BY target
    HAVING count(*) > 1
     ORDER BY count(*) DESC, target`;
}

/**
 * Le compte de ce que chaque processus tient ouvert. Séparé de l'arbre parce
 * qu'il coûte 4,8 s contre 88 ms — il doit lire les 89 582 lignes de fichiers
 * pour compter, et aucun index n'évite cette lecture.
 */
export function processFileCountsSql(): string {
  return `
    SELECT pid,
           count(*) FILTER (WHERE kind = 'catscale_proc_open_fd')     AS fd,
           count(*) FILTER (WHERE kind = 'catscale_proc_mapped_file') AS maps,
           count(*) FILTER (WHERE deleted)                            AS deleted_count
      FROM (${FICHIERS}) x
     GROUP BY pid`;
}
