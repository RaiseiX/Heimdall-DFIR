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

// ── Les sockets, et ce qui distingue un signal d'un bruit ───────────────────
//
// Mesure du 2026-09-16 sur l'hote de reference : 177 sockets, dont **40
// seulement portent un PID**. Les 137 autres sont TIME-WAIT — le noyau a libere
// le descripteur, le socket n'appartient plus a aucun processus. Piege a eviter :
// la cle `pid` existe sur les 177 lignes, c'est sa VALEUR qui est nulle sur 137.
// Tester `raw ? 'pid'` rend 100 %, tester la valeur rend 23 %.
//
// Les 40 restants se rattachent tous a l'instantane : 0 orphelin, 23 PID.
//
// Un compte brut ne dit rien. Ce qui separe le bruit du signal :
//
//   ecoute sur 127.0.0.1 / [::1]  -> port local, un debogueur d'IDE
//   ecoute sur 0.0.0.0 / [::]     -> joignable du reseau : porte derobee
//   etabli vers 10.0.0.5          -> trafic interne
//   etabli vers une IP routable   -> exfiltration ou commande et controle
//
// Mesure sur l'hote : 8 ecoutes exposees, 16 etablies vers l'exterieur.
//
// Les antislashs sont DOUBLES : dans un litteral de gabarit JavaScript, `\.`
// s'evalue en `.` et le point deviendrait un joker — `127.` matcherait alors
// `1275`, et n'importe quelle adresse commencant par trois chiffres passerait
// pour une loopback.
const LOOPBACK = `'^(127\\.|\\[::1\\])'`;

const NON_ROUTABLE = `'^(127\\.|\\[::1\\]|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.|\\[fe80:|0\\.0\\.0\\.0|\\[::\\]|\\*)'`;

const SOCKETS = `
    SELECT (raw->>'pid')::int AS pid,
           raw->>'state'      AS state,
           raw->>'netid'      AS proto,
           raw->>'local'      AS local_addr,
           raw->>'peer'       AS peer,
           raw->>'uid'        AS uid,
           (raw->>'state' = 'LISTEN' AND raw->>'local' !~ ${LOOPBACK})     AS exposed,
           (raw->>'state' = 'ESTAB'  AND raw->>'peer'  !~ ${NON_ROUTABLE}) AS external
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'catscale_network'
       AND ${PID_NUM}`;

// ── Le hachage du binaire ───────────────────────────────────────────────────
//
// CatScale hache `/proc/<pid>/exe`, et deux proprietes en decoulent.
//
// Le PID est DANS le chemin : le rattachement est direct, il ne passe pas par
// le chemin de l'executable. Mesure du 2026-09-16 : 277 hachages, tous de cette
// forme, 276 rattaches a l'instantane, 1 orphelin — un processus disparu entre
// deux etapes de la collecte.
//
// Et c'est l'image EN MEMOIRE qui est lue, pas le fichier sur disque. Un
// processus dont le binaire a ete supprime reste donc hachable : les 18
// binaires supprimes de l'hote ont tous leur SHA-1. C'est ce qui fait passer le
// drapeau « binaire supprime » de « suspect, inverifiable » a « suspect, et
// voici l'empreinte a rechercher ».
//
// Couverture : 278 executables lisibles, 276 haches. Les 160 fils du noyau n'en
// ont pas, et c'est normal — ils n'ont pas d'executable.
//
// `catscale_executable_hash` (150 223 lignes) est un AUTRE objet : l'inventaire
// des executables presents sur le disque, sans PID. Il ne sert pas ici.
const HACHAGES = `
    SELECT substring(raw->>'path' from '^/proc/([0-9]+)/exe$')::int AS pid,
           raw->>'sha1' AS sha1
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'catscale_process_hash'
       AND raw->>'path' ~ '^/proc/[0-9]{1,7}/exe$'`;

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
    -- Le binaire du processus lui-meme, et surtout : existe-t-il encore ?
    --
    -- Mesure du 2026-09-16 sur l'hote de reference : 18 processus sur 438
    -- tournent depuis un binaire supprime. C'est la signature de l'effacement
    -- apres lancement — le programme s'ecrit, s'execute, se supprime, et ne vit
    -- plus qu'en memoire. Ici ce sont des mises a jour d'applications, mais la
    -- colonne qui le dit doit exister pour le jour ou ce n'en sera pas une.
    --
    -- A ne pas confondre avec unreadable : 160 processus sur 438 n'ont pas
    -- d'executable lisible, parce que ce sont des fils du noyau. Les melanger
    -- noierait 18 signaux sous 160 absences normales.
    x AS (
      SELECT (raw->>'pid')::int AS pid,
             nullif(raw->>'exe', '')                              AS exe,
             coalesce((raw->>'deleted')::boolean, false)          AS exe_deleted,
             coalesce((raw->>'unreadable')::boolean, false)       AS exe_unreadable
        FROM collection_timeline
       WHERE case_id = $1 AND evidence_id = $2
         AND artifact_type = 'catscale_proc_exe' AND ${PID_NUM}
    ),
    h AS (${HACHAGES}),
    -- Une meme empreinte sous PLUSIEURS noms de processus. Mesure sur l'hote :
    -- 4 empreintes dans ce cas, dont une sous 8 noms (l'architecture
    -- multiprocessus de Firefox) et une sous celery et daphne (le meme
    -- interpreteur Python). Legitime ici, et exactement la forme que prend un
    -- masquage de nom de processus.
    hn AS (
      SELECT h.sha1, count(DISTINCT p.name)::int AS sha1_names
        FROM h JOIN p ON p.pid = h.pid
       GROUP BY h.sha1
    ),
    n AS (
      SELECT pid,
             count(*)::int                         AS net_total,
             count(*) FILTER (WHERE exposed)::int  AS net_listen_exposed,
             count(*) FILTER (WHERE external)::int AS net_estab_external
        FROM (${SOCKETS}) s
       GROUP BY pid
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
           c.command_line, c.user_name,
           x.exe,
           coalesce(x.exe_deleted, false)    AS exe_deleted,
           coalesce(x.exe_unreadable, false) AS exe_unreadable,
           coalesce(n.net_total, 0)          AS net_total,
           coalesce(n.net_listen_exposed, 0) AS net_listen_exposed,
           coalesce(n.net_estab_external, 0) AS net_estab_external,
           h.sha1,
           hn.sha1_names
      FROM p
      LEFT JOIN c  ON c.pid  = p.pid
      LEFT JOIN x  ON x.pid  = p.pid
      LEFT JOIN n  ON n.pid  = p.pid
      LEFT JOIN h  ON h.pid  = p.pid
      LEFT JOIN hn ON hn.sha1 = h.sha1
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

/**
 * Un socket par ligne, avec son processus. Seuls les sockets qui appartiennent
 * encore a un processus sortent : un TIME-WAIT n'a plus de proprietaire, et
 * l'afficher sous un PID serait une attribution inventee.
 */
export function processNetworkSql(): string {
  return `
    SELECT pid, state, proto, local_addr, peer, uid, exposed, external
      FROM (${SOCKETS}) s
     ORDER BY pid, state, local_addr`;
}
