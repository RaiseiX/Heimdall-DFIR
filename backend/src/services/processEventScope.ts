// Le pivot d'un processus vers ses événements, et la contrainte sans laquelle
// il serait faux.
//
// ── Le défaut que ce module existe pour empêcher ─────────────────────────────
//
// Un PID ne désigne rien dans le temps : Linux les recycle. Mesuré le
// 2026-09-15 sur l'hôte de référence, en joignant le journal aux 438 processus
// de l'instantané par le seul `_PID` :
//
//   sans contrainte          142 625 événements · 35 démarrages · depuis le 02/04
//   démarrage de la photo     58 414 événements ·  1 démarrage
//
// Soit 84 211 événements — 59 % — attribués à des processus qui ne les ont pas
// produits, avec des horodatages précis et l'allure d'une vraie réponse. C'est
// la pire classe de défaut pour un outil d'analyse : un analyste conclurait
// « ce processus a fait ça » sur l'activité d'un autre, trois mois plus tôt.
//
// ── Pourquoi la contrainte tient ─────────────────────────────────────────────
//
// L'instantané est daté à la seconde — les 438 lignes de `catscale_process`
// portent le même instant — et un seul démarrage couvre cet instant, son
// dernier événement tombant 4 secondes avant.
//
// Vérifié en plus, parce qu'un démarrage unique ne suffit pas à lui seul : le
// compteur de PID n'a pas bouclé pendant ce démarrage (2 242 768 au maximum
// dans l'instantané, 2 318 740 dans le journal, pour un plafond à 4 194 304),
// et seuls 3 PID y portent deux noms de processus distincts.
//
// Le nom lève ces derniers cas. Sur 61 paires (pid, comm) rattachées à l'arbre,
// 59 concordent : 58 407 événements corroborés contre 7 écartés.
//
// ── Ce que ce module ne fait pas ─────────────────────────────────────────────
//
// Il ne rend pas de page d'événements. La carte des processus produit des
// pivots, la SuperTimeline affiche les événements — elle a déjà le tri sur
// treize colonnes, les colonnes dynamiques, le regroupement et les favoris, et
// un second affichage divergerait du premier comme l'ont fait les quatre listes
// de tri fusionnées le 2026-09-14.

/**
 * Le démarrage pendant lequel l'instantané a été pris, et l'instant de la
 * collecte. Rend zéro ligne quand le démarrage n'est pas déterminable : un
 * pivot absent vaut mieux qu'un pivot faux.
 */
export function snapshotBootSql(): string {
  return `
    WITH photo AS (
      SELECT max(timestamp) AS taken_at
        FROM collection_timeline
       WHERE case_id = $1 AND evidence_id = $2
         AND artifact_type = 'catscale_process' AND timestamp IS NOT NULL
    )
    SELECT j.raw->>'_BOOT_ID' AS boot_id, p.taken_at
      FROM collection_timeline j, photo p
     WHERE j.case_id = $1 AND j.evidence_id = $2
       AND j.artifact_type = 'catscale_journal'
       AND j.raw->>'_BOOT_ID' IS NOT NULL
       AND p.taken_at IS NOT NULL
       AND j.timestamp IS NOT NULL
       AND j.timestamp <= p.taken_at
     ORDER BY j.timestamp DESC
     LIMIT 1`;
}

// Écrit en containment (`raw @> {...}`) et non en extraction (`raw->>'_PID' =`)
// parce que le premier se sert de l'index GIN existant sur `raw` et pas le
// second. Mesuré le 2026-09-15 sur les 1,8 M de lignes du journal, pour un
// processus : **5 664 ms en extraction, 208 ms en containment** — vingt-sept
// fois moins, sans ajouter le moindre index.
//
// Un compte pour TOUS les processus d'un coup reste hors de portée (8,3 s
// mesurées) : ce pivot se charge à la demande, quand un processus est choisi.
/**
 * Les événements du journal qu'on peut attribuer à un processus donné.
 * Paramètres : $1 dossier, $2 collecte, $3 pid, $4 nom du processus,
 * $5 démarrage de l'instantané, $6 plafond de lignes.
 */
export function processEventsScopeSql(): string {
  return `
    SELECT id, timestamp, artifact_type, description, source,
           raw->>'_COMM'     AS comm,
           raw->>'_EXE'      AS exe,
           raw->>'PRIORITY'  AS priority,
           raw->>'_SYSTEMD_UNIT' AS unit
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'catscale_journal'
       AND raw @> jsonb_build_object('_PID', $3::text, '_COMM', $4::text, '_BOOT_ID', $5::text)
     ORDER BY timestamp DESC
     LIMIT $6`;
}
