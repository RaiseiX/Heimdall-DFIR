// L'arbre des processus Windows, reconstruit depuis les événements Security 4688.
//
// ── Pourquoi ce n'est pas le même objet que l'arbre Linux ───────────────────
//
// Linux donne un INSTANTANÉ — 438 processus lus à un moment, sans horodatage,
// avec leur filiation déjà établie par `ppid`. Windows donne des ÉVÉNEMENTS de
// création, étalés dans le temps, dont il faut déduire la filiation. Les deux
// écrans se ressemblent, les deux données n'ont rien à voir.
//
// Mesuré le 2026-09-16 sur `LAB_Xtended` : 155 événements, 67 PID enfants
// distincts, étalés sur 20 jours et 8 journées. Et **13 PID portent deux images
// différentes** — recyclés d'une session à l'autre. Rattacher par le seul PID
// donnerait un parent faux pour près d'un nœud sur cinq.
//
// ── Ce qui rend le rattachement prouvable ───────────────────────────────────
//
// Windows fournit à la fois le PID du parent (`PayloadData3`) et son chemin
// (`PayloadData1`). L'heuristique peut donc être vérifiée contre la réponse que
// Windows donne lui-même : on rattache chaque enfant au 4688 le plus récent qui
// le précède avec ce PID, puis on compare le chemin obtenu au chemin déclaré.
//
// Résultat sur les données réelles : **127 rattachements, 127 concordants,
// zéro divergence**, y compris pour les 13 PID recyclés que l'ordre temporel
// départage. `parent_declared` est conservé dans la sortie pour que ce contrôle
// reste possible à l'écran, et pas seulement en test.
//
// ── Détails de format ───────────────────────────────────────────────────────
//
// Les PID sont en hexadécimal dans la charge utile (`PID: 0x2D8`), convertis en
// décimal ici. Un PID illisible écarte sa ligne plutôt que de faire échouer la
// requête entière. Le chemin du parent est vide quand le parent est le
// processus System (PID 4), pour lequel Windows n'en publie pas : c'est une
// absence légitime, pas une donnée manquante.

const PID_HEX = (champ: string, etiquette: string) =>
  `substring(raw->>'${champ}' from '${etiquette}: 0x([0-9A-Fa-f]{1,8})')`;

const EN_DECIMAL = (expr: string) => `('x' || lpad(${expr}, 8, '0'))::bit(32)::int`;

export function windowsProcessTreeSql(): string {
  return `
    WITH e AS (
      SELECT id, timestamp,
             ${EN_DECIMAL(PID_HEX('PayloadData2', 'PID'))}        AS pid,
             ${EN_DECIMAL(PID_HEX('PayloadData3', 'Parent PID'))} AS ppid,
             nullif(trim(raw->>'ExecutableInfo'), '')             AS image,
             nullif(trim(substring(raw->>'PayloadData1' from 'Parent process: (.*)$')), '')
                                                                  AS parent_declared,
             raw->>'UserName'                                     AS user_name,
             host_name
        FROM collection_timeline
       WHERE case_id = $1 AND evidence_id = $2
         AND artifact_type = 'evtx' AND event_id = '4688'
         AND timestamp IS NOT NULL
         AND ${PID_HEX('PayloadData2', 'PID')} IS NOT NULL
         AND ${PID_HEX('PayloadData3', 'Parent PID')} IS NOT NULL
    )
    SELECT c.id, c.timestamp, c.pid, c.ppid, c.image,
           c.parent_declared, c.user_name, c.host_name,
           (SELECT p.image FROM e p
             WHERE p.pid = c.ppid AND p.timestamp <= c.timestamp AND p.id <> c.id
             ORDER BY p.timestamp DESC LIMIT 1) AS parent_image,
           -- L'identifiant de l'evenement parent, pas seulement son PID : avec
           -- 13 PID recycles sur ce seul hote, un arbre construit sur le PID
           -- fusionnerait deux processus distincts en un seul noeud.
           (SELECT p.id FROM e p
             WHERE p.pid = c.ppid AND p.timestamp <= c.timestamp AND p.id <> c.id
             ORDER BY p.timestamp DESC LIMIT 1) AS parent_id
      FROM e c
     ORDER BY c.timestamp, c.id`;
}
