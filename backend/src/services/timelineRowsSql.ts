// La requête qui rend une page de la SuperTimeline.
//
// Extraite de la route pour être exécutable par un test contre un vrai Postgres.
// Elle vivait en ligne, et son défaut ne se voyait pas à la lecture.
//
// Le défaut : `SELECT DISTINCT ON (k) … ORDER BY k, …, <tri de l'analyste>`.
// Postgres exige que le ORDER BY d'un DISTINCT ON commence par l'expression
// distincte — le tri demandé n'arrivait donc qu'en quatrième clé, où il ne
// départageait que les doublons d'un même groupe. Les lignes sortaient dans
// l'ordre des `dedupe_hash`. Mesuré sur la base réelle, tri `timestamp DESC` :
// 2024-09-05 · 2026-03-06 · 2022-05-07 · 2025-12-09 · 2026-02-23.
//
// Et le `LIMIT` étant à l'intérieur, ce n'était pas seulement l'ordre de la page
// qui était faux : c'était la page elle-même.
//
// Le dédoublonnage se fait donc dans une sous-requête, dont le seul rôle est de
// choisir quel doublon survit — la ligne la plus informative du groupe, d'où les
// clés `tags` puis longueur de description. Le tri de l'analyste s'applique
// ensuite, sur le résultat.

const COLONNES = (hostProj: string, rawCol: string) => `
                id, timestamp, artifact_type, artifact_name, description, source,
                ${hostProj} AS host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections${rawCol}`;

export interface RowsSqlInput {
  collapseDupes: boolean;
  hostProj: string;
  rawCol: string;
  whereRows: string;
  /** Déjà validé contre la liste blanche par l'appelant. */
  safeCol: string;
  direction: string;
  /** Index du premier paramètre de pagination : $n = LIMIT, $n+1 = OFFSET. */
  limitParam: number;
}

export function timelineRowsSql(i: RowsSqlInput): string {
  const pagination = `LIMIT $${i.limitParam} OFFSET $${i.limitParam + 1}`;
  // `id` en dernière clé dans les deux branches : sans départage stable, deux
  // lignes de même horodatage peuvent changer de page entre deux requêtes, et
  // l'analyste en voit une deux fois, ou aucune.
  const tri = `ORDER BY ${i.safeCol} ${i.direction} NULLS LAST, id ${i.direction}`;

  if (!i.collapseDupes) {
    return `SELECT ${COLONNES(i.hostProj, i.rawCol)}
           FROM collection_timeline
          WHERE ${i.whereRows}
          ${tri}
          ${pagination}`;
  }

  return `SELECT * FROM (
            SELECT DISTINCT ON (COALESCE(dedupe_hash, id::text))
              ${COLONNES(i.hostProj, i.rawCol)}
             FROM collection_timeline
            WHERE ${i.whereRows}
            ORDER BY COALESCE(dedupe_hash, id::text),
                     array_length(tags, 1) DESC NULLS LAST,
                     length(COALESCE(description, '')) DESC
          ) d
          ${tri}
          ${pagination}`;
}
