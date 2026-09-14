// La requête qui rend une page de la SuperTimeline.
//
// Extraite de la route pour être exécutable par un test contre un vrai Postgres.
// Elle vivait en ligne, et son défaut ne se voyait pas à la lecture.
//
// ── La bascule « dédoublonner » a été retirée le 2026-09-14 ──────────────────
//
// Elle ne supprimait aucune ligne. `uq_ct_case_dedupe` est UNIQUE sur
// (case_id, dedupe_hash) et existe en production ; les lignes sans hash sont
// distinguées par leur id. Mesuré sur la base réelle : 4 810 204 lignes avec
// dédoublonnage comme sans, à la ligne près.
//
// Elle cassait en revanche le tri. `SELECT DISTINCT ON (k) … ORDER BY k, …, <tri>`
// — Postgres exige que le ORDER BY d'un DISTINCT ON commence par l'expression
// distincte, si bien que le tri demandé n'arrivait qu'en quatrième clé, où il ne
// départageait que les doublons d'un même groupe. Mesuré, tri `timestamp DESC` :
// 2024-09-05 · 2026-03-06 · 2022-05-07 · 2025-12-09. Et le LIMIT étant à
// l'intérieur, ce n'était pas seulement l'ordre de la page qui était faux, c'était
// la page elle-même.
//
// La colonne `dedupe_hash` reste : elle porte l'index unique et la chaîne de
// custody de l'établi. Seule la bascule de requête disparaît.

const COLONNES = (hostProj: string, rawCol: string) => `
                id, timestamp, artifact_type, artifact_name, description, source,
                ${hostProj} AS host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections${rawCol}`;

export interface RowsSqlInput {
  hostProj: string;
  rawCol: string;
  whereRows: string;
  /** Déjà validé contre SORTABLE_COLUMNS par l'appelant. */
  safeCol: string;
  direction: string;
  /** Index du premier paramètre de pagination : $n = LIMIT, $n+1 = OFFSET. */
  limitParam: number;
}

export function timelineRowsSql(i: RowsSqlInput): string {
  // `id` en dernière clé : sans départage stable, deux lignes de même horodatage
  // peuvent changer de page entre deux requêtes, et l'analyste en voit une deux
  // fois, ou aucune.
  return `SELECT ${COLONNES(i.hostProj, i.rawCol)}
           FROM collection_timeline
          WHERE ${i.whereRows}
          ORDER BY ${i.safeCol} ${i.direction} NULLS LAST, id ${i.direction}
          LIMIT $${i.limitParam} OFFSET $${i.limitParam + 1}`;
}
