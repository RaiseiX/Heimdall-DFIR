export function lignesParCollecteSql(): string {
  return `
    SELECT evidence_id, count(*)::bigint AS lignes
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id IS NOT NULL
     GROUP BY evidence_id`;
}
