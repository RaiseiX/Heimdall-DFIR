-- ╔══════════════════════════════════════════════════════════════╗
-- ║   Migration — Index de boot pour les jobs de réconciliation   ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Two boot jobs scan collection_timeline on every server start and
-- competed with each other (observed: 3× `SELECT DISTINCT case_id`
-- running for minutes, delaying the ES index rebuild):
--
--   1. reconcileAllCases()  → SELECT DISTINCT case_id
--      A dedicated (case_id) btree lets PG satisfy DISTINCT with a
--      small index-only scan instead of a seq scan over 3.5M wide rows.
--
--   2. reconcileEvidenceLinks() → UPDATE … WHERE evidence_id IS NULL
--      A partial index on (result_id) WHERE evidence_id IS NULL makes
--      the relink scan only touch the (usually empty) unlinked set.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_case_id_only
  ON collection_timeline(case_id);

CREATE INDEX IF NOT EXISTS idx_ct_unlinked_result
  ON collection_timeline(result_id)
  WHERE evidence_id IS NULL;
