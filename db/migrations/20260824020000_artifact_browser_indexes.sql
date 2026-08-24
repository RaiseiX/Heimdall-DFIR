-- ╔══════════════════════════════════════════════════════════════╗
-- ║   Migration — Index du navigateur d'artefacts                 ║
-- ╚══════════════════════════════════════════════════════════════╝
-- The artifact browser queries collection_timeline per
-- (case_id, evidence_id, artifact_type) and the summary aggregates
-- artifact_type with MAX(artifact_name). With no covering index the
-- planner seq-scans the whole case/evidence subset (GBs of raw JSONB):
-- the type summary took ~26 s, the evtx rows page ~5 s on a 3.5M-row
-- case. Both become index-only scans with these two indexes.

-- Summary: GROUP BY artifact_type + MAX(artifact_name) — INCLUDE makes
-- the aggregate index-only (artifact_name averages 11 bytes/row).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_case_ev_type_name
  ON collection_timeline (case_id, evidence_id, artifact_type)
  INCLUDE (artifact_name);

-- Rows: WHERE case+evidence+type ORDER BY timestamp DESC LIMIT 100 —
-- the sort is satisfied by the index, so the top-N stops early instead
-- of sorting the full filtered set.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_case_ev_type_ts
  ON collection_timeline (case_id, evidence_id, artifact_type, timestamp);
