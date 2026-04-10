-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.13 — ECS Columns on collection_timeline       ║
-- ║  + host/user aggregation index                               ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.13.sql

ALTER TABLE collection_timeline
  ADD COLUMN IF NOT EXISTS host_name            VARCHAR(256),
  ADD COLUMN IF NOT EXISTS user_name            VARCHAR(256),
  ADD COLUMN IF NOT EXISTS process_name         VARCHAR(512),
  ADD COLUMN IF NOT EXISTS mitre_technique_id   VARCHAR(20),
  ADD COLUMN IF NOT EXISTS mitre_technique_name VARCHAR(200),
  ADD COLUMN IF NOT EXISTS mitre_tactic         VARCHAR(64);

-- Indexes for the new filter columns (partial — only rows where value is set)
CREATE INDEX IF NOT EXISTS idx_ct_host    ON collection_timeline(case_id, host_name)    WHERE host_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_user    ON collection_timeline(case_id, user_name)    WHERE user_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_mitre   ON collection_timeline(case_id, mitre_tactic) WHERE mitre_tactic IS NOT NULL;
