-- ╔══════════════════════════════════════════════════════════════╗
-- ║    Migration v2.10 — Score de Triage par Machine           ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.10.sql

CREATE TABLE IF NOT EXISTS triage_scores (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  hostname      VARCHAR(255) NOT NULL,
  score         INTEGER NOT NULL DEFAULT 0,
  risk_level    VARCHAR(20) NOT NULL DEFAULT 'FAIBLE',
  event_count   INTEGER NOT NULL DEFAULT 0,
  breakdown     JSONB NOT NULL DEFAULT '{}',
  computed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_triage_scores_case  ON triage_scores(case_id);
CREATE INDEX IF NOT EXISTS idx_triage_scores_score ON triage_scores(case_id, score DESC);
