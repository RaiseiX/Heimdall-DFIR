-- db/migrations/20260709000000_hunt_runs.sql
CREATE TABLE IF NOT EXISTS hunt_runs (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  status       VARCHAR(20) NOT NULL DEFAULT 'running'
    CONSTRAINT hunt_runs_status_check CHECK (status IN ('running','done','error')),
  trigger      VARCHAR(20),
  evidence_id  UUID,                       -- provenance only (no FK: evidence may be deleted)
  steps        JSONB NOT NULL DEFAULT '[]',
  started_at   TIMESTAMPTZ DEFAULT NOW(),
  finished_at  TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);
-- At most ONE running hunt per case (the per-case guard, enforced at DB level).
CREATE UNIQUE INDEX IF NOT EXISTS idx_hunt_runs_one_running
  ON hunt_runs(case_id) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_hunt_runs_case ON hunt_runs(case_id, started_at DESC);
