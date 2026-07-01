-- db/migrations/011_investigation_workspace.sql
-- Investigation workspace : notes structurées + suivi de workflow.

ALTER TABLE timeline_bookmarks
  ADD COLUMN IF NOT EXISTS significance TEXT,
  ADD COLUMN IF NOT EXISTS confidence   VARCHAR(20),
  ADD COLUMN IF NOT EXISTS links_to     UUID;

ALTER TABLE case_mitre_techniques
  ADD COLUMN IF NOT EXISTS significance TEXT,
  ADD COLUMN IF NOT EXISTS links_to     UUID;

CREATE TABLE IF NOT EXISTS investigation_steps (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  phase       VARCHAR(40) NOT NULL DEFAULT 'analysis',
  title       VARCHAR(300) NOT NULL,
  status      VARCHAR(20) NOT NULL DEFAULT 'todo',
  position    INTEGER NOT NULL DEFAULT 0,
  finding_ref UUID REFERENCES timeline_bookmarks(id) ON DELETE SET NULL,  -- bookmark rattaché (optionnel)
  assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_investigation_steps_case ON investigation_steps(case_id, phase, position);
