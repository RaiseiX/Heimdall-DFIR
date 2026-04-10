-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 004 — user_artifact_column_prefs                 ║
-- ║  Stores per-analyst column preferences per artifact type.   ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS user_artifact_column_prefs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id       UUID REFERENCES cases(id) ON DELETE CASCADE,
  artifact_type VARCHAR(64) NOT NULL,
  prefs         JSONB NOT NULL DEFAULT '{}',
  scope         VARCHAR(16) NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'case')),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, case_id, artifact_type, scope)
);

CREATE INDEX IF NOT EXISTS idx_uacp_user ON user_artifact_column_prefs(user_id);
CREATE INDEX IF NOT EXISTS idx_uacp_case ON user_artifact_column_prefs(case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_uacp_type ON user_artifact_column_prefs(artifact_type);
