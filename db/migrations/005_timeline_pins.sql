-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 005 — timeline_pins                              ║
-- ║  Sticky pinned rows in the Super Timeline per analyst.      ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS timeline_pins (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  evidence_id  UUID REFERENCES evidence(id) ON DELETE CASCADE,
  -- The original ES document fields, stored for display even if ES data changes
  event_ts     TIMESTAMPTZ,
  artifact_type VARCHAR(64),
  description  TEXT,
  source       TEXT,
  raw_data     JSONB,
  note         TEXT,        -- analyst annotation on the pin
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(case_id, author_id, event_ts, source)
);

CREATE INDEX IF NOT EXISTS idx_tpins_case   ON timeline_pins(case_id);
CREATE INDEX IF NOT EXISTS idx_tpins_author ON timeline_pins(author_id, case_id);
