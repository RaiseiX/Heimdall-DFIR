-- Collaborative report editor: persisted Yjs draft per case.
CREATE TABLE IF NOT EXISTS report_drafts (
  case_id       UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  ydoc          BYTEA NOT NULL,
  text_snapshot JSONB NOT NULL DEFAULT '{}',
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
