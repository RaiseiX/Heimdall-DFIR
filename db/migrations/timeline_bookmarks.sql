-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.12 — Timeline Bookmarks + Attack Chain       ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.12.sql

CREATE TABLE IF NOT EXISTS timeline_bookmarks (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id          UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  artifact_ref     VARCHAR(128),          -- djb2 hash (même que artifact_notes)
  event_timestamp  TIMESTAMPTZ,           -- horodatage de l'événement bookmarké
  title            VARCHAR(255) NOT NULL,
  description      TEXT,
  mitre_technique  VARCHAR(20),           -- ex: T1059.001
  mitre_tactic     VARCHAR(64),           -- ex: Execution
  color            VARCHAR(7) DEFAULT '#4d82c0',
  author_id        UUID REFERENCES users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bookmarks_case    ON timeline_bookmarks(case_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_tactic  ON timeline_bookmarks(case_id, mitre_tactic);
CREATE INDEX IF NOT EXISTS idx_bookmarks_ref     ON timeline_bookmarks(case_id, artifact_ref);
