-- ─────────────────────────────────────────────────────────────────────────────
-- migrate_v2.22.sql — memory_uploads : positional write support (chunk_size + received set)
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

ALTER TABLE memory_uploads
  ADD COLUMN IF NOT EXISTS chunk_size          BIGINT    NOT NULL DEFAULT 52428800,
  ADD COLUMN IF NOT EXISTS received_chunks_set INTEGER[] NOT NULL DEFAULT '{}';

COMMIT;
