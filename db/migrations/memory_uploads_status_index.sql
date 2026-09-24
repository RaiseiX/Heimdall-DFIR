-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 009 — memory_uploads: add missing columns         ║
-- ║                                                              ║
-- ║  002_volweb_integration.sql created the memory_uploads       ║
-- ║  table but omitted two columns that the backend routes use:  ║
-- ║                                                              ║
-- ║  • chunk_size         BIGINT  — per-session chunk size       ║
-- ║  • received_chunks_set INTEGER[] — set of received indices   ║
-- ║                                                              ║
-- ║  Without these columns every chunk upload fails with         ║
-- ║  "column does not exist" at the DB level.                    ║
-- ╚══════════════════════════════════════════════════════════════╝

ALTER TABLE memory_uploads
  ADD COLUMN IF NOT EXISTS chunk_size          BIGINT       NOT NULL DEFAULT 52428800,
  ADD COLUMN IF NOT EXISTS received_chunks_set INTEGER[]    NOT NULL DEFAULT '{}';

-- Index: fast lookup of a specific upload_id + status (used in chunk handler hot-path)
CREATE INDEX IF NOT EXISTS idx_memory_uploads_id_status
  ON memory_uploads(id, status);
