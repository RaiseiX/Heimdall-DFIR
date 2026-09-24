-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 002 — VolWeb Integration                         ║
-- ║  Liens cases ↔ VolWeb, tracking chunked uploads mémoire    ║
-- ╚══════════════════════════════════════════════════════════════╝

-- ─── Lier un cas Heimdall à son cas VolWeb ───────────────────────────────────
ALTER TABLE cases
  ADD COLUMN IF NOT EXISTS volweb_case_id INTEGER;

-- ─── Lier une evidence mémoire à son evidence VolWeb ────────────────────────
ALTER TABLE evidence
  ADD COLUMN IF NOT EXISTS volweb_evidence_id INTEGER,
  ADD COLUMN IF NOT EXISTS volweb_status      VARCHAR(20) NOT NULL DEFAULT 'not_linked'
    CONSTRAINT evidence_volweb_status_check
      CHECK (volweb_status IN ('not_linked','uploading','processing','ready','error'));

-- ─── Tracking des uploads mémoire en cours (chunked upload) ─────────────────
--
-- Permet de reprendre un upload interrompu et de suivre la progression
-- côté frontend via Socket.io.
--
CREATE TABLE IF NOT EXISTS memory_uploads (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id         UUID    NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_id     UUID    REFERENCES evidence(id) ON DELETE SET NULL,

  -- Fichier
  filename        VARCHAR(255) NOT NULL,
  total_size      BIGINT  NOT NULL,
  dump_os         VARCHAR(20)  NOT NULL DEFAULT 'windows'
                    CHECK (dump_os IN ('windows','linux','mac')),
  temp_path       VARCHAR(500) NOT NULL,

  -- Progression
  total_chunks    INTEGER NOT NULL,
  received_chunks INTEGER NOT NULL DEFAULT 0,

  -- État
  status          VARCHAR(20)  NOT NULL DEFAULT 'uploading'
                    CONSTRAINT memory_upload_status_check
                      CHECK (status IN ('uploading','hashing','forwarding','complete','error')),
  error_message   TEXT,

  created_by      UUID REFERENCES users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_uploads_case
  ON memory_uploads(case_id);
CREATE INDEX IF NOT EXISTS idx_memory_uploads_status
  ON memory_uploads(status, created_at DESC);
