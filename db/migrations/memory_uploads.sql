-- ─────────────────────────────────────────────────────────────────────────────
-- migrate_v2.20.sql — VolWeb : table memory_uploads pour l'upload chunké RAM
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

CREATE TABLE IF NOT EXISTS memory_uploads (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id          UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  filename         TEXT        NOT NULL,
  total_size       BIGINT      NOT NULL,
  dump_os          TEXT        NOT NULL DEFAULT 'windows' CHECK (dump_os IN ('windows', 'linux', 'mac')),
  temp_path        TEXT        NOT NULL,
  total_chunks     INTEGER     NOT NULL,
  received_chunks  INTEGER     NOT NULL DEFAULT 0,
  evidence_id      UUID        REFERENCES evidence(id) ON DELETE SET NULL,
  status           TEXT        NOT NULL DEFAULT 'uploading'
                               CHECK (status IN ('uploading', 'hashing', 'forwarding', 'complete', 'error')),
  error_message    TEXT,
  created_by       UUID        REFERENCES users(id) ON DELETE SET NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_uploads_case   ON memory_uploads(case_id);
CREATE INDEX IF NOT EXISTS idx_memory_uploads_status ON memory_uploads(status);

COMMIT;
