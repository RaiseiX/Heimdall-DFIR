-- ─────────────────────────────────────────────────────────────────────────────
-- migrate_v2.23.sql — SuperTimeline unified forensic columns (inspired by
-- acquiredsecurity/forensic-timeliner). Promotes raw JSONB fields to first-class
-- columns so the UI can render EventId / SHA1 / IP / size / tool without digging.
-- All columns are nullable so existing rows remain valid.
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

ALTER TABLE collection_timeline
  ADD COLUMN IF NOT EXISTS tool           VARCHAR(32),
  ADD COLUMN IF NOT EXISTS timestamp_kind VARCHAR(64),
  ADD COLUMN IF NOT EXISTS details        TEXT,
  ADD COLUMN IF NOT EXISTS "path"         TEXT,
  ADD COLUMN IF NOT EXISTS ext            VARCHAR(16),
  ADD COLUMN IF NOT EXISTS event_id       INTEGER,
  ADD COLUMN IF NOT EXISTS file_size      BIGINT,
  ADD COLUMN IF NOT EXISTS src_ip         INET,
  ADD COLUMN IF NOT EXISTS dst_ip         INET,
  ADD COLUMN IF NOT EXISTS sha1           CHAR(40),
  ADD COLUMN IF NOT EXISTS tags           TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS dedupe_hash    CHAR(16);

CREATE INDEX IF NOT EXISTS idx_ct_case_tool     ON collection_timeline(case_id, tool)     WHERE tool     IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_event_id ON collection_timeline(case_id, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_ext      ON collection_timeline(case_id, ext)      WHERE ext      IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_sha1     ON collection_timeline(case_id, sha1)     WHERE sha1     IS NOT NULL;

-- Partial unique index on (case_id, dedupe_hash) — idempotent cross-result ingest
-- while legacy rows (dedupe_hash NULL) keep existing semantics.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ct_case_dedupe
  ON collection_timeline(case_id, dedupe_hash)
  WHERE dedupe_hash IS NOT NULL;

COMMIT;
