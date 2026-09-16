-- v2.25 — Workbench Evidence Bridge: server-side sync + tamper-evident chain-of-custody ledger
-- Idempotent: uses CREATE TABLE IF NOT EXISTS.

BEGIN;

CREATE TABLE IF NOT EXISTS workbench_evidence_pins (
  pin_id                 UUID PRIMARY KEY,
  case_id                UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  collection_timeline_id BIGINT NULL,
  dedupe_hash            TEXT NULL,
  pinned_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  pinned_by              UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  timestamp              TIMESTAMPTZ NULL,
  artifact_type          VARCHAR(64) NULL,
  tool                   VARCHAR(64) NULL,
  source                 TEXT NULL,
  description            TEXT NULL,
  event_id               INTEGER NULL,
  host_name              TEXT NULL,
  user_name              TEXT NULL,
  mitre_technique_id     VARCHAR(16) NULL,
  tags                   TEXT[] DEFAULT ARRAY[]::TEXT[],
  note                   TEXT DEFAULT '',
  color                  VARCHAR(16) NULL,
  status                 VARCHAR(16) NOT NULL DEFAULT 'triage',
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wbpins_case        ON workbench_evidence_pins (case_id);
CREATE INDEX IF NOT EXISTS idx_wbpins_case_status ON workbench_evidence_pins (case_id, status);
CREATE INDEX IF NOT EXISTS idx_wbpins_ctid        ON workbench_evidence_pins (case_id, collection_timeline_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_wbpins_case_ctid
  ON workbench_evidence_pins (case_id, collection_timeline_id)
  WHERE collection_timeline_id IS NOT NULL;

-- Chain-of-custody ledger: append-only, hash-chained for tamper evidence.
-- Each row carries a SHA-256 of (prev_hash || canonical_payload_json), forming a verifiable chain per case.
CREATE TABLE IF NOT EXISTS workbench_evidence_audit (
  seq        BIGSERIAL PRIMARY KEY,
  case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  pin_id     UUID NOT NULL,
  actor_id   UUID NULL REFERENCES users(id) ON DELETE SET NULL,
  action     VARCHAR(16) NOT NULL,       -- pin | unpin | update | clear | import
  payload    JSONB NOT NULL,             -- canonical JSON of the mutation (or full row on pin/import)
  prev_hash  CHAR(64) NULL,              -- previous row's content_hash for this case_id
  content_hash CHAR(64) NOT NULL,        -- sha256(prev_hash || action || payload_canonical)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wbaudit_case_seq ON workbench_evidence_audit (case_id, seq);
CREATE INDEX IF NOT EXISTS idx_wbaudit_pin      ON workbench_evidence_audit (pin_id);

COMMIT;
