-- db/migrations/20260708000000_ingestion_files.sql
CREATE TABLE IF NOT EXISTS ingestion_files (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  evidence_id       UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  case_id           UUID NOT NULL REFERENCES cases(id)    ON DELETE CASCADE,
  relative_path     TEXT NOT NULL,
  file_size         BIGINT,
  sha256            CHAR(64) NOT NULL,
  detected_type     VARCHAR(50),
  confidence        SMALLINT,
  parser_name       VARCHAR(50),
  parser_version    VARCHAR(20),
  status            VARCHAR(20) NOT NULL DEFAULT 'received'
    CONSTRAINT ingestion_files_status_check CHECK (status IN (
      'received','extracting','classified','queued','parsing',
      'parsed','empty','degraded','error','quarantined','skipped_duplicate')),
  status_detail     TEXT,
  dedup_of          UUID REFERENCES ingestion_files(id),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ingfiles_dedup
  ON ingestion_files(evidence_id, sha256, parser_name, parser_version);
CREATE INDEX IF NOT EXISTS idx_ingfiles_evidence_status
  ON ingestion_files(evidence_id, status);
