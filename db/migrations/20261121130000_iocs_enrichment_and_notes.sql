SET lock_timeout = '5s';

ALTER TABLE iocs
  ADD COLUMN IF NOT EXISTS vt_malicious    INTEGER,
  ADD COLUMN IF NOT EXISTS vt_total        INTEGER,
  ADD COLUMN IF NOT EXISTS vt_verdict      VARCHAR(20),
  ADD COLUMN IF NOT EXISTS abuseipdb_score INTEGER,
  ADD COLUMN IF NOT EXISTS enriched_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS enrichment_data JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS notes           TEXT;

CREATE INDEX IF NOT EXISTS idx_iocs_vt_verdict
  ON iocs(vt_verdict) WHERE vt_verdict IS NOT NULL;
