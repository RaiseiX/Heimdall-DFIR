-- ╔══════════════════════════════════════════════════════════════╗
-- ║     Migration v2.9 — IOC Enrichissement (VT + AbuseIPDB)   ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.9.sql

ALTER TABLE iocs
  ADD COLUMN IF NOT EXISTS vt_malicious    INTEGER,
  ADD COLUMN IF NOT EXISTS vt_total        INTEGER,
  ADD COLUMN IF NOT EXISTS vt_verdict      VARCHAR(20),
  ADD COLUMN IF NOT EXISTS abuseipdb_score INTEGER,
  ADD COLUMN IF NOT EXISTS enriched_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS enrichment_data JSONB DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_iocs_vt_verdict
  ON iocs(vt_verdict) WHERE vt_verdict IS NOT NULL;
