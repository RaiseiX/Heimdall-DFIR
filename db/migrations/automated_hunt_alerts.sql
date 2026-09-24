-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.17 — Automated Hunt Alerts (SOAR Engine)     ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.17.sql

CREATE TABLE IF NOT EXISTS automated_hunt_alerts (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  type            VARCHAR(20) NOT NULL CHECK (type IN ('yara','sigma','threat_intel','triage')),
  severity        VARCHAR(20) NOT NULL DEFAULT 'medium'
                              CHECK (severity IN ('critical','high','medium','low','info')),
  title           VARCHAR(300) NOT NULL,
  description     TEXT,
  details         JSONB        NOT NULL DEFAULT '{}',
  source          VARCHAR(200) NOT NULL,  -- rule name / hostname / 'TAXII/STIX'
  triggered_by    VARCHAR(50)  NOT NULL DEFAULT 'manual',
  acknowledged    BOOLEAN      NOT NULL DEFAULT FALSE,
  acknowledged_by UUID        REFERENCES users(id),
  acknowledged_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  -- One alert per unique (case, type, source) — refreshed on each SOAR run
  UNIQUE (case_id, type, source)
);

CREATE INDEX IF NOT EXISTS idx_aha_case     ON automated_hunt_alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_aha_case_ack ON automated_hunt_alerts(case_id, acknowledged);
CREATE INDEX IF NOT EXISTS idx_aha_severity ON automated_hunt_alerts(case_id, severity)
  WHERE acknowledged = FALSE;
