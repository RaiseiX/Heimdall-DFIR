-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  ForensicLab — Migration idempotente (DB existante)                 ║
-- ║                                                                      ║
-- ║  À appliquer sur une DB initialisée avant M3/M5/M6/M8/M9            ║
-- ║  via : docker compose exec db psql -U forensiclab forensiclab        ║
-- ║        -f /docker-entrypoint-initdb.d/migrate.sql                   ║
-- ║                                                                      ║
-- ║  Toutes les commandes sont idempotentes (IF NOT EXISTS / IF EXISTS). ║
-- ╚══════════════════════════════════════════════════════════════════════╝

-- ─── M3 : Colonnes ajoutées aux tables existantes ────────────────────────────
ALTER TABLE cases    ADD COLUMN IF NOT EXISTS report_deadline TIMESTAMPTZ;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS scan_status VARCHAR(20) DEFAULT 'pending';
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS scan_threat  VARCHAR(500);

-- ─── M5 : MITRE ATT&CK ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_mitre_techniques (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id          UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    technique_id     VARCHAR(20) NOT NULL,
    tactic           VARCHAR(60) NOT NULL,
    technique_name   VARCHAR(200) NOT NULL,
    sub_technique_name VARCHAR(200),
    confidence       VARCHAR(20) DEFAULT 'medium',
    notes            TEXT,
    created_by       UUID REFERENCES users(id),
    created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mitre_case ON case_mitre_techniques(case_id);

-- ─── M1 : Super Timeline (collection_timeline) ───────────────────────────────
CREATE TABLE IF NOT EXISTS collection_timeline (
    id            BIGSERIAL PRIMARY KEY,
    case_id       UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    result_id     UUID REFERENCES parser_results(id) ON DELETE CASCADE,
    timestamp     TIMESTAMPTZ NOT NULL,
    artifact_type VARCHAR(50)  NOT NULL DEFAULT '',
    artifact_name VARCHAR(100) NOT NULL DEFAULT '',
    description   TEXT         NOT NULL DEFAULT '',
    source        VARCHAR(200) NOT NULL DEFAULT '',
    raw           JSONB        NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ct_case_ts   ON collection_timeline(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ct_case_type ON collection_timeline(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_ct_result    ON collection_timeline(result_id);

-- ─── M6 : Artifact Notes ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS artifact_notes (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  artifact_ref VARCHAR(128) NOT NULL,
  note         TEXT NOT NULL,
  author_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_artifact_notes_case_ref ON artifact_notes(case_id, artifact_ref);

-- ─── M8 : YARA rules & scan results ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS yara_rules (
  id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  description TEXT,
  content     TEXT NOT NULL,
  author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
  tags        VARCHAR[] DEFAULT '{}',
  is_active   BOOLEAN DEFAULT true,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS yara_scan_results (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  evidence_id     UUID REFERENCES evidence(id) ON DELETE CASCADE,
  case_id         UUID REFERENCES cases(id) ON DELETE CASCADE,
  rule_id         UUID REFERENCES yara_rules(id) ON DELETE CASCADE,
  rule_name       VARCHAR(200) NOT NULL,
  matched_strings JSONB DEFAULT '[]',
  scanned_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_yara_scan_case     ON yara_scan_results(case_id);
CREATE INDEX IF NOT EXISTS idx_yara_scan_evidence ON yara_scan_results(evidence_id);

-- ─── M8 : Sigma rules & hunt results ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sigma_rules (
  id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name                VARCHAR(200) NOT NULL,
  description         TEXT,
  content             TEXT NOT NULL,
  author_id           UUID REFERENCES users(id) ON DELETE SET NULL,
  logsource_category  VARCHAR(100),
  logsource_product   VARCHAR(100),
  tags                VARCHAR[] DEFAULT '{}',
  is_active           BOOLEAN DEFAULT true,
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sigma_hunt_results (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  case_id         UUID REFERENCES cases(id) ON DELETE CASCADE,
  rule_id         UUID REFERENCES sigma_rules(id) ON DELETE CASCADE,
  rule_name       VARCHAR(200) NOT NULL,
  match_count     INTEGER DEFAULT 0,
  matched_events  JSONB DEFAULT '[]',
  hunted_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sigma_hunt_case ON sigma_hunt_results(case_id);

-- ─── M9 : Threat Intelligence TAXII/STIX ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS taxii_feeds (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name            VARCHAR(200) NOT NULL,
  url             TEXT NOT NULL,
  api_root        VARCHAR(200),
  collection_id   VARCHAR(200),
  auth_type       VARCHAR(20) DEFAULT 'none',
  auth_value      TEXT,
  is_active       BOOLEAN DEFAULT true,
  last_fetched    TIMESTAMPTZ,
  indicator_count INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_correlations (
  id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  case_id        UUID REFERENCES cases(id) ON DELETE CASCADE,
  ioc_value      VARCHAR(500) NOT NULL,
  ioc_type       VARCHAR(20) NOT NULL,
  stix_id        VARCHAR(200),
  indicator_name VARCHAR(500),
  source_name    VARCHAR(200),
  matched_at     TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(case_id, ioc_value, stix_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_corr_case ON threat_correlations(case_id);
