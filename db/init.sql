-- ╔══════════════════════════════════════════════════════════════╗
-- ║                  ForensicLab Database Schema                ║
-- ╚══════════════════════════════════════════════════════════════╝

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── ENUM Types ───
-- PostgreSQL has no CREATE TYPE IF NOT EXISTS syntax.
-- We use a DO block that silently ignores duplicate_object errors,
-- making init.sql safe to re-run on an existing volume.
DO $$ BEGIN
    CREATE TYPE user_role     AS ENUM ('admin', 'analyst');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE case_status   AS ENUM ('active', 'pending', 'closed', 'archived');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE case_priority AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE evidence_type AS ENUM ('log', 'memory', 'network', 'binary', 'disk', 'collection', 'config', 'text', 'registry', 'prefetch', 'browser', 'other');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE event_type    AS ENUM ('alert', 'malware', 'exfil', 'network', 'analysis', 'response', 'persistence', 'lateral', 'discovery', 'other');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    CREATE TYPE ioc_type      AS ENUM ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'filename', 'registry_key', 'mutex', 'user_agent', 'email', 'other');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ─── Users ───
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'analyst',
    avatar_url VARCHAR(500),
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMPTZ,
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Cases ───
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_number VARCHAR(20) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status case_status NOT NULL DEFAULT 'active',
    priority case_priority NOT NULL DEFAULT 'medium',
    investigator_id UUID REFERENCES users(id),
    created_by UUID REFERENCES users(id),
    opened_at TIMESTAMPTZ DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    report_deadline TIMESTAMPTZ,
    volweb_case_id INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Case Tags ───
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    color VARCHAR(7) DEFAULT '#00d4ff',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE case_tags (
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, tag_id)
);

-- ─── Evidence ───
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255),
    file_path VARCHAR(500),
    file_size BIGINT,
    evidence_type evidence_type NOT NULL DEFAULT 'other',
    mime_type VARCHAR(100),
    hash_md5 VARCHAR(32),
    hash_sha1 VARCHAR(40),
    hash_sha256 VARCHAR(64),
    is_highlighted BOOLEAN DEFAULT false,
    notes TEXT,
    added_by UUID REFERENCES users(id),
    chain_of_custody JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    -- ClamAV antivirus scan result (M4)
    scan_status  VARCHAR(20) DEFAULT 'pending', -- 'pending' | 'clean' | 'quarantined' | 'error'
    scan_threat  VARCHAR(500),                   -- malware/virus name when scan_status='quarantined'
    -- VolWeb memory analysis integration
    volweb_evidence_id INTEGER,
    volweb_status VARCHAR(20) NOT NULL DEFAULT 'not_linked'
      CONSTRAINT evidence_volweb_status_check
        CHECK (volweb_status IN ('not_linked','uploading','processing','ready','error')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Evidence Comments ───
CREATE TABLE evidence_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    is_pinned BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Timeline Events ───
CREATE TABLE timeline_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL,
    event_type event_type NOT NULL DEFAULT 'other',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    source VARCHAR(100),
    evidence_id UUID REFERENCES evidence(id),
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── IOC (Indicators of Compromise) ───
CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    ioc_type ioc_type NOT NULL,
    value VARCHAR(500) NOT NULL,
    description TEXT,
    severity INTEGER DEFAULT 5 CHECK (severity >= 1 AND severity <= 10),
    is_malicious BOOLEAN,
    source VARCHAR(255),
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Network Connections (for map visualization) ───
CREATE TABLE network_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INTEGER,
    protocol VARCHAR(10),
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    packet_count INTEGER DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    geo_src JSONB DEFAULT '{}',
    geo_dst JSONB DEFAULT '{}',
    is_suspicious BOOLEAN DEFAULT false,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Artifact Parser Results ───
-- output_data is a JSONB array of event records.
-- It is populated incrementally via streaming CSV import (append batches).
CREATE TABLE parser_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id UUID REFERENCES evidence(id),
    parser_name VARCHAR(50) NOT NULL,
    parser_version VARCHAR(20),
    input_file VARCHAR(500),
    output_data JSONB NOT NULL DEFAULT '[]',
    record_count INTEGER DEFAULT 0,
    parsed_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Audit Log ───
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50),
    entity_id UUID,
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    hmac VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Reports ───
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content JSONB NOT NULL DEFAULT '{}',
    generated_by UUID REFERENCES users(id),
    file_path VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ═══ MITRE ATT&CK Mapping ═══
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

-- ═══ Collection Timeline Records ═══
-- Remplace le stockage de unified_timeline dans parser_results.output_data (JSONB).
-- Chaque enregistrement est une ligne dédiée → pas de limite sur le nombre d'événements.
CREATE TABLE IF NOT EXISTS collection_timeline (
    id                  BIGSERIAL PRIMARY KEY,
    case_id             UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    result_id           UUID REFERENCES parser_results(id) ON DELETE CASCADE,
    evidence_id         UUID REFERENCES evidence(id) ON DELETE CASCADE,  -- v2.18 isolation key
    timestamp           TIMESTAMPTZ NOT NULL,
    artifact_type       VARCHAR(50)  NOT NULL DEFAULT '',
    artifact_name       VARCHAR(200) NOT NULL DEFAULT '',
    description         TEXT         NOT NULL DEFAULT '',
    source              TEXT         NOT NULL DEFAULT '',
    raw                 JSONB        NOT NULL DEFAULT '{}',
    -- ECS columns (v2.13)
    host_name           VARCHAR(256),
    user_name           VARCHAR(256),
    process_name        VARCHAR(512),
    mitre_technique_id  VARCHAR(20),
    mitre_technique_name VARCHAR(200),
    mitre_tactic        VARCHAR(64),
    -- Unified forensic columns (v2.23, inspired by forensic-timeliner)
    tool                VARCHAR(32),
    timestamp_kind      VARCHAR(64),
    details             TEXT,
    "path"              TEXT,
    ext                 VARCHAR(16),
    event_id            INTEGER,
    file_size           BIGINT,
    src_ip              INET,
    dst_ip              INET,
    sha1                CHAR(40),
    tags                TEXT[]       NOT NULL DEFAULT '{}',
    dedupe_hash         CHAR(16),
    created_at          TIMESTAMPTZ  DEFAULT NOW()
);

-- ═══ Indexes ═══
CREATE INDEX idx_cases_status ON cases(status);
CREATE INDEX idx_cases_priority ON cases(priority);
CREATE INDEX idx_cases_investigator ON cases(investigator_id);
CREATE INDEX idx_evidence_case ON evidence(case_id);
CREATE INDEX idx_evidence_highlighted ON evidence(case_id, is_highlighted);
CREATE INDEX idx_timeline_case ON timeline_events(case_id);
CREATE INDEX idx_timeline_time ON timeline_events(event_time);
CREATE INDEX idx_iocs_case ON iocs(case_id);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_network_case ON network_connections(case_id);
CREATE INDEX idx_network_src ON network_connections(src_ip);
CREATE INDEX idx_network_dst ON network_connections(dst_ip);
CREATE INDEX idx_parser_results_case ON parser_results(case_id);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX idx_mitre_case ON case_mitre_techniques(case_id);
CREATE INDEX idx_ct_case_ts   ON collection_timeline(case_id, timestamp);
CREATE INDEX idx_ct_case_type ON collection_timeline(case_id, artifact_type);
CREATE INDEX idx_ct_result    ON collection_timeline(result_id);
CREATE INDEX idx_ct_evidence  ON collection_timeline(evidence_id);
CREATE INDEX idx_ct_case_ev_ts ON collection_timeline(case_id, evidence_id, timestamp);
-- ECS partial indexes (v2.13)
CREATE INDEX IF NOT EXISTS idx_ct_host  ON collection_timeline(case_id, host_name)    WHERE host_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_user  ON collection_timeline(case_id, user_name)    WHERE user_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_mitre ON collection_timeline(case_id, mitre_tactic) WHERE mitre_tactic IS NOT NULL;
-- Unified forensic partial indexes (v2.23)
CREATE INDEX IF NOT EXISTS idx_ct_case_tool     ON collection_timeline(case_id, tool)     WHERE tool     IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_event_id ON collection_timeline(case_id, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_ext      ON collection_timeline(case_id, ext)      WHERE ext      IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_case_sha1     ON collection_timeline(case_id, sha1)     WHERE sha1     IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ct_case_dedupe ON collection_timeline(case_id, dedupe_hash) WHERE dedupe_hash IS NOT NULL;

-- ═══ Default users are created by db/zz-init-users.sh (reads ADMIN_DEFAULT_PASSWORD
--     and ANALYST_DEFAULT_PASSWORD from the environment — see .env.example) ═══

-- ═══ Default Tags ═══
INSERT INTO tags (name, color) VALUES
('intrusion', '#ff3355'),
('malware', '#ff6b35'),
('ransomware', '#ff3355'),
('phishing', '#ffd740'),
('exfiltration', '#ff6b35'),
('dns-tunneling', '#00d4ff'),
('persistence', '#a78bfa'),
('lateral-movement', '#f472b6'),
('privilege-escalation', '#fb923c'),
('c2', '#ef4444'),
('data-theft', '#fbbf24'),
('insider-threat', '#8b5cf6'),
('apt', '#dc2626'),
('zero-day', '#b91c1c');

-- ═══ Demo Data ═══
-- Demo Case
INSERT INTO cases (case_number, title, description, status, priority, investigator_id, created_by, opened_at) VALUES
('CASE-2026-001', 'Intrusion Serveur Principal', 'Accès non autorisé détecté sur le serveur de production. Exfiltration de données suspectée via protocole DNS tunneling. Le serveur web (10.0.1.15) a été compromis via CVE-2025-31337.', 'active', 'critical',
  (SELECT id FROM users WHERE username = 'admin'),
  (SELECT id FROM users WHERE username = 'admin'),
  '2026-02-10 08:30:00+00'),
('CASE-2026-002', 'Ransomware Département Finance', 'Chiffrement de fichiers détecté sur les postes du département finance. Variante LockBit 4.0 identifiée. Vecteur initial: email de phishing avec macro malveillante.', 'active', 'high',
  (SELECT id FROM users WHERE username = 'analyst'),
  (SELECT id FROM users WHERE username = 'admin'),
  '2026-02-12 14:15:00+00'),
('CASE-2026-003', 'Analyse Clé USB Suspecte', 'Clé USB récupérée sur site lors d''une perquisition. Analyse du contenu et recherche de malware requise.', 'pending', 'medium',
  (SELECT id FROM users WHERE username = 'analyst'),
  (SELECT id FROM users WHERE username = 'admin'),
  '2026-02-14 09:00:00+00');

-- Demo IOCs
INSERT INTO iocs (case_id, ioc_type, value, description, severity, is_malicious, source, first_seen, tags) VALUES
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), 'domain', 'xz7.malware-c2.net', 'Domaine C2 utilisé pour DNS tunneling', 10, true, 'DNS Logs', '2026-02-10 02:14:00+00', ARRAY['c2', 'dns-tunneling']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), 'ip', '185.220.101.42', 'IP du serveur C2', 9, true, 'Network Capture', '2026-02-10 02:14:00+00', ARRAY['c2']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), 'hash_sha256', '9f8e7d6c5b4a3e2f1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8', 'Hash du malware backdoor', 10, true, 'EDR', '2026-02-10 02:20:00+00', ARRAY['malware', 'backdoor']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), 'ip', '10.0.1.15', 'Serveur compromis (web)', 7, false, 'Internal', '2026-02-10 02:14:00+00', ARRAY['compromised']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), 'ip', '10.0.2.30', 'Serveur base de données (mouvement latéral)', 6, false, 'Internal', '2026-02-10 03:00:00+00', ARRAY['lateral-movement']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-002'), 'hash_sha256', 'abc123def456789abc123def456789abc123def456789abc123def456789abcd', 'Hash LockBit 4.0 payload', 10, true, 'EDR', '2026-02-12 09:20:00+00', ARRAY['ransomware', 'lockbit']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-002'), 'email', 'invoice-feb@secure-payment.biz', 'Adresse email de phishing', 8, true, 'Email Gateway', '2026-02-12 09:00:00+00', ARRAY['phishing']),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-002'), 'domain', 'secure-payment.biz', 'Domaine de phishing', 9, true, 'Email Gateway', '2026-02-12 09:00:00+00', ARRAY['phishing']);

-- Demo Network Connections
INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen, is_suspicious, geo_src, geo_dst) VALUES
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), '10.0.1.15', 53421, '185.220.101.42', 53, 'UDP', 471859200, 1024000, 45000, '2026-02-10 02:14:00+00', '2026-02-10 02:20:00+00', true,
  '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
  '{"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173}'),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), '10.0.1.15', 44821, '10.0.2.30', 3306, 'TCP', 1024000, 268435456, 12000, '2026-02-10 03:00:00+00', '2026-02-10 03:30:00+00', true,
  '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
  '{"country": "FR", "city": "Paris", "lat": 48.8580, "lon": 2.3540}'),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), '10.0.1.15', 38912, '8.8.8.8', 53, 'UDP', 2048000, 512000, 3000, '2026-02-10 02:14:00+00', '2026-02-10 06:00:00+00', false,
  '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
  '{"country": "US", "city": "Mountain View", "lat": 37.3861, "lon": -122.0839}'),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-001'), '10.0.1.15', 22345, '91.198.174.192', 443, 'TCP', 50000, 120000, 200, '2026-02-10 02:30:00+00', '2026-02-10 02:31:00+00', false,
  '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
  '{"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041}'),
((SELECT id FROM cases WHERE case_number = 'CASE-2026-002'), '192.168.1.45', 49152, '203.0.113.66', 443, 'TCP', 45000, 2560000, 500, '2026-02-12 09:15:00+00', '2026-02-12 09:20:00+00', true,
  '{"country": "FR", "city": "Lyon", "lat": 45.7640, "lon": 4.8357}',
  '{"country": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074}');

-- ═══ Idempotent schema migrations (applied on restart for pre-existing DBs) ═══
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS scan_status VARCHAR(20) DEFAULT 'pending';
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS scan_threat VARCHAR(500);
ALTER TABLE cases    ADD COLUMN IF NOT EXISTS report_deadline TIMESTAMPTZ;
-- v2.16 — Legal Hold
ALTER TABLE cases    ADD COLUMN IF NOT EXISTS legal_hold    BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cases    ADD COLUMN IF NOT EXISTS legal_hold_at TIMESTAMPTZ;
ALTER TABLE cases    ADD COLUMN IF NOT EXISTS legal_hold_by UUID REFERENCES users(id);

-- ─── VolWeb database (Volatility 3 analysis engine — M5) ────────────────────
-- NOTE: runs only on a fresh pg_data volume.
-- For existing installs: docker exec forensiclab-db psql -U forensiclab -c "CREATE DATABASE volweb;"
CREATE DATABASE volweb;
GRANT ALL PRIVILEGES ON DATABASE volweb TO forensiclab;

-- Switch back to the forensiclab DB for the remainder of this script
\connect forensiclab

-- ─── Artifact Notes (M6) ───────────────────────────────────────────────────
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

-- ─── Threat Hunting — YARA (M8) ────────────────────────────────────────────
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

-- ─── Threat Hunting — Sigma (M8) ───────────────────────────────────────────
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

-- ─── VolWeb — Chunked Memory Upload tracking ─────────────────────────────────
CREATE TABLE IF NOT EXISTS memory_uploads (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id             UUID    NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_id         UUID    REFERENCES evidence(id) ON DELETE SET NULL,
  filename            VARCHAR(255) NOT NULL,
  total_size          BIGINT  NOT NULL,
  dump_os             VARCHAR(20)  NOT NULL DEFAULT 'windows'
                        CHECK (dump_os IN ('windows','linux','mac')),
  temp_path           VARCHAR(500) NOT NULL,
  total_chunks        INTEGER NOT NULL,
  received_chunks     INTEGER NOT NULL DEFAULT 0,
  chunk_size          BIGINT  NOT NULL DEFAULT 52428800,
  received_chunks_set INTEGER[] NOT NULL DEFAULT '{}',
  status              VARCHAR(20)  NOT NULL DEFAULT 'uploading'
                        CONSTRAINT memory_upload_status_check
                          CHECK (status IN ('uploading','hashing','forwarding','complete','error')),
  error_message       TEXT,
  created_by          UUID REFERENCES users(id),
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_uploads_case   ON memory_uploads(case_id);
CREATE INDEX IF NOT EXISTS idx_memory_uploads_status ON memory_uploads(status, created_at DESC);

-- ─── Threat Intelligence — TAXII / STIX (M9) ────────────────────────────────
CREATE TABLE IF NOT EXISTS taxii_feeds (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name            VARCHAR(200) NOT NULL,
  url             TEXT NOT NULL,
  api_root        VARCHAR(200),
  collection_id   VARCHAR(200),
  auth_type       VARCHAR(20) DEFAULT 'none',  -- 'none', 'bearer', 'basic'
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

-- ─── Triage Scores par Machine (v2.10) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS triage_scores (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  hostname    VARCHAR(255) NOT NULL,
  score       INTEGER NOT NULL DEFAULT 0,
  risk_level  VARCHAR(20) NOT NULL DEFAULT 'FAIBLE',
  event_count INTEGER NOT NULL DEFAULT 0,
  breakdown   JSONB NOT NULL DEFAULT '{}',
  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_triage_scores_case  ON triage_scores(case_id);
CREATE INDEX IF NOT EXISTS idx_triage_scores_score ON triage_scores(case_id, score DESC);

-- ─── Sysmon Configurations (v2.11) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sysmon_configs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_key     VARCHAR(64) UNIQUE NOT NULL,
  name           VARCHAR(128) NOT NULL,
  filename       VARCHAR(128) NOT NULL,
  is_recommended BOOLEAN NOT NULL DEFAULT FALSE,
  deployed_at    TIMESTAMPTZ,
  deployed_by    UUID REFERENCES users(id),
  notes          TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO sysmon_configs (config_key, name, filename, is_recommended) VALUES
  ('swifton_security',    'SwiftOnSecurity',            'swifton_security.xml',    TRUE),
  ('neo23x0',             'Neo23x0 (Florian Roth)',     'neo23x0.xml',             FALSE),
  ('olafhartong_modular', 'olafhartong sysmon-modular', 'olafhartong_modular.xml', FALSE),
  ('ion_storm',           'ion-storm',                  'ion_storm.xml',           FALSE)
ON CONFLICT (config_key) DO NOTHING;

-- ─── Timeline Bookmarks / Attack Chain (v2.12) ──────────────────────────────
CREATE TABLE IF NOT EXISTS timeline_bookmarks (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  artifact_ref    VARCHAR(128),
  event_timestamp TIMESTAMPTZ,
  title           VARCHAR(255) NOT NULL,
  description     TEXT,
  mitre_technique VARCHAR(20),
  mitre_tactic    VARCHAR(64),
  color           VARCHAR(7) DEFAULT '#4d82c0',
  author_id       UUID REFERENCES users(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bookmarks_case   ON timeline_bookmarks(case_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_tactic ON timeline_bookmarks(case_id, mitre_tactic);
CREATE INDEX IF NOT EXISTS idx_bookmarks_ref    ON timeline_bookmarks(case_id, artifact_ref);

-- ─── Case Chat Messages + Notifications (v2.14) ─────────────────────────────
CREATE TABLE IF NOT EXISTS case_messages (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id  UUID NOT NULL REFERENCES users(id),
  content    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_case ON case_messages(case_id, created_at);

CREATE TABLE IF NOT EXISTS case_notifications (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id    UUID REFERENCES cases(id) ON DELETE CASCADE,
  type       VARCHAR(50) NOT NULL DEFAULT 'info',
  payload    JSONB NOT NULL DEFAULT '{}',
  read       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON case_notifications(user_id, read, created_at DESC);

-- ─── JWT Refresh Tokens (v2.15) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rt_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens(expires_at) WHERE revoked = FALSE;

-- ─── Playbooks DFIR (v2.16) ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbooks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title         VARCHAR(200) NOT NULL,
  incident_type VARCHAR(50) NOT NULL DEFAULT 'generic',
  description   TEXT,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS playbook_steps (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  step_order      INTEGER NOT NULL,
  title           VARCHAR(300) NOT NULL,
  description     TEXT,
  note_required   BOOLEAN NOT NULL DEFAULT FALSE,
  mitre_technique VARCHAR(20),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(playbook_id, step_order)
);
CREATE TABLE IF NOT EXISTS case_playbooks (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  playbook_id  UUID NOT NULL REFERENCES playbooks(id),
  started_by   UUID REFERENCES users(id),
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  UNIQUE(case_id, playbook_id)
);
CREATE TABLE IF NOT EXISTS case_playbook_steps (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_playbook_id UUID NOT NULL REFERENCES case_playbooks(id) ON DELETE CASCADE,
  step_id          UUID NOT NULL REFERENCES playbook_steps(id),
  completed        BOOLEAN NOT NULL DEFAULT FALSE,
  note             TEXT,
  completed_by     UUID REFERENCES users(id),
  completed_at     TIMESTAMPTZ,
  UNIQUE(case_playbook_id, step_id)
);
CREATE INDEX IF NOT EXISTS idx_cp_case ON case_playbooks(case_id);
CREATE INDEX IF NOT EXISTS idx_cps_cp  ON case_playbook_steps(case_playbook_id);

-- ─── SOAR — Automated Hunt Alerts (v2.17) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS automated_hunt_alerts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  type            VARCHAR(20) NOT NULL CHECK (type IN ('yara','sigma','threat_intel','triage')),
  severity        VARCHAR(20) NOT NULL DEFAULT 'medium'
                              CHECK (severity IN ('critical','high','medium','low','info')),
  title           VARCHAR(300) NOT NULL,
  description     TEXT,
  details         JSONB NOT NULL DEFAULT '{}',
  source          VARCHAR(200) NOT NULL,
  triggered_by    VARCHAR(50) NOT NULL DEFAULT 'manual',
  acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
  acknowledged_by UUID REFERENCES users(id),
  acknowledged_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, type, source)
);
CREATE INDEX IF NOT EXISTS idx_aha_case     ON automated_hunt_alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_aha_case_ack ON automated_hunt_alerts(case_id, acknowledged);
CREATE INDEX IF NOT EXISTS idx_aha_severity ON automated_hunt_alerts(case_id, severity)
  WHERE acknowledged = FALSE;

-- ── Timeline Color Rules (v3.0 Sprint 2) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS timeline_color_rules (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID        REFERENCES cases(id) ON DELETE CASCADE,
  author_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
  name        VARCHAR(100) NOT NULL,
  priority    SMALLINT    NOT NULL DEFAULT 10,
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  color       CHAR(7)     NOT NULL,
  icon        VARCHAR(20),
  scope       VARCHAR(10) NOT NULL DEFAULT 'case' CHECK (scope IN ('global','case')),
  conditions  JSONB       NOT NULL DEFAULT '{"operator":"AND","rules":[]}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_color_rule_name_scope UNIQUE NULLS NOT DISTINCT (case_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tcr_case     ON timeline_color_rules(case_id, is_active, priority);
CREATE INDEX IF NOT EXISTS idx_tcr_global   ON timeline_color_rules(scope, is_active, priority) WHERE scope = 'global';
CREATE INDEX IF NOT EXISTS idx_tcr_author   ON timeline_color_rules(author_id);

-- Seed: 20 pre-built forensic color rules
INSERT INTO timeline_color_rules (name, priority, color, icon, scope, conditions) VALUES
('Mimikatz',               1,  '#EF4444', 'skull',       'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"mimikatz","case_sensitive":false}]}'),
('LSASS Access',           2,  '#DC2626', 'alert-circle','global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"lsass","case_sensitive":false}]}'),
('PowerShell Encoded',     3,  '#F97316', 'code',        'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"-enc","case_sensitive":false},{"field":"description","op":"contains","value":"EncodedCommand","case_sensitive":false},{"field":"description","op":"contains","value":"FromBase64String","case_sensitive":false}]}'),
('cmd.exe Spawn',          4,  '#FB923C', 'terminal',    'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"cmd.exe","case_sensitive":false},{"field":"artifact_type","op":"in","value":["evtx","hayabusa"]}]}'),
('Scheduled Task',         5,  '#EAB308', 'clock',       'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"schtasks","case_sensitive":false},{"field":"description","op":"contains","value":"Task Scheduler","case_sensitive":false}]}'),
('Lateral Movement SMB',   6,  '#F59E0B', 'network',     'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"ADMIN$","case_sensitive":false},{"field":"description","op":"contains","value":"IPC$","case_sensitive":false},{"field":"description","op":"contains","value":"C$","case_sensitive":false}]}'),
('New User Created',       7,  '#FBBF24', 'user-plus',   'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"net user /add","case_sensitive":false},{"field":"description","op":"contains","value":"4720","case_sensitive":false}]}'),
('RDP Login',              8,  '#3B82F6', 'monitor',     'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"RemoteInteractive","case_sensitive":false}]}'),
('Service Installed',      9,  '#60A5FA', 'settings',    'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"service installed","case_sensitive":false},{"field":"artifact_type","op":"equals","value":"evtx"}]}'),
('Process Hollowing',      10, '#B91C1C', 'zap',         'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"NtUnmapViewOfSection","case_sensitive":false},{"field":"description","op":"contains","value":"VirtualAllocEx","case_sensitive":false}]}'),
('Hayabusa Critical',      11, '#EF4444', 'alert-triangle','global','{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"hayabusa"},{"field":"raw.level","op":"equals","value":"critical"}]}'),
('Hayabusa High',          12, '#F97316', 'alert-triangle','global','{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"hayabusa"},{"field":"raw.level","op":"equals","value":"high"}]}'),
('Credential Access',      13, '#A855F7', 'key',         'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"credential_access"}]}'),
('Persistence',            14, '#9333EA', 'anchor',      'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"persistence"}]}'),
('Defense Evasion',        15, '#78716C', 'eye-off',     'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"defense_evasion"}]}'),
('SYSTEM Account Activity',16, '#6366F1', 'shield',      'global', '{"operator":"AND","rules":[{"field":"user_name","op":"equals","value":"SYSTEM"}]}'),
('Wget/Curl/WebRequest',   17, '#EA580C', 'download',    'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"wget","case_sensitive":false},{"field":"description","op":"contains","value":"curl ","case_sensitive":false},{"field":"description","op":"contains","value":"Invoke-WebRequest","case_sensitive":false}]}'),
('Base64 Payload',         18, '#C2410C', 'binary',      'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"base64","case_sensitive":false},{"field":"description","op":"contains","value":"FromBase64","case_sensitive":false}]}'),
('Registry Run Key',       19, '#CA8A04', 'database',    'global', '{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"registry"},{"field":"source","op":"contains","value":"\\Run","case_sensitive":false}]}'),
('Off-Hours Activity',     20, '#0EA5E9', 'moon',        'global', '{"operator":"AND","rules":[{"field":"artifact_type","op":"not_equals","value":"__never__"}]}')
ON CONFLICT DO NOTHING;
-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 004 — user_artifact_column_prefs                 ║
-- ║  Stores per-analyst column preferences per artifact type.   ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS user_artifact_column_prefs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id       UUID REFERENCES cases(id) ON DELETE CASCADE,
  artifact_type VARCHAR(64) NOT NULL,
  prefs         JSONB NOT NULL DEFAULT '{}',
  scope         VARCHAR(16) NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'case')),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, case_id, artifact_type, scope)
);

CREATE INDEX IF NOT EXISTS idx_uacp_user ON user_artifact_column_prefs(user_id);
CREATE INDEX IF NOT EXISTS idx_uacp_case ON user_artifact_column_prefs(case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_uacp_type ON user_artifact_column_prefs(artifact_type);
-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration 005 — timeline_pins                              ║
-- ║  Sticky pinned rows in the Super Timeline per analyst.      ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS timeline_pins (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  evidence_id  UUID REFERENCES evidence(id) ON DELETE CASCADE,
  -- The original ES document fields, stored for display even if ES data changes
  event_ts     TIMESTAMPTZ,
  artifact_type VARCHAR(64),
  description  TEXT,
  source       TEXT,
  raw_data     JSONB,
  note         TEXT,        -- analyst annotation on the pin
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(case_id, author_id, event_ts, source)
);

CREATE INDEX IF NOT EXISTS idx_tpins_case   ON timeline_pins(case_id);
CREATE INDEX IF NOT EXISTS idx_tpins_author ON timeline_pins(author_id, case_id);

-- ─── Migration Tracker ────────────────────────────────────────────────────────
-- Utilisé par db/migrate.sh pour éviter de ré-appliquer les migrations.
-- Sur une fresh install, toutes les migrations déjà incluses dans init.sql
-- sont pré-enregistrées ici afin que migrate.sh les skip automatiquement.

CREATE TABLE IF NOT EXISTS case_sessions (
  id          BIGSERIAL PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at    TIMESTAMPTZ,
  duration_s  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_case_sessions_case ON case_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_case_sessions_user ON case_sessions(user_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO schema_migrations (filename) VALUES
    ('migrate_v2.7.sql'),
    ('migrate_v2.8.sql'),
    ('migrate_v2.9.sql'),
    ('migrate_v2.10.sql'),
    ('migrate_v2.11.sql'),
    ('migrate_v2.12.sql'),
    ('migrate_v2.13.sql'),
    ('migrate_v2.14.sql'),
    ('migrate_v2.15.sql'),
    ('migrate_v2.16.sql'),
    ('migrate_v2.17.sql'),
    ('migrate_v2.18.sql'),
    ('migrate_v2.19.sql'),
    ('migrate_v2.20.sql'),
    ('migrate_v2.21.sql'),
    ('migrate_v2.22.sql'),
    ('001_performance_indexes.sql'),
    ('002_volweb_integration.sql'),
    ('003_color_rules.sql'),
    ('004_column_prefs.sql'),
    ('005_timeline_pins.sql'),
    ('006_parser_perf_indexes.sql'),
    ('007_risk_score.sql'),
    ('008_ioc_cross_case_view.sql'),
    ('20260322120000_ai_case_context.sql'),
    ('20260322140000_report_templates.sql')
ON CONFLICT DO NOTHING;
