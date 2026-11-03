SET lock_timeout = '5s';

ALTER TABLE cases ADD COLUMN IF NOT EXISTS retention_exempt BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'collection_timeline' AND column_name = 'source_device') THEN
    ALTER TABLE collection_timeline ADD COLUMN source_device TEXT;
  END IF;
  IF (SELECT data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'collection_timeline' AND column_name = 'host_name') <> 'text' THEN
    ALTER TABLE collection_timeline ALTER COLUMN host_name TYPE text;
  END IF;
  IF (SELECT data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'collection_timeline' AND column_name = 'user_name') <> 'text' THEN
    ALTER TABLE collection_timeline ALTER COLUMN user_name TYPE text;
  END IF;
  IF (SELECT data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'collection_timeline' AND column_name = 'process_name') <> 'text' THEN
    ALTER TABLE collection_timeline ALTER COLUMN process_name TYPE text;
  END IF;
  IF (SELECT data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'collection_timeline' AND column_name = 'source_device') <> 'text' THEN
    ALTER TABLE collection_timeline ALTER COLUMN source_device TYPE text;
  END IF;
END $$;

ALTER TABLE network_connections ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE CASCADE;
ALTER TABLE network_connections
  ADD COLUMN IF NOT EXISTS process      TEXT,
  ADD COLUMN IF NOT EXISTS socket_state TEXT,
  ADD COLUMN IF NOT EXISTS src_host     TEXT;
CREATE INDEX IF NOT EXISTS idx_netconn_case_evidence ON network_connections(case_id, evidence_id);

ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS is_global BOOLEAN DEFAULT FALSE;
ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS promoted_by UUID REFERENCES users(id);
ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'evidence_volweb_status_check'
       AND conrelid = 'public.evidence'::regclass
       AND pg_get_constraintdef(oid) LIKE '%''complete''%'
  ) THEN
    ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_volweb_status_check;
    ALTER TABLE evidence ADD CONSTRAINT evidence_volweb_status_check
      CHECK (volweb_status IN ('uploading','processing','ready','complete','error','not_linked'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS hunt_verdicts (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id          UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  rule_id          UUID NOT NULL REFERENCES sigma_rules(id) ON DELETE CASCADE,
  status           VARCHAR(20) NOT NULL,
  rule_fingerprint VARCHAR(32),
  note             TEXT,
  decided_by       UUID REFERENCES users(id),
  decided_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_verdicts_case ON hunt_verdicts(case_id);

CREATE TABLE IF NOT EXISTS ai_feedback (
  id         BIGSERIAL PRIMARY KEY,
  case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  rating     SMALLINT NOT NULL CHECK (rating IN (-1, 1)),
  agent_type VARCHAR(32),
  model      VARCHAR(100),
  msg_ref    TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_feedback_case ON ai_feedback(case_id);

CREATE TABLE IF NOT EXISTS access_log (
  id           BIGSERIAL PRIMARY KEY,
  user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
  username     VARCHAR(100),
  method       VARCHAR(10) NOT NULL,
  path         TEXT NOT NULL,
  status_code  SMALLINT,
  response_ms  INTEGER,
  ip_address   INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_log_created ON access_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_log_user    ON access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_access_log_method  ON access_log(method);

CREATE TABLE IF NOT EXISTS api_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        VARCHAR(120) NOT NULL,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS feedback (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  type        VARCHAR(20) NOT NULL DEFAULT 'bug',
  title       VARCHAR(200),
  description TEXT NOT NULL,
  page_url    VARCHAR(500),
  status      VARCHAR(20) NOT NULL DEFAULT 'open',
  admin_reply TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE feedback
  ADD COLUMN IF NOT EXISTS status      VARCHAR(20) NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS admin_reply TEXT,
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS system_settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by UUID
);

CREATE TABLE IF NOT EXISTS detection_exceptions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        UUID REFERENCES cases(id) ON DELETE CASCADE,
  detection_type TEXT,
  match_value    TEXT NOT NULL,
  reason         TEXT,
  created_by     UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_annotations (
  case_id    UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  data       JSONB NOT NULL DEFAULT '{"zones":[],"node_overrides":{}}',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS artifact_verdicts (
  id           BIGSERIAL PRIMARY KEY,
  case_id      UUID NOT NULL,
  event_ref    TEXT NOT NULL,
  verdict      TEXT NOT NULL,
  analyst_note TEXT,
  created_by   UUID,
  updated_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (case_id, event_ref)
);

CREATE TABLE IF NOT EXISTS misp_instances (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name            VARCHAR(200) NOT NULL,
  url             TEXT NOT NULL,
  api_key         TEXT NOT NULL,
  verify_ssl      BOOLEAN DEFAULT true,
  is_active       BOOLEAN DEFAULT true,
  last_synced     TIMESTAMPTZ,
  indicator_count INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sysmon_library (
  config_key   VARCHAR(80) PRIMARY KEY,
  name         VARCHAR(200) NOT NULL,
  author       VARCHAR(120),
  license      VARCHAR(120),
  source_url   TEXT,
  content      TEXT NOT NULL,
  imported_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  imported_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS triage_alerts (
  id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  title          TEXT NOT NULL,
  description    TEXT,
  source         VARCHAR(40)  NOT NULL DEFAULT 'manual',
  severity       VARCHAR(12)  NOT NULL DEFAULT 'medium',
  status         VARCHAR(16)  NOT NULL DEFAULT 'new',
  dedup_key      VARCHAR(255),
  hit_count      INTEGER      NOT NULL DEFAULT 1,
  case_id        UUID REFERENCES cases(id) ON DELETE SET NULL,
  entity_type    VARCHAR(20),
  entity_value   VARCHAR(500),
  assignee       UUID REFERENCES users(id) ON DELETE SET NULL,
  dismiss_reason TEXT,
  metadata       JSONB DEFAULT '{}'::jsonb,
  created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
  first_seen     TIMESTAMPTZ DEFAULT NOW(),
  last_seen      TIMESTAMPTZ DEFAULT NOW(),
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_triage_status ON triage_alerts(status, severity);
CREATE INDEX IF NOT EXISTS idx_triage_case   ON triage_alerts(case_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_triage_dedup_open
  ON triage_alerts(dedup_key)
  WHERE dedup_key IS NOT NULL AND status IN ('new', 'in_progress');
