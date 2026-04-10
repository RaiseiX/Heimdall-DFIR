-- ╔══════════════════════════════════════════════════════════════╗
-- ║   Migration v2.11 — Sysmon Configurations Management       ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.11.sql

CREATE TABLE IF NOT EXISTS sysmon_configs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_key      VARCHAR(64) UNIQUE NOT NULL,   -- ex: 'swifton_security'
  name            VARCHAR(128) NOT NULL,
  filename        VARCHAR(128) NOT NULL,
  is_recommended  BOOLEAN NOT NULL DEFAULT FALSE,
  deployed_at     TIMESTAMPTZ,
  deployed_by     UUID REFERENCES users(id),
  notes           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed with the 4 bundled configs
INSERT INTO sysmon_configs (config_key, name, filename, is_recommended) VALUES
  ('swifton_security',   'SwiftOnSecurity',            'swifton_security.xml',    TRUE),
  ('neo23x0',            'Neo23x0 (Florian Roth)',     'neo23x0.xml',             FALSE),
  ('olafhartong_modular','olafhartong sysmon-modular', 'olafhartong_modular.xml', FALSE),
  ('ion_storm',          'ion-storm',                  'ion_storm.xml',           FALSE)
ON CONFLICT (config_key) DO NOTHING;
