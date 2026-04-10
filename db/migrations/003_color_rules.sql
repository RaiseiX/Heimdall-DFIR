-- ══════════════════════════════════════════════════════════════════════════════
-- Migration 003 — Timeline Color Coding Rules
-- Allows analysts to define visual rules: "if description contains X → highlight red"
-- Evaluated 100% client-side (JS) for zero-latency rendering.
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS timeline_color_rules (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID        REFERENCES cases(id) ON DELETE CASCADE,  -- NULL = global rule
  author_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
  name        VARCHAR(100) NOT NULL,
  priority    SMALLINT    NOT NULL DEFAULT 10,  -- lower = evaluated first
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  color       CHAR(7)     NOT NULL,             -- hex color e.g. '#EF4444'
  icon        VARCHAR(20),                       -- lucide icon name e.g. 'skull'
  scope       VARCHAR(10) NOT NULL DEFAULT 'case' CHECK (scope IN ('global','case')),
  conditions  JSONB       NOT NULL DEFAULT '{"operator":"AND","rules":[]}',
  -- conditions schema:
  -- {
  --   "operator": "AND" | "OR",
  --   "rules": [
  --     { "field": "description", "op": "contains", "value": "mimikatz", "case_sensitive": false },
  --     { "field": "artifact_type", "op": "in", "value": ["evtx","hayabusa"] }
  --   ]
  -- }
  -- Supported ops: contains, not_contains, equals, not_equals, starts_with, ends_with, regex, in, not_in
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_color_rule_name_scope UNIQUE NULLS NOT DISTINCT (case_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tcr_case     ON timeline_color_rules(case_id, is_active, priority);
CREATE INDEX IF NOT EXISTS idx_tcr_global   ON timeline_color_rules(scope, is_active, priority) WHERE scope = 'global';
CREATE INDEX IF NOT EXISTS idx_tcr_author   ON timeline_color_rules(author_id);

-- ── Seed: 20 pre-built forensic color rules (global scope, case_id = NULL) ──
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
