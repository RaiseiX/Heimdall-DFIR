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
-- Low-false-positive rule set: specific regex patterns, char-classes for literals
-- ([$], [.]) to stay JSON-valid, and the dedicated off_hours operator.
('Mimikatz',                        1,  '#EF4444', 'skull',         'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"mimikatz|sekurlsa::|lsadump::|kerberos::ptt|privilege::debug|invoke-mimikatz","case_sensitive":false}]}'),
('LSASS Dump',                      2,  '#DC2626', 'alert-circle',  'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"lsass.{0,15}dump|dump.{0,15}lsass|comsvcs.{0,15}minidump|procdump.{0,10}lsass|minidumpwritedump|out-minidump","case_sensitive":false}]}'),
('PowerShell Encoded',              3,  '#F97316', 'code',          'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"-enc |-encodedcommand|frombase64string|-w hidden|-windowstyle hidden","case_sensitive":false}]}'),
('Suspicious cmd /c',               4,  '#FB923C', 'terminal',      'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"cmd[.a-z]* /c .*(powershell|certutil|bitsadmin|mshta|rundll32|wscript|cscript|curl|wget)","case_sensitive":false}]}'),
('Scheduled Task',                  5,  '#EAB308', 'clock',         'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"schtasks /create|register-scheduledtask|\\b4698\\b","case_sensitive":false}]}'),
('Lateral Movement (PsExec/ADMIN$)',6,  '#F59E0B', 'network',       'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"admin[$]|psexesvc|psexec","case_sensitive":false}]}'),
('New User Created',                7,  '#FBBF24', 'user-plus',     'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"net user [^ ]+ /add|net localgroup administrators [^ ]+ /add|\\b4720\\b|\\b4732\\b","case_sensitive":false}]}'),
('RDP Login',                       8,  '#3B82F6', 'monitor',       'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"RemoteInteractive","case_sensitive":false}]}'),
('Service Installed',               9,  '#60A5FA', 'settings',      'global', '{"operator":"AND","rules":[{"field":"description","op":"contains","value":"service installed","case_sensitive":false},{"field":"artifact_type","op":"equals","value":"evtx"}]}'),
('Process Hollowing',               10, '#B91C1C', 'zap',           'global', '{"operator":"OR","rules":[{"field":"description","op":"contains","value":"NtUnmapViewOfSection","case_sensitive":false},{"field":"description","op":"contains","value":"VirtualAllocEx","case_sensitive":false}]}'),
('Hayabusa Critical',               11, '#EF4444', 'alert-triangle','global','{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"hayabusa"},{"field":"raw.level","op":"equals","value":"critical"}]}'),
('Hayabusa High',                   12, '#F97316', 'alert-triangle','global','{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"hayabusa"},{"field":"raw.level","op":"equals","value":"high"}]}'),
('Credential Access',               13, '#A855F7', 'key',           'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"credential_access"}]}'),
('Persistence',                     14, '#9333EA', 'anchor',        'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"persistence"}]}'),
('Defense Evasion',                 15, '#78716C', 'eye-off',       'global', '{"operator":"AND","rules":[{"field":"mitre_tactic","op":"equals","value":"defense_evasion"}]}'),
('Defender Tampering',              16, '#9333EA', 'shield-off',    'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"set-mppreference.{0,40}disable|add-mppreference.{0,40}exclusion|disableantispyware|mpcmdrun.{0,20}removedefinitions","case_sensitive":false}]}'),
('Wget/Curl/WebRequest',            17, '#EA580C', 'download',      'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"(wget|curl) https?://|invoke-webrequest|new-object net[.]webclient|downloadstring|downloadfile","case_sensitive":false}]}'),
('Log Cleared / Anti-Forensic',     18, '#B91C1C', 'eraser',        'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"\\b1102\\b|\\b104\\b|log was cleared|wevtutil cl|vssadmin.{0,20}delete.{0,20}shadow|fsutil.{0,20}usn.{0,20}deletejournal","case_sensitive":false}]}'),
('Registry Run Key',                19, '#CA8A04', 'database',      'global', '{"operator":"AND","rules":[{"field":"artifact_type","op":"equals","value":"registry"},{"field":"source","op":"contains","value":"\\Run","case_sensitive":false}]}'),
('Off-Hours Activity',              20, '#0EA5E9', 'moon',          'global', '{"operator":"AND","rules":[{"field":"timestamp","op":"off_hours","value":""}]}'),
-- Enrichment set: LOLBins, destructive (ransomware), evasion, anti-forensic, cred access.
('WMI Execution',                   21, '#FB923C', 'cpu',           'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"wmic .{0,30}process call create|invoke-wmimethod.{0,20}create|win32_process.{0,15}create","case_sensitive":false}]}'),
('Certutil Abuse',                  22, '#F97316', 'file-down',     'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"certutil.{0,20}-urlcache|certutil.{0,20}-decode|certutil.{0,20}-encode|certutil.{0,20}-verifyctl","case_sensitive":false}]}'),
('BITSAdmin Transfer',              23, '#EA580C', 'download',      'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"bitsadmin.{0,20}/transfer|start-bitstransfer.{0,30}source","case_sensitive":false}]}'),
('MSHTA Remote',                    24, '#FB923C', 'globe',         'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"mshta.{0,20}http|mshta.{0,20}javascript:|mshta.{0,20}vbscript:","case_sensitive":false}]}'),
('Regsvr32 Squiblydoo',             25, '#F97316', 'box',           'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"regsvr32.{0,20}/i:http|regsvr32.{0,20}scrobj","case_sensitive":false}]}'),
('Rundll32 Abuse',                  26, '#EA580C', 'box',           'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"rundll32.{0,30}javascript:|rundll32.{0,25}url[.]dll.{0,15}openurl|rundll32.{0,25}shell32[.]dll.{0,25}control_rundll.{0,10}http","case_sensitive":false}]}'),
('Shadow Copy Deletion',            27, '#DC2626', 'trash-2',       'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"vssadmin.{0,20}delete.{0,20}shadow|wmic.{0,20}shadowcopy.{0,20}delete|win32_shadowcopy.{0,15}delete|remove-ciminstance.{0,30}shadowcopy","case_sensitive":false}]}'),
('Boot Recovery Tamper',            28, '#B91C1C', 'power-off',     'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"bcdedit.{0,40}recoveryenabled no|bcdedit.{0,40}bootstatuspolicy ignoreallfailures|wbadmin.{0,15}delete.{0,15}catalog|wbadmin delete systemstatebackup","case_sensitive":false}]}'),
('Firewall Disabled',               29, '#9333EA', 'shield-off',    'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"netsh.{0,20}advfirewall.{0,25}state off|netsh firewall set opmode disable|set-netfirewallprofile.{0,35}enabled.{0,10}false","case_sensitive":false}]}'),
('AMSI Bypass',                     30, '#A855F7', 'shield-off',    'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"amsiutils|amsiinitfailed|amsi.{0,15}bypass|amsiscanbuffer","case_sensitive":false}]}'),
('PS History Cleared',              31, '#B91C1C', 'eraser',        'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"consolehost_history|clear-history|set-psreadlineoption.{0,25}historysavestyle.{0,15}savenothing","case_sensitive":false}]}'),
('Kerberoasting (4769 RC4)',        32, '#A855F7', 'key',           'global', '{"operator":"AND","rules":[{"field":"description","op":"regex","value":"4769.{0,120}0x17|4769.{0,120}rc4-hmac","case_sensitive":false}]}')
ON CONFLICT DO NOTHING;
