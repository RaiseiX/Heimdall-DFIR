import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronDown, ChevronRight, RefreshCw, Activity, ExternalLink } from 'lucide-react';
import { useDateFormat } from '../../hooks/useDateFormat';

const RISK_COLOR = {
  CRITICAL: 'var(--fl-danger)',
  HIGH:     'var(--fl-warn)',
  MEDIUM:   'var(--fl-gold)',
  LOW:      'var(--fl-ok)',
};

const RULE_SEARCH = {
  suspicious_exec_path:       '%TEMP%',
  powershell_encoded:         '-enc',
  lateral_movement:           '4624',
  privilege_escalation:       '4672',
  double_extension:           '.exe',
  night_activity:             '',
  sysmon_proc_injection:      'CreateRemoteThread',
  sysmon_lsass_access:        'lsass',
  sysmon_suspicious_netconn:  '',
  sysmon_ads:                 'Zone.Identifier',
  credential_dump_tool:       'mimikatz',
  lolbas_exec:                'certutil',
  uac_bypass:                 'fodhelper',
  wmi_persistence:            'wmiprvse',
  browser_exploitation:       '',
  ransomware_indicator:       'vssadmin',
};

const RULE_LABELS = {
  suspicious_exec_path:       'Suspicious path execution (%TEMP%/AppData)',
  powershell_encoded:         'Encoded PowerShell (-enc)',
  lateral_movement:           'Lateral movement (LogonType 3/10)',
  privilege_escalation:       'Privilege escalation (EID 4672)',
  double_extension:           'Double extension (.pdf.exe, .docx.scr)',
  night_activity:             'Night activity (22:00-06:00)',
  sysmon_proc_injection:      'Injection de processus (EID 8 / CreateRemoteThread)',
  sysmon_lsass_access:        'LSASS access (credential dump)',
  sysmon_suspicious_netconn:  'Network connection from suspicious path',
  sysmon_ads:                 'Alternate Data Stream (Zone.Identifier)',
  credential_dump_tool:       'Outil de dump credentials (mimikatz, procdump)',
  lolbas_exec:                'LOLBaS — certutil/regsvr32/mshta (T1218)',
  uac_bypass:                 'Contournement UAC — fodhelper/eventvwr (T1548)',
  wmi_persistence:            'Persistance WMI — wmiprvse (T1546)',
  browser_exploitation:       'Exploitation navigateur → shell (T1189)',
  ransomware_indicator:       'Indicateur ransomware — vssadmin/wbadmin delete',
};

function ScoreBar({ score, color }) {
  return (
    <div style={{ height: 6, borderRadius: 3, background: '#1c2a3a', overflow: 'hidden', flex: 1 }}>
      <div style={{
        height: '100%',
        width: `${Math.min(score, 100)}%`,
        background: color,
        borderRadius: 3,
        transition: 'width 0.4s ease',
      }} />
    </div>
  );
}

function MachineRow({ machine, caseId, collectionId }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const color = RISK_COLOR[machine.risk_level] || 'var(--fl-dim)';
  const breakdown = machine.breakdown || {};
  const factors = Object.entries(breakdown);
  const topFactor = factors.length > 0 ? factors.reduce((a, b) => b[1] > a[1] ? b : a) : null;

  const handleRuleClick = (e, rule) => {
    e.stopPropagation();
    const keyword = RULE_SEARCH[rule];
    const base = (caseId && collectionId)
      ? `/cases/${caseId}/collections/${collectionId}/timeline`
      : '/super-timeline';
    const params = keyword ? `?search=${encodeURIComponent(keyword)}` : '';
    navigate(`${base}${params}`);
  };

  return (
    <div style={{ borderBottom: '1px solid #1c2a3a' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10, width: '100%',
          padding: '8px 12px', background: 'none', border: 'none', cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <span style={{ color: 'var(--fl-muted)', flexShrink: 0 }}>
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
        <span style={{
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-text)',
          flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {machine.hostname}
        </span>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)', marginRight: 8, flexShrink: 0 }}>
          {machine.event_count.toLocaleString()} events
        </span>
        <ScoreBar score={machine.score} color={color} />
        <span style={{
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 700,
          color, width: 28, textAlign: 'right', flexShrink: 0,
        }}>
          {machine.score}
        </span>
        <span style={{
          fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
          padding: '1px 5px', borderRadius: 3, marginLeft: 4,
          background: `color-mix(in srgb, ${color} 9%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 21%, transparent)`,
          flexShrink: 0,
        }}>
          {machine.risk_level}
        </span>
        {!open && topFactor && (
          <span
          title={`Top rule: ${RULE_LABELS[topFactor[0]] || topFactor[0]} (+${topFactor[1]} pts)`}
            style={{
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-dim)',
              maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              flexShrink: 1, marginLeft: 6,
              padding: '1px 6px', borderRadius: 3, background: '#1c2a3a', border: '1px solid var(--fl-card)',
            }}
          >
            +{topFactor[1]} · {RULE_LABELS[topFactor[0]] || topFactor[0]}
          </span>
        )}
      </button>

      {open && factors.length > 0 && (
        <div style={{ padding: '4px 12px 10px 32px' }}>
          {factors.map(([rule, pts]) => (
            <div key={rule} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '3px 0', borderBottom: '1px solid rgba(30,42,60,0.4)',
            }}>
              <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, fontWeight: 700,
                color: pts >= 20 ? 'var(--fl-danger)' : pts >= 15 ? 'var(--fl-warn)' : 'var(--fl-gold)',
                width: 24, textAlign: 'right', flexShrink: 0 }}>
                +{pts}
              </span>
              <button
                onClick={e => handleRuleClick(e, rule)}
                title={RULE_SEARCH[rule] ? `Search "${RULE_SEARCH[rule]}" in Timeline` : 'Open Timeline'}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                  color: 'var(--fl-dim)', fontSize: 11, textAlign: 'left',
                }}
              >
                {RULE_LABELS[rule] || rule}
                <ExternalLink size={9} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
              </button>
            </div>
          ))}
        </div>
      )}

      {open && factors.length === 0 && (
        <div style={{ padding: '4px 12px 10px 32px', fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          No risk factors detected
        </div>
      )}
    </div>
  );
}

export default function MachineScorePanel({ triageData, onRefresh, loading, caseId, collectionId }) {
  const { fmtDateTime } = useDateFormat();
  if (!triageData) return null;

  const { scores, computed_at, case_indicators } = triageData;
  const machines = scores || [];

  const ci = case_indicators || {};

  return (
    <div style={{ marginBottom: 20 }}>
      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={14} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>
            Machine compromise scores
          </span>
          {machines.length > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
              {machines.length} machine{machines.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {computed_at && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>
              {fmtDateTime(computed_at)}
            </span>
          )}
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={loading}
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                background: 'none', border: '1px solid var(--fl-border)', borderRadius: 4, padding: '2px 7px',
                color: 'var(--fl-dim)', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.5 : 1 }}
            >
              <RefreshCw size={10} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              Recalculate
            </button>
          )}
        </div>
      </div>

      {(ci.yara_matches > 0 || ci.sigma_matches > 0 || ci.threat_intel_matches > 0 || ci.malicious_iocs > 0) && (
        <div style={{
          display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap',
        }}>
          {ci.yara_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 4,
              background: 'color-mix(in srgb, var(--fl-danger) 9%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)' }}>
              {ci.yara_matches} YARA match{ci.yara_matches > 1 ? 'es' : ''}
            </span>
          )}
          {ci.sigma_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 4,
              background: 'color-mix(in srgb, var(--fl-warn) 9%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 19%, transparent)' }}>
              {ci.sigma_matches} Sigma alert{ci.sigma_matches > 1 ? 's' : ''}
            </span>
          )}
          {ci.threat_intel_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 4,
              background: 'color-mix(in srgb, var(--fl-purple) 9%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 19%, transparent)' }}>
              {ci.threat_intel_matches} Threat Intel correlation{ci.threat_intel_matches > 1 ? 's' : ''}
            </span>
          )}
          {ci.malicious_iocs > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 4,
              background: 'color-mix(in srgb, var(--fl-gold) 9%, transparent)', color: 'var(--fl-gold)', border: '1px solid color-mix(in srgb, var(--fl-gold) 19%, transparent)' }}>
              {ci.malicious_iocs} malicious IOC{ci.malicious_iocs > 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}

      {machines.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', borderRadius: 8,
          background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
          No score computed - run triage to analyze the machines
        </div>
      ) : (
        <div style={{ borderRadius: 8, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', overflow: 'hidden' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 10,
            padding: '5px 12px', borderBottom: '1px solid var(--fl-border)', background: '#0a0f16' }}>
            <span style={{ width: 12 }} />
            <span style={{ flex: 1, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: 'var(--fl-muted)' }}>Machine</span>
            <span style={{ width: 80, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: 'var(--fl-muted)', textAlign: 'right', marginRight: 8 }}>Events</span>
            <span style={{ flex: 1, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: 'var(--fl-muted)' }}>Score</span>
          </div>
          {machines.map(m => <MachineRow key={m.hostname} machine={m} caseId={caseId} collectionId={collectionId} />)}
        </div>
      )}
    </div>
  );
}
