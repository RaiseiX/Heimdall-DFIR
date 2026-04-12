import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronDown, ChevronRight, RefreshCw, Activity, ExternalLink } from 'lucide-react';
import { useDateFormat } from '../../hooks/useDateFormat';

const RISK_COLOR = {
  CRITIQUE: '#da3633',
  'ÉLEVÉ':   '#d97c20',
  MOYEN:    '#c89d1d',
  FAIBLE:   '#3fb950',
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
  suspicious_exec_path:       'Exécution chemin suspect (%TEMP%/AppData)',
  powershell_encoded:         'PowerShell encodé (-enc)',
  lateral_movement:           'Mouvement latéral (LogonType 3/10)',
  privilege_escalation:       'Élévation de privilèges (EID 4672)',
  double_extension:           'Double extension (.pdf.exe, .docx.scr)',
  night_activity:             'Activité nocturne (22h–6h)',
  sysmon_proc_injection:      'Injection de processus (EID 8 / CreateRemoteThread)',
  sysmon_lsass_access:        'Accès LSASS (dump credentials)',
  sysmon_suspicious_netconn:  'Connexion réseau depuis chemin suspect',
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
  const color = RISK_COLOR[machine.risk_level] || '#7d8590';
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
        <span style={{ color: '#484f58', flexShrink: 0 }}>
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
        <span style={{
          fontFamily: 'monospace', fontSize: 11, color: '#e6edf3',
          flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {machine.hostname}
        </span>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#484f58', marginRight: 8, flexShrink: 0 }}>
          {machine.event_count.toLocaleString()} evt
        </span>
        <ScoreBar score={machine.score} color={color} />
        <span style={{
          fontFamily: 'monospace', fontSize: 12, fontWeight: 700,
          color, width: 28, textAlign: 'right', flexShrink: 0,
        }}>
          {machine.score}
        </span>
        <span style={{
          fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
          padding: '1px 5px', borderRadius: 3, marginLeft: 4,
          background: `${color}18`, color, border: `1px solid ${color}35`,
          flexShrink: 0,
        }}>
          {machine.risk_level}
        </span>
        {!open && topFactor && (
          <span
            title={`Règle principale : ${RULE_LABELS[topFactor[0]] || topFactor[0]} (+${topFactor[1]} pts)`}
            style={{
              fontFamily: 'monospace', fontSize: 9, color: '#7d8590',
              maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              flexShrink: 1, marginLeft: 6,
              padding: '1px 6px', borderRadius: 3, background: '#1c2a3a', border: '1px solid #2a3a50',
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
              <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
                color: pts >= 20 ? '#da3633' : pts >= 15 ? '#d97c20' : '#c89d1d',
                width: 24, textAlign: 'right', flexShrink: 0 }}>
                +{pts}
              </span>
              <button
                onClick={e => handleRuleClick(e, rule)}
                title={RULE_SEARCH[rule] ? `Rechercher "${RULE_SEARCH[rule]}" dans la Timeline` : 'Ouvrir la Timeline'}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                  color: '#7d8590', fontSize: 11, textAlign: 'left',
                }}
              >
                {RULE_LABELS[rule] || rule}
                <ExternalLink size={9} style={{ color: '#3d5070', flexShrink: 0 }} />
              </button>
            </div>
          ))}
        </div>
      )}

      {open && factors.length === 0 && (
        <div style={{ padding: '4px 12px 10px 32px', fontSize: 11, color: '#484f58', fontFamily: 'monospace' }}>
          Aucun facteur de risque détecté
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
          <Activity size={14} style={{ color: '#4d82c0' }} />
          <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#7d8590' }}>
            Scores de Compromission par Machine
          </span>
          {machines.length > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 4, background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030' }}>
              {machines.length} machine{machines.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {computed_at && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#484f58' }}>
              {fmtDateTime(computed_at)}
            </span>
          )}
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={loading}
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace',
                background: 'none', border: '1px solid #30363d', borderRadius: 4, padding: '2px 7px',
                color: '#7d8590', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.5 : 1 }}
            >
              <RefreshCw size={10} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              Recalculer
            </button>
          )}
        </div>
      </div>

      {(ci.yara_matches > 0 || ci.sigma_matches > 0 || ci.threat_intel_matches > 0 || ci.malicious_iocs > 0) && (
        <div style={{
          display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap',
        }}>
          {ci.yara_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4,
              background: '#da363318', color: '#da3633', border: '1px solid #da363330' }}>
              {ci.yara_matches} match YARA
            </span>
          )}
          {ci.sigma_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4,
              background: '#d97c2018', color: '#d97c20', border: '1px solid #d97c2030' }}>
              {ci.sigma_matches} alerte Sigma
            </span>
          )}
          {ci.threat_intel_matches > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4,
              background: '#8b72d618', color: '#8b72d6', border: '1px solid #8b72d630' }}>
              {ci.threat_intel_matches} corrélation Threat Intel
            </span>
          )}
          {ci.malicious_iocs > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4,
              background: '#c89d1d18', color: '#c89d1d', border: '1px solid #c89d1d30' }}>
              {ci.malicious_iocs} IOC malveillant{ci.malicious_iocs > 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}

      {machines.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', borderRadius: 8,
          background: '#0d1117', border: '1px solid #30363d', color: '#484f58',
          fontFamily: 'monospace', fontSize: 11 }}>
          Aucun score calculé — lancez le triage pour analyser les machines
        </div>
      ) : (
        <div style={{ borderRadius: 8, border: '1px solid #30363d', background: '#0d1117', overflow: 'hidden' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 10,
            padding: '5px 12px', borderBottom: '1px solid #30363d', background: '#0a0f16' }}>
            <span style={{ width: 12 }} />
            <span style={{ flex: 1, fontSize: 9, fontFamily: 'monospace', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: '#484f58' }}>Machine</span>
            <span style={{ width: 80, fontSize: 9, fontFamily: 'monospace', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: '#484f58', textAlign: 'right', marginRight: 8 }}>Evénements</span>
            <span style={{ flex: 1, fontSize: 9, fontFamily: 'monospace', textTransform: 'uppercase',
              letterSpacing: '0.06em', color: '#484f58' }}>Score</span>
          </div>
          {machines.map(m => <MachineRow key={m.hostname} machine={m} caseId={caseId} collectionId={collectionId} />)}
        </div>
      )}
    </div>
  );
}
