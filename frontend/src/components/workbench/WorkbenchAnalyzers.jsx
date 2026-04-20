import { useMemo } from 'react';
import { Shield, KeyRound, LogIn, AlertTriangle } from 'lucide-react';

// ── Persistence Sweep ────────────────────────────────────────────────────────
// Pattern library: structured detection rules matching common Windows persistence
// techniques. Each rule is evaluated against every pinned row's raw text; hits are
// grouped by MITRE technique and rendered as a compact, actionable table.

const PERSISTENCE_RULES = [
  { mitre: 'T1547.001', name: 'Registry Run Keys',       weight: 3, match: r => /\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)(\\|$)/i.test(r._blob) || /HKLM.*CurrentVersion\\Run/i.test(r._blob) || r.artifact_type === 'registry' && /\\Run(Once)?\\/.test(r.source || '') },
  { mitre: 'T1547.009', name: 'LNK Startup Folder',      weight: 3, match: r => /Startup\\.*\.lnk/i.test(r._blob) || (r.artifact_type === 'lnk' && /\\Startup\\/i.test(r._blob)) },
  { mitre: 'T1543.003', name: 'Windows Services',        weight: 3, match: r => r.event_id === 7045 || /CurrentControlSet\\Services\\/i.test(r._blob) || r.artifact_type === 'services' },
  { mitre: 'T1053.005', name: 'Scheduled Tasks',         weight: 3, match: r => r.event_id === 4698 || r.event_id === 4702 || /\\Tasks\\|schtasks|Task Scheduler/i.test(r._blob) },
  { mitre: 'T1546.003', name: 'WMI Event Subscription',  weight: 4, match: r => /__EventFilter|__EventConsumer|ActiveScriptEventConsumer|CommandLineEventConsumer/i.test(r._blob) },
  { mitre: 'T1197',     name: 'BITS Jobs',               weight: 2, match: r => r.artifact_type === 'bits' || /bitsadmin|BITS Job/i.test(r._blob) },
  { mitre: 'T1037.001', name: 'Logon Scripts',           weight: 2, match: r => /UserInitMprLogonScript|Environment\\UserInitMpr/i.test(r._blob) },
  { mitre: 'T1546.008', name: 'Accessibility Features',  weight: 4, match: r => /(sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\.exe/i.test(r._blob) && /Image File Execution Options/i.test(r._blob) },
  { mitre: 'T1546.015', name: 'COM Hijacking',           weight: 4, match: r => /CLSID\\.*\\InprocServer32|TreatAs|HKCU\\Software\\Classes\\CLSID/i.test(r._blob) },
  { mitre: 'T1574.011', name: 'Service Registry Perms',  weight: 3, match: r => r.artifact_type === 'registry' && /Services\\.*\\(ImagePath|ServiceDll)/i.test(r._blob) },
  { mitre: 'T1547.004', name: 'Winlogon Helper DLL',     weight: 4, match: r => /Winlogon\\(Userinit|Shell|Notify)/i.test(r._blob) },
];

function rowBlob(r) {
  return [r.description, r.source, r.tool, r.host_name, r.user_name, r.mitre_technique_id].filter(Boolean).join(' | ');
}

export function PersistenceSweep({ pins, caseId, navigate }) {
  const hits = useMemo(() => {
    const enriched = pins.map(p => ({ ...p, _blob: rowBlob(p) }));
    const out = [];
    for (const rule of PERSISTENCE_RULES) {
      const matches = enriched.filter(p => { try { return rule.match(p); } catch { return false; } });
      if (matches.length) out.push({ rule, matches });
    }
    return out;
  }, [pins]);

  const score = useMemo(() => hits.reduce((s, h) => s + h.rule.weight * h.matches.length, 0), [hits]);
  const scoreColor = score === 0 ? 'var(--fl-dim)' : score < 6 ? 'var(--fl-gold)' : score < 15 ? 'var(--fl-warn)' : 'var(--fl-danger)';

  if (pins.length === 0) {
    return <EmptyHint icon={<Shield size={22} />} text="Épinglez des événements depuis la Super Timeline pour lancer l'analyse de persistance." />;
  }

  return (
    <div style={{ fontFamily: 'monospace' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', marginBottom: 10,
        background: 'var(--fl-bg)', border: `1px solid ${scoreColor}60`, borderLeft: `3px solid ${scoreColor}`, borderRadius: 6,
      }}>
        <Shield size={14} style={{ color: scoreColor }} />
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fl-on-dark)' }}>Persistence Score</span>
        <span style={{ fontSize: 18, fontWeight: 700, color: scoreColor }}>{score}</span>
        <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>
          {score === 0 ? 'Aucun signal de persistance détecté.' : `${hits.length} technique(s) MITRE touchée(s) sur ${pins.length} preuve(s)`}
        </span>
      </div>

      {hits.length === 0 ? (
        <EmptyHint icon={<Shield size={22} />} text="Aucune règle de persistance n'a déclenché sur les preuves épinglées." subtle />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {hits.map(({ rule, matches }) => (
            <div key={rule.mitre} style={{
              background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderLeft: '3px solid var(--fl-purple, #c96898)',
              borderRadius: 6, padding: '8px 12px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 3, background: '#c9689825', color: 'var(--fl-purple, #c96898)', fontWeight: 700 }}>{rule.mitre}</span>
                <span style={{ fontSize: 12, color: 'var(--fl-on-dark)', fontWeight: 600 }}>{rule.name}</span>
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fl-dim)' }}>{matches.length} hit(s) × poids {rule.weight}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {matches.slice(0, 20).map(m => (
                  <div key={m.pin_id} onClick={() => {
                      const qs = new URLSearchParams({ caseId: String(caseId) });
                      if (m.collection_timeline_id != null) qs.set('focus', String(m.collection_timeline_id));
                      navigate(`/super-timeline?${qs.toString()}`);
                    }}
                    style={{ fontSize: 10, color: 'var(--fl-on-dark)', padding: '3px 6px', background: 'var(--fl-card)', borderRadius: 3, cursor: 'pointer', wordBreak: 'break-all' }}
                    title="Ouvrir dans la Super Timeline">
                    <span style={{ color: 'var(--fl-accent)' }}>{m.timestamp ? String(m.timestamp).slice(0, 19).replace('T', ' ') : '—'}</span>
                    {' · '}
                    <span style={{ color: 'var(--fl-dim)' }}>{m.artifact_type || '—'}</span>
                    {m.event_id != null && <span style={{ color: 'var(--fl-accent)' }}> · EID {m.event_id}</span>}
                    {' — '}
                    {(m.description || m.source || '').slice(0, 160)}
                  </div>
                ))}
                {matches.length > 20 && (
                  <div style={{ fontSize: 10, color: 'var(--fl-dim)', fontStyle: 'italic', padding: '2px 6px' }}>
                    +{matches.length - 20} autres hit(s) masqué(s)
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Logon Session Reconstruction ─────────────────────────────────────────────
// Groups 4624 / 4625 / 4634 / 4648 events by their TargetLogonId / SubjectLogonId.
// Reconstructs sessions: start (logon), end (logoff), duration, logon type, user, host.

const LOGON_TYPES = {
  2:  'Interactive',
  3:  'Network',
  4:  'Batch',
  5:  'Service',
  7:  'Unlock',
  8:  'NetworkCleartext',
  9:  'NewCredentials',
  10: 'RemoteInteractive (RDP)',
  11: 'CachedInteractive',
};

function extractLogonId(pin) {
  const blob = (pin.description || '') + ' ' + (pin.source || '');
  const m = blob.match(/(?:Target\s*Logon\s*Id|TargetLogonId|LogonId)[:\s=]+(0x[0-9a-fA-F]+|\d+)/);
  return m ? m[1] : null;
}
function extractLogonType(pin) {
  const blob = pin.description || '';
  const m = blob.match(/Logon\s*Type[:\s=]+(\d+)/i);
  return m ? Number(m[1]) : null;
}
function extractIP(pin) {
  const blob = pin.description || '';
  const m = blob.match(/(?:Source\s*Network\s*Address|SourceIP|IpAddress)[:\s=]+([0-9a-fA-F.:]+)/);
  return m ? m[1] : null;
}

export function LogonSessions({ pins, caseId, navigate }) {
  const sessions = useMemo(() => {
    const relevant = pins.filter(p =>
      (p.artifact_type === 'evtx' || p.artifact_type === 'hayabusa') &&
      [4624, 4625, 4634, 4647, 4648].includes(Number(p.event_id))
    );
    const byId = new Map();
    for (const p of relevant) {
      const id = extractLogonId(p) || `${p.user_name || '?'}@${p.host_name || '?'}|${String(p.timestamp || '').slice(0, 10)}`;
      if (!byId.has(id)) byId.set(id, []);
      byId.get(id).push(p);
    }
    return Array.from(byId.entries()).map(([id, events]) => {
      events.sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
      const logon = events.find(e => Number(e.event_id) === 4624);
      const fail  = events.find(e => Number(e.event_id) === 4625);
      const logoff = events.find(e => [4634, 4647].includes(Number(e.event_id)));
      const explicit = events.find(e => Number(e.event_id) === 4648);
      const start = logon?.timestamp || fail?.timestamp || events[0]?.timestamp;
      const end   = logoff?.timestamp || null;
      const lt    = extractLogonType(logon || events[0]);
      const ip    = extractIP(logon || explicit || fail || events[0]);
      const durSec = (start && end) ? Math.max(0, Math.round((new Date(end) - new Date(start)) / 1000)) : null;
      const status = fail && !logon ? 'failed' : logon ? (end ? 'closed' : 'open') : 'partial';
      return { id, events, start, end, durSec, status, logonType: lt, ip, user: logon?.user_name || fail?.user_name || events[0]?.user_name, host: logon?.host_name || events[0]?.host_name };
    }).sort((a, b) => String(a.start || '').localeCompare(String(b.start || '')));
  }, [pins]);

  if (pins.length === 0) {
    return <EmptyHint icon={<LogIn size={22} />} text="Épinglez des événements 4624/4625/4634/4648 pour reconstruire les sessions de logon." />;
  }
  if (sessions.length === 0) {
    return <EmptyHint icon={<LogIn size={22} />} text="Aucun événement de logon (4624/4625/4634/4647/4648) dans les preuves épinglées." subtle />;
  }

  const fmtDur = (s) => {
    if (s == null) return '—';
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  };
  const statusColor = (s) => s === 'failed' ? 'var(--fl-danger)' : s === 'open' ? 'var(--fl-warn)' : s === 'closed' ? 'var(--fl-ok, #22c55e)' : 'var(--fl-dim)';

  return (
    <div style={{ fontFamily: 'monospace' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', marginBottom: 10,
        background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderLeft: '3px solid var(--fl-accent)', borderRadius: 6,
      }}>
        <LogIn size={14} style={{ color: 'var(--fl-accent)' }} />
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--fl-on-dark)' }}>Sessions reconstruites</span>
        <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--fl-accent)' }}>{sessions.length}</span>
        <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>
          {sessions.filter(s => s.status === 'open').length} ouverte(s) · {sessions.filter(s => s.status === 'failed').length} échec(s)
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {sessions.map(s => (
          <div key={s.id} style={{
            background: 'var(--fl-bg)', border: '1px solid var(--fl-card)',
            borderLeft: `3px solid ${statusColor(s.status)}`, borderRadius: 5, padding: '7px 12px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: `${statusColor(s.status)}25`, color: statusColor(s.status), textTransform: 'uppercase', fontWeight: 700 }}>{s.status}</span>
              <span style={{ fontSize: 10, color: 'var(--fl-accent)' }}>{s.id}</span>
              {s.user && <span style={{ fontSize: 10, color: 'var(--fl-on-dark)' }}>👤 {s.user}</span>}
              {s.host && <span style={{ fontSize: 10, color: 'var(--fl-on-dark)' }}>⚙ {s.host}</span>}
              {s.logonType != null && (
                <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--fl-card)', color: 'var(--fl-dim)' }}>
                  Type {s.logonType}{LOGON_TYPES[s.logonType] ? ` · ${LOGON_TYPES[s.logonType]}` : ''}
                </span>
              )}
              {s.ip && <span style={{ fontSize: 10, color: 'var(--fl-gold)' }}>{s.ip}</span>}
              <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fl-dim)' }}>
                {s.start ? String(s.start).slice(0, 19).replace('T', ' ') : '—'}
                {s.end ? ` → ${String(s.end).slice(0, 19).replace('T', ' ')}` : ''}
                {' · '}
                <span style={{ color: 'var(--fl-on-dark)' }}>{fmtDur(s.durSec)}</span>
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {s.events.map(e => (
                <span key={e.pin_id}
                  onClick={() => {
                    const qs = new URLSearchParams({ caseId: String(caseId) });
                    if (e.collection_timeline_id != null) qs.set('focus', String(e.collection_timeline_id));
                    navigate(`/super-timeline?${qs.toString()}`);
                  }}
                  title={e.description || ''}
                  style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                    background: Number(e.event_id) === 4625 ? '#ef444420' : Number(e.event_id) === 4624 ? '#22c55e20' : 'var(--fl-card)',
                    color: Number(e.event_id) === 4625 ? 'var(--fl-danger)' : Number(e.event_id) === 4624 ? 'var(--fl-ok, #22c55e)' : 'var(--fl-dim)',
                    border: '1px solid var(--fl-sep)',
                  }}>
                  {e.event_id} · {String(e.timestamp || '').slice(11, 19)}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyHint({ icon, text, subtle }) {
  return (
    <div style={{
      padding: '32px 20px', textAlign: 'center', color: 'var(--fl-dim)',
      border: `1px ${subtle ? 'solid' : 'dashed'} var(--fl-sep)`, borderRadius: 8, background: 'var(--fl-bg)',
      fontFamily: 'monospace',
    }}>
      <div style={{ opacity: 0.5, marginBottom: 10 }}>{icon}</div>
      <div style={{ fontSize: 11 }}>{text}</div>
    </div>
  );
}
