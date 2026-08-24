import { useState } from 'react';
import { Copy, Check, Shield } from 'lucide-react';
import { fmtTs } from '../../../../utils/formatters';
import { fmtDesc, fmtSrc } from '../../utils/timelineUtils';
import { useTimelineStore } from '../../store/useTimelineStore';
import { iocsAPI } from '../../../../utils/api';
import { detectIocType } from '../../../../utils/iocType';

function IocButton({ value, field, caseId, ts }) {
  const [added, setAdded] = useState(false);
  const [err, setErr]     = useState('');
  if (!caseId || value == null) return null;
  const s = String(value).trim();
  if (!s || s === '—' || s.length < 2) return null;
  const match = detectIocType(s);

  const handleAdd = async () => {
    setErr('');
    try {
      await iocsAPI.create(caseId, {
        ioc_type: match.type,
        value: s.slice(0, 500),
        description: `${field} from timeline event`,
        severity: 5,
        source: 'timeline_field',
        first_seen: ts || null,
      });
      setAdded(true);
      setTimeout(() => setAdded(false), 1500);
    } catch (e) {
      setErr('Failed');
    }
  };

  return (
    <button
      onClick={handleAdd}
      title={err || `Add ${match.label} IOC: ${s.slice(0, 200)}`}
      style={{ marginLeft: 4, fontSize: 8, padding: '1px 5px', borderRadius: 3, cursor: 'pointer',
        background: added ? 'color-mix(in srgb, var(--fl-ok) 14%, transparent)' : 'var(--fl-card)',
        border: `1px solid ${added ? 'color-mix(in srgb, var(--fl-ok) 30%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 25%, transparent)'}`,
        color: added ? 'var(--fl-ok)' : 'var(--fl-danger)',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', whiteSpace: 'nowrap',
        display: 'inline-flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
      {added ? '✓' : <><Shield size={8} />IOC</>}
    </button>
  );
}

function cleanHost(v) {
  if (!v) return null;
  const s = String(v);
  if (s.startsWith('/app/') || s.startsWith('/tmp/')) return null;
  return s;
}
function cleanProcess(v) {
  if (!v) return null;
  const s = String(v);
  const name = s.split(/[/\\]/).pop() || s;
  return /\.(exe|dll|sys|bat|cmd|ps1|msi|sh|py)$/i.test(name) ? name : null;
}

const RAW_FIELD_PRIORITY = [
  'process_name','ProcessName','Image','process_path','command_line','CommandLine',
  'ParentImage','ParentCommandLine','ParentProcessName',
  'username','user_name','UserName','SubjectUserName','TargetUserName',
  'file_path','FileName','TargetFilename','full_path','path','OriginalFileName',
  'key_path','TargetObject','value_name','Details','registry_path',
  'dst_ip','DestinationIp','SourceIp','src_ip','ip','hostname',
  'DestinationHostname','dst_port','DestinationPort','src_port','SourcePort','Protocol',
  'url','domain','QueryName',
  'md5','Hashes','sha1','sha256','hash','Imphash','MD5','SHA1','SHA256',
  'pid','ProcessId','ppid','ParentProcessId','EventID','event_id',
  'channel','Channel','computer','Computer','LogonId',
  'RuleName','Techniques','level','Level','RecordID',
];
function sortRawByPriority(entries) {
  return [...entries].sort(([a], [b]) => {
    const ia = RAW_FIELD_PRIORITY.indexOf(a);
    const ib = RAW_FIELD_PRIORITY.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });
}

// wrap=true for multi-line fields (description, notes); false by default = single truncated line
function FieldBlock({ label, value, highlight, wrap = false, field, ts }) {
  const { caseId } = useTimelineStore();
  if (value == null || value === '') return null;
  const str = String(value);
  return (
    <div style={{ borderRadius: 4, border: '1px solid var(--fl-card)', overflow: 'hidden', marginBottom: 5 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6,
        fontSize: 8, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase',
        color: 'var(--fl-muted)', padding: '3px 8px', background: 'var(--fl-bg)' }}>
        <span>{label}</span>
        {str.length > 0 && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
            <IocButton value={str} field={field || label} caseId={caseId} ts={ts} />
            <CopyBtn value={str} />
          </span>
        )}
      </div>
      <div title={str.length > 2000 ? undefined : str} style={{
        fontSize: 10, color: highlight ? 'var(--fl-danger)' : 'var(--fl-dim)', padding: '5px 8px',
        background: 'var(--fl-bg)', lineHeight: 1.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        maxHeight: 220, overflowY: 'auto',
        ...(wrap
          ? { wordBreak: 'break-all' }
          : { overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }),
      }}>
        {str.length > 50000 ? str.slice(0, 50000) + '…' : str}
      </div>
    </div>
  );
}

function CopyBtn({ value }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(String(value)); setOk(true); setTimeout(() => setOk(false), 1200); }}
      style={{ background: 'none', border: 'none', cursor: 'pointer', color: ok ? 'var(--fl-ok)' : 'var(--fl-dim)',
        padding: '2px 3px', flexShrink: 0, display: 'inline-flex', alignItems: 'center' }}
      aria-label={ok ? 'Copied' : 'Copy value'} title="Copy">
      {ok ? <Check size={12} strokeWidth={1.6} /> : <Copy size={12} strokeWidth={1.6} />}
    </button>
  );
}

export default function DetailsTab({ record: r }) {
  const { caseId } = useTimelineStore();
  if (!r) return null;
  const raw = r.raw || {};
  // Flatten AllFieldInfo / ExtraFieldInfo nested objects into top-level entries
  // so Hayabusa event-specific fields (ServiceName, CommandLine, etc.) appear individually.
  const rawEntries = sortRawByPriority(
    Object.entries(raw)
      .filter(([, v]) => v != null)
      .flatMap(([k, v]) => {
        if (
          (k === 'AllFieldInfo' || k === 'all_field_info' ||
           k === 'ExtraFieldInfo' || k === 'extra_field_info') &&
          typeof v === 'object' && !Array.isArray(v)
        ) {
          return Object.entries(v).filter(([, iv]) => iv != null && iv !== '');
        }
        return [[k, v]];
      })
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px' }}>
      <FieldBlock label="Description" value={fmtDesc(r)} highlight={!!r.detections?.length} wrap ts={r.timestamp} />
      {r.details && <FieldBlock label="Payload" value={r.details} wrap ts={r.timestamp} />}
      <FieldBlock label="Timestamp UTC" value={fmtTs(r.timestamp)} ts={r.timestamp} />
      <FieldBlock label="Artifact Type" value={r.artifact_type} ts={r.timestamp} />
      <FieldBlock label="Source"        value={fmtSrc(r)} ts={r.timestamp} />
      {cleanHost(r.host_name)    && <FieldBlock label="Host"      value={cleanHost(r.host_name)} ts={r.timestamp} />}
      {r.user_name               && <FieldBlock label="User"      value={r.user_name} ts={r.timestamp} />}
      {cleanProcess(r.process_name) && <FieldBlock label="Process" value={cleanProcess(r.process_name)} ts={r.timestamp} />}
      {r.event_id                && <FieldBlock label="Event ID"  value={r.event_id} ts={r.timestamp} />}
      {r.ext                     && <FieldBlock label="Extension" value={r.ext} ts={r.timestamp} />}
      {r.sha1                    && <FieldBlock label="SHA1"      value={r.sha1} ts={r.timestamp} />}
      {r.src_ip                  && <FieldBlock label="Src IP"    value={r.src_ip} ts={r.timestamp} />}
      {r.dst_ip                  && <FieldBlock label="Dst IP"    value={r.dst_ip} ts={r.timestamp} />}
      {r.tool                    && <FieldBlock label="Tool"      value={r.tool} ts={r.timestamp} />}

      {/* CSV original data — all raw fields from the source file */}
      {rawEntries.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase',
            color: 'var(--fl-muted)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>CSV Data</span>
            <span style={{ color: 'var(--fl-subtle)', fontWeight: 400 }}>({rawEntries.length} fields)</span>
          </div>
          <div style={{ borderRadius: 4, border: '1px solid var(--fl-card)', overflow: 'hidden' }}>
            {rawEntries.map(([k, v], idx) => {
              const str = String(v ?? '');
              const isEmpty = str === '';
              return (
                <div key={k} style={{
                  display: 'flex', gap: 0, alignItems: 'flex-start',
                  borderBottom: idx < rawEntries.length - 1 ? '1px solid var(--fl-panel)' : 'none',
                  background: idx % 2 === 0 ? 'var(--fl-bg)' : 'var(--fl-panel)',
                }}>
                  <span style={{
                    fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                    minWidth: 130, maxWidth: 130, flexShrink: 0, padding: '4px 6px 4px 8px',
                    borderRight: '1px solid var(--fl-panel)', wordBreak: 'break-all', lineHeight: 1.4,
                  }}>{k}</span>
                  <span style={{
                    fontSize: 10, color: isEmpty ? 'var(--fl-subtle)' : '#8ab4cc',
                    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', wordBreak: 'break-all', flex: 1,
                    lineHeight: 1.4, padding: '4px 4px 4px 6px',
                    fontStyle: isEmpty ? 'italic' : 'normal',
                  }}>
                    {isEmpty ? '—' : (str.length > 600 ? str.slice(0, 600) + '…' : str)}
                  </span>
                  {!isEmpty && (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 0, paddingRight: 4, flexShrink: 0 }}>
                      <IocButton value={str} field={k} caseId={caseId} ts={r.timestamp} />
                      <CopyBtn value={str} />
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {(r.mitre_technique_id || r.mitre_technique_name || r.mitre_tactic) && (
        <div style={{ marginTop: 10, padding: '6px 8px', borderRadius: 4, background: '#12082a', border: '1px solid #2a1a50' }}>
          <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-muted)', marginBottom: 5 }}>MITRE ATT&CK</div>
          {r.mitre_technique_id && (
            <div style={{ marginBottom: 3 }}>
              <a href={`https://attack.mitre.org/techniques/${String(r.mitre_technique_id).replace('.', '/')}`}
                target="_blank" rel="noopener noreferrer" style={{ fontSize: 11, color: '#c48bff', textDecoration: 'none', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700 }}>
                {r.mitre_technique_id} ↗
              </a>
            </div>
          )}
          {r.mitre_technique_name && <div style={{ fontSize: 10, color: '#7a5a98' }}>{r.mitre_technique_name}</div>}
          {r.mitre_tactic && <div style={{ fontSize: 9, color: '#5a4070', marginTop: 2 }}>{r.mitre_tactic}</div>}
        </div>
      )}

      {Array.isArray(r.detections) && r.detections.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-danger)', marginBottom: 6 }}>Active Detections</div>
          {r.detections.map((d, i) => {
            const sColors = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)', greyware: 'var(--fl-gold)' };
            const c = sColors[d.severity] || 'var(--fl-dim)';
            return (
              <div key={i} style={{ padding: '5px 8px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-danger) 7%, transparent)', border: `1px solid color-mix(in srgb, ${c} 15%, transparent)`, marginBottom: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span style={{ padding: '1px 5px', borderRadius: 3, fontSize: 8, fontWeight: 700, background: `color-mix(in srgb, ${c} 13%, transparent)`, color: c, border: `1px solid color-mix(in srgb, ${c} 21%, transparent)` }}>
                    {(d.severity || '?').toUpperCase()}
                  </span>
                  <span style={{ fontSize: 10, color: '#c0a0a0' }}>{d.name}</span>
                </div>
                <div style={{ fontSize: 9, color: '#5a3a3a', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {d.category} {d.mitre?.length ? `· ${d.mitre.join(', ')}` : ''}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
