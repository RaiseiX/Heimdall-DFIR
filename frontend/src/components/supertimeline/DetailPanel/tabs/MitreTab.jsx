import { useTimelineStore } from '../../store/useTimelineStore';

export default function MitreTab({ record: r }) {
  const { setFilter, applyFilters } = useTimelineStore();
  if (!r) return null;
  const hasMitre = r.mitre_technique_id || r.mitre_technique_name || r.mitre_tactic;
  if (!hasMitre) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
        No MITRE ATT&CK mapping on this event.
      </div>
    );
  }
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
      {r.mitre_technique_id && (
        <div style={{ borderRadius: 4, border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', overflow: 'hidden' }}>
          <div style={{ fontSize: 9, color: 'var(--fl-accent)', padding: '3px 7px', background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Technique ID</div>
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: '#e6d5ff', padding: '7px', background: 'var(--fl-panel)' }}>
            <a href={`https://attack.mitre.org/techniques/${String(r.mitre_technique_id).replace('.', '/')}`}
              target="_blank" rel="noopener noreferrer" style={{ color: '#c48bff', textDecoration: 'none' }}>
              {r.mitre_technique_id} ↗
            </a>
          </div>
        </div>
      )}
      {r.mitre_technique_name && (
        <div style={{ borderRadius: 4, border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', overflow: 'hidden' }}>
          <div style={{ fontSize: 9, color: 'var(--fl-accent)', padding: '3px 7px', background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Technique</div>
          <div style={{ fontSize: 10, color: '#c0cfe0', padding: '5px 7px', background: 'var(--fl-panel)' }}>{r.mitre_technique_name}</div>
        </div>
      )}
      {r.mitre_tactic && (
        <div style={{ borderRadius: 4, border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', overflow: 'hidden' }}>
          <div style={{ fontSize: 9, color: 'var(--fl-accent)', padding: '3px 7px', background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Tactic</div>
          <div style={{ fontSize: 10, color: '#c0cfe0', padding: '5px 7px', background: 'var(--fl-panel)' }}>{r.mitre_tactic}</div>
        </div>
      )}
      {r.mitre_technique_id && (
        <button onClick={() => { setFilter('search', r.mitre_technique_id); applyFilters(); }}
          style={{ padding: '6px 12px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)',
            color: 'var(--fl-accent)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textAlign: 'left' }}>
          🔍 Filter timeline by {r.mitre_technique_id}
        </button>
      )}
    </div>
  );
}
