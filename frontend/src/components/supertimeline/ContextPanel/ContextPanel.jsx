import { useTimelineStore } from '../store/useTimelineStore';
import { X } from 'lucide-react';

const N_OPTIONS = [10, 25, 50, 100];

export default function ContextPanel() {
  const {
    contextOpen, contextRows, contextHostName, contextAllHosts, contextN, contextLoading,
    setContextN, toggleContextAllHosts, reAnchorContext, closeContext,
  } = useTimelineStore();
  if (!contextOpen) return null;

  return (
    <div style={{ position: 'fixed', top: 0, right: 0, width: 520, height: '100%', zIndex: 600,
      background: 'var(--fl-bg)', borderLeft: '1px solid var(--fl-raised)', boxShadow: '-8px 0 28px rgba(0,0,0,0.6)',
      display: 'flex', flexDirection: 'column', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
      {/* header + controls */}
      <div style={{ padding: 12, borderBottom: '1px solid var(--fl-raised)', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 12, color: 'var(--fl-on-dark)' }}>
            Contexte {contextAllHosts ? '· tous les hôtes' : contextHostName ? `· ${contextHostName}` : ''}
          </span>
          <button onClick={closeContext} style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer' }}><X size={14} /></button>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 10, color: 'var(--fl-dim)' }}>
          <span>±</span>
          {N_OPTIONS.map(n => (
            <button key={n} onClick={() => setContextN(n)} style={{
              padding: '2px 8px', borderRadius: 4, cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
              background: contextN === n ? 'var(--fl-card)' : 'transparent',
              border: `1px solid ${contextN === n ? 'color-mix(in srgb, var(--fl-accent) 35%, transparent)' : 'var(--fl-raised)'}`,
              color: contextN === n ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>{n}</button>
          ))}
          <label style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 'auto', cursor: 'pointer' }}>
            <input type="checkbox" checked={contextAllHosts} onChange={toggleContextAllHosts} />
            tous les hôtes
          </label>
        </div>
      </div>
      {/* neighbor list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {contextLoading && <div style={{ padding: 12, color: 'var(--fl-muted)', fontSize: 11 }}>Chargement…</div>}
        {!contextLoading && contextRows.length === 0 && <div style={{ padding: 12, color: 'var(--fl-muted)', fontSize: 11 }}>Aucun voisin.</div>}
        {contextRows.map(r => (
          <div key={r.id}
            onClick={() => !r.is_anchor && reAnchorContext(r.id)}
            title={r.is_anchor ? 'Événement ancre' : 'Cliquer pour ré-ancrer'}
            style={{ padding: '6px 12px', borderBottom: '1px solid var(--fl-card)', cursor: r.is_anchor ? 'default' : 'pointer',
              background: r.is_anchor ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
              borderLeft: r.is_anchor ? '3px solid var(--fl-accent)' : '3px solid transparent',
              fontSize: 10.5, color: 'var(--fl-on-dark)', display: 'flex', gap: 8 }}>
            <span style={{ color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>{new Date(r.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</span>
            <span style={{ color: 'var(--fl-dim)', flexShrink: 0 }}>[{r.artifact_type}]</span>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || r.source || '—'}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
