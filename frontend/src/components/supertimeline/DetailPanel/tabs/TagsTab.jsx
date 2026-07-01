import { useTimelineStore } from '../../store/useTimelineStore';
import { CONFIDENCE_LEVELS, FORENSIC_TAGS } from '../../utils/timelineUtils';

export default function TagsTab({ record: r }) {
  const { selectedRowId, tagData, setTag, setFilter, applyFilters } = useTimelineStore();
  if (!r || selectedRowId == null) return null;

  const entry = tagData.get(r.id) || { level: null, tags: [] };

  function setLevel(lvl) {
    setTag(r.id, { ...entry, level: entry.level === lvl ? null : lvl });
  }
  function toggleForensicTag(key) {
    const tags = entry.tags.includes(key)
      ? entry.tags.filter(k => k !== key)
      : [...entry.tags, key];
    setTag(r.id, { ...entry, tags });
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div>
        <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fl-muted)', marginBottom: 7 }}>Confidence</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 5 }}>
          {CONFIDENCE_LEVELS.map(l => {
            const active = entry.level === l.key;
            return (
              <button key={l.key} onClick={() => setLevel(l.key)} style={{
                padding: '6px 4px', borderRadius: 6, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                fontWeight: 700, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
                background: active ? l.bg : 'var(--fl-card)',
                color: active ? l.color : 'var(--fl-dim)',
                border: `1px solid ${active ? l.color + '80' : 'var(--fl-border)'}`,
                transition: 'all 0.1s', minHeight: 42, whiteSpace: 'normal', textAlign: 'center', lineHeight: 1.3,
              }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: l.color }} />
                {l.label}
              </button>
            );
          })}
        </div>
      </div>
      <div>
        <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fl-muted)', marginBottom: 7 }}>Categories</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {FORENSIC_TAGS.map(tag => {
            const active = entry.tags.includes(tag.key);
            return (
              <button key={tag.key} onClick={() => toggleForensicTag(tag.key)} style={{
                padding: '3px 9px', borderRadius: 10, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                cursor: 'pointer', fontWeight: 600,
                background: active ? `color-mix(in srgb, ${tag.color} 15%, transparent)` : 'var(--fl-card)',
                color: active ? tag.color : 'var(--fl-dim)',
                border: `1px solid ${active ? tag.color + '60' : 'var(--fl-border)'}`,
                transition: 'all 0.1s',
              }}>{tag.label}</button>
            );
          })}
        </div>
      </div>
      {(entry.level || entry.tags.length > 0) && (
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button onClick={() => setTag(r.id, { level: null, tags: [] })}
            style={{ fontSize: 9, color: 'var(--fl-muted)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            Clear all tags
          </button>
        </div>
      )}
      {entry.tags.length > 0 && (
        <div>
          <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fl-subtle)', marginBottom: 5 }}>Filter by tag</div>
          {entry.tags.map(key => {
            const tag = FORENSIC_TAGS.find(t => t.key === key);
            if (!tag) return null;
            return (
              <button key={key} onClick={() => { setFilter('tagFilter', key); applyFilters(); }}
                style={{ display: 'block', width: '100%', textAlign: 'left', marginBottom: 4,
                  padding: '5px 8px', borderRadius: 4, background: `color-mix(in srgb, ${tag.color} 7%, transparent)`, border: `1px solid color-mix(in srgb, ${tag.color} 19%, transparent)`,
                  color: tag.color, cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                Filter the timeline by tag: {tag.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
