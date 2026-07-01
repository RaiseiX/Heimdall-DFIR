// frontend/src/components/supertimeline/StatusBar/StatusBar.jsx
import { useTimelineStore } from '../store/useTimelineStore';
import { artifactColor } from '../../../constants/artifactColors';

export default function StatusBar() {
  const {
    page, totalPages, pageSize, total, sortCol, sortDir, multiSort, loading,
    search, artifactTypes, hostFilter, userFilter, startTime, endTime,
    hitsOnly, detSeverity, tagFilter, toolFilter, eventIdFilter, extFilter,
    setPage, setPageSize,
  } = useTimelineStore();

  const filterCount =
    [search, hostFilter, userFilter, startTime, endTime, toolFilter, eventIdFilter, extFilter, tagFilter].filter(Boolean).length +
    (artifactTypes.length > 0 ? 1 : 0) +
    (hitsOnly ? 1 : 0) +
    (detSeverity ? 1 : 0);

  const sortLabel = multiSort.length > 1
    ? multiSort.map(s => `${s.col} ${s.dir}`).join(', ')
    : `${sortCol} ${sortDir === 'desc' ? '↓' : '↑'}`;

  const from = total === 0 ? 0 : ((page - 1) * pageSize + 1).toLocaleString();
  const to   = Math.min(page * pageSize, total).toLocaleString();

  return (
    <div style={{ height: 24, background: '#05080f', borderTop: '1px solid var(--fl-card)',
      display: 'flex', alignItems: 'center', padding: '0 12px', gap: 12,
      flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
      {filterCount > 0 && (
        <>
          <span style={{ fontSize: 9, color: 'var(--fl-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ color: 'var(--fl-accent)', fontWeight: 700 }}>{filterCount}</span> filter{filterCount !== 1 ? 's' : ''} active
          </span>
          <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
        </>
      )}
      <span style={{ fontSize: 9, color: 'var(--fl-muted)' }}>
        <span style={{ color: '#4a6080', fontWeight: 700 }}>{from}–{to}</span> / {total.toLocaleString()} events
      </span>
      <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
      <span style={{ fontSize: 9, color: 'var(--fl-subtle)' }}>
        sort: <span style={{ color: 'var(--fl-muted)', fontWeight: 700 }}>{sortLabel}</span>
      </span>
      {totalPages > 1 && (
        <>
          <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <button disabled={page <= 1} onClick={() => setPage(page - 1)}
              style={{ width: 18, height: 16, borderRadius: 3, background: 'transparent', border: '1px solid var(--fl-raised)',
                color: page <= 1 ? 'var(--fl-raised)' : 'var(--fl-muted)', cursor: page <= 1 ? 'default' : 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              ‹
            </button>
            <span style={{ fontSize: 9, color: 'var(--fl-muted)' }}>{page} / {totalPages}</span>
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
              style={{ width: 18, height: 16, borderRadius: 3, background: 'transparent', border: '1px solid var(--fl-raised)',
                color: page >= totalPages ? 'var(--fl-raised)' : 'var(--fl-muted)', cursor: page >= totalPages ? 'default' : 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              ›
            </button>
            {[500, 1000, 2000, 5000, 10000, 50000].map(s => (
              <button key={s} onClick={() => setPageSize(s)} style={{
                padding: '1px 5px', borderRadius: 3,
                background: pageSize === s ? 'var(--fl-card)' : 'transparent',
                border: `1px solid ${pageSize === s ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'var(--fl-raised)'}`,
                color: pageSize === s ? 'var(--fl-accent)' : 'var(--fl-subtle)', cursor: 'pointer', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              }}>{s}</button>
            ))}
          </div>
        </>
      )}
      {/* Schema mode badge */}
      {artifactTypes.length === 1 && (
        <>
          <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
          <span style={{
            fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 3,
            background: `color-mix(in srgb, ${artifactColor(artifactTypes[0])} 8%, transparent)`,
            color: artifactColor(artifactTypes[0]),
            border: `1px solid color-mix(in srgb, ${artifactColor(artifactTypes[0])} 25%, transparent)`,
          }}>
            {artifactTypes[0].toUpperCase()} SCHEMA
          </span>
        </>
      )}
      <div style={{ flex: 1 }} />
      {loading && <span style={{ fontSize: 9, color: 'var(--fl-raised)' }}>loading…</span>}
      <div style={{ display: 'flex', gap: 5 }}>
        {[['E','explorer'],['/', 'search'],['↑↓','navigate'],['Esc','close']].map(([key, label]) => (
          <span key={key} style={{ display: 'flex', gap: 3, alignItems: 'center', fontSize: 8, color: 'var(--fl-raised)' }}>
            <span style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 2, padding: '0 3px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{key}</span>
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}
