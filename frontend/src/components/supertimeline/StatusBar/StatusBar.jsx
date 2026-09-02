import { useTranslation } from 'react-i18next';
import { AlignJustify, Menu, StretchHorizontal } from 'lucide-react';
import { useMemo } from 'react';
import { useTimelineStore } from '../store/useTimelineStore';
import { artifactColor } from '../../../constants/artifactColors';
import { countImplausible, pagePosition } from '../utils/timelineUtils';

const DENSITY_ICONS = {
  compact: AlignJustify,
  normal:  Menu,
  relaxed: StretchHorizontal,
};

export default function StatusBar() {
  const { t, i18n } = useTranslation();
  const {
    page, totalPages, pageSize, total, sortCol, sortDir, multiSort, loading,
    search, artifactTypes, hostFilter, userFilter, startTime, endTime,
    hitsOnly, detSeverity, tagFilter, toolFilter, eventIdFilter, extFilter,
    setPage, setPageSize, density, setDensity, records, bounds, setFilter, applyFilters,
  } = useTimelineStore();

  const position = useMemo(() => {
    if (!bounds?.lo || !bounds?.hi || !records?.length) return null;
    let first = Infinity, last = -Infinity;
    for (const r of records) {
      const t = r?.timestamp ? new Date(r.timestamp).getTime() : NaN;
      if (Number.isNaN(t)) continue;
      if (t < first) first = t;
      if (t > last)  last  = t;
    }
    if (!Number.isFinite(first) || !Number.isFinite(last)) return null;
    return pagePosition(new Date(bounds.lo).getTime(), new Date(bounds.hi).getTime(), first, last);
  }, [bounds, records]);

  function jumpBefore() { setFilter('endTime',   String(bounds.lo).slice(0, 16)); applyFilters(); }
  function jumpAfter()  { setFilter('startTime', String(bounds.hi).slice(0, 16)); applyFilters(); }

  const implausible = useMemo(() => countImplausible(records, Date.now()), [records]);

  const filterCount =
    [search, hostFilter, userFilter, startTime, endTime, toolFilter, eventIdFilter, extFilter, tagFilter].filter(Boolean).length +
    (artifactTypes.length > 0 ? 1 : 0) +
    (hitsOnly ? 1 : 0) +
    (detSeverity ? 1 : 0);

  const sortLabel = multiSort.length > 1
    ? multiSort.map(s => `${s.col} ${s.dir}`).join(', ')
    : `${sortCol} ${sortDir === 'desc' ? '↓' : '↑'}`;

  const from = total === 0 ? 0 : ((page - 1) * pageSize + 1).toLocaleString(i18n.language);
  const to   = Math.min(page * pageSize, total).toLocaleString(i18n.language);

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
        <span style={{ color: 'var(--fl-dim)', fontWeight: 700 }}>{from}–{to}</span> / {total.toLocaleString(i18n.language)} events
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
      {position && (
        <>
          <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
          {bounds.beforeLo > 0 && (
            <button onClick={jumpBefore} title={String(bounds.lo)}
              style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer',
                fontSize: 9, color: 'var(--fl-muted)', font: 'inherit', textDecoration: 'underline' }}>
              &lsaquo;{bounds.beforeLo.toLocaleString(i18n.language)}
            </button>
          )}
          <span title={`${bounds.lo} → ${bounds.hi}`}
            style={{ position: 'relative', width: 132, height: 5, borderRadius: 2,
              background: 'var(--fl-card)', flexShrink: 0 }}>
            <span style={{ position: 'absolute', top: 0, bottom: 0, borderRadius: 2,
              background: 'var(--fl-accent)',
              left: `${position.startPct}%`,
              width: `${Math.max(1.5, position.endPct - position.startPct)}%` }} />
          </span>
          {bounds.afterHi > 0 && (
            <button onClick={jumpAfter} title={String(bounds.hi)}
              style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer',
                fontSize: 9, color: 'var(--fl-muted)', font: 'inherit', textDecoration: 'underline' }}>
              {bounds.afterHi.toLocaleString(i18n.language)}&rsaquo;
            </button>
          )}
        </>
      )}

      {implausible.total > 0 && (
        <>
          <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
          <span title={t('timeline.implausible_detail', { future: implausible.future, ancient: implausible.ancient })}
            style={{ fontSize: 9, color: 'var(--fl-warn)', textDecoration: 'underline dotted' }}>
            {t('timeline.implausible', { count: implausible.total })}
          </span>
        </>
      )}

      <span style={{ width: 1, height: 12, background: 'var(--fl-card)' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 2 }} role="group" aria-label={t('timeline.density_label')}>
        {Object.entries(DENSITY_ICONS).map(([key, Icon]) => {
          const on = density === key;
          return (
            <button key={key} onClick={() => setDensity(key)}
              aria-pressed={on} title={t(`timeline.density_${key}`)}
              style={{
                width: 20, height: 16, borderRadius: 3, padding: 0, cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: on ? 'var(--fl-card)' : 'transparent',
                border: `1px solid ${on ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-raised)'}`,
                color: on ? 'var(--fl-accent)' : 'var(--fl-muted)',
              }}>
              <Icon size={10} strokeWidth={1.6} />
            </button>
          );
        })}
      </div>

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
      {loading && <span style={{ fontSize: 9, color: 'var(--fl-dim)' }}>loading…</span>}
      <div style={{ display: 'flex', gap: 5 }}>
        {[['E','explorer'],['/', 'search'],['↑↓','navigate'],['Esc','close']].map(([key, label]) => (
          <span key={key} style={{ display: 'flex', gap: 3, alignItems: 'center', fontSize: 8, color: 'var(--fl-dim)' }}>
            <span style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 2, padding: '0 3px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{key}</span>
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}
