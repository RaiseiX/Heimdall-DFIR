import { useRef, useMemo, useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Loader2, Palette, Columns, Download } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { collectionAPI } from '../../../utils/api';
import ColorRulesManager from '../../../components/timeline/ColorRulesManager';
import { EventRow } from './EventRow';
import { GroupRow } from './GroupRow';
import { ColumnHeader } from './ColumnHeader';
import { buildDynamicCols, computeRef, readRawPath, constantColumns, rowHeightFor, stacksTimestamp, orderColumns, moveColumn, timestampColumnWidth, describeCount } from '../utils/timelineUtils';
import { artifactColor } from '../../../constants/artifactColors';
import GroupPanel from './GroupPanel';
import ColumnManager from './ColumnManager';

const INLINE_PICTO = { verticalAlign: '-1px' };

const PREFIX = '4px';
const DEFAULT_PINNED = ['timestamp'];
const SERVER_SORTABLE_COLS = new Set(['timestamp', 'artifact_type', 'description', 'source']);

const LEDGER_COLS = [
  { key: 'timestamp',      label: 'DateTime',    size: 110 },
  { key: 'timestamp_kind', label: 'TS Type',     size: 76  },
  { key: 'artifact_type',  label: 'Artifact',    size: 130 },
  { key: 'tool',           label: 'Tool',        size: 110 },
  { key: 'description',    label: 'Description', size: null, meta: { flex: true } },
  { key: '_source',        label: 'DataPath',    size: 300 },
  { key: 'user_name',      label: 'User',        size: 88  },
  { key: 'host_name',      label: 'Computer',    size: 120 },
  { key: '_verdict',       label: 'Verdict',     size: 84  },
];

export default function EventGrid() {
  const { t, i18n } = useTranslation();
  const tsLabels = useMemo(() => ({
    inventory:      t('timeline.tsKind.inventory'),
    inventoryTitle: t('timeline.tsKind.inventoryTitle'),
    undatedCell:    t('timeline.tsKind.undatedCell'),
    future:         t('timeline.ts_future'),
    ancient:        t('timeline.ts_ancient'),
  }), [t]);

  const nowMs = useMemo(() => Date.now(), []);
  const {
    records, loading, total, search,
    sortCol, sortDir, multiSort,
    selectedRowId,
    tagData, notedRefs, colorRules,
    groupByFields, caseId, page, totalPages, pageSize, dynamicColsRev,
    setSelectedRow, setSort, loadMore,
    artifactTypes, huntMessage, density,
  } = useTimelineStore();

  const countState = describeCount({ loading, total });

  const scrollRef     = useRef(null);
  const scrollLeftRef = useRef(0);
  const groupRowEls   = useRef(new Map());
  const loadMoreRef   = useRef(null);

  const colKey = useCallback(k => caseId ? `supertl.${k}.${caseId}` : `supertl.${k}`, [caseId]);
  const [hiddenCols, setHiddenCols] = useState(() => new Set());
  const [colWidths,  setColWidths]  = useState(() => new Map());
  const [pinnedCols, setPinnedCols] = useState(() => DEFAULT_PINNED);
  const [colOrder,   setColOrder]   = useState(() => []);

  useEffect(() => {
    if (!caseId) return;
    try { setColOrder(JSON.parse(localStorage.getItem(colKey('colOrder')) || '[]')); } catch { }
    try { setHiddenCols(new Set(JSON.parse(localStorage.getItem(colKey('hiddenCols')) || '[]'))); } catch { }
    try { setColWidths(new Map(Object.entries(JSON.parse(localStorage.getItem(colKey('colWidths')) || '{}')))); } catch { }
    try {
      const saved = localStorage.getItem(colKey('pinnedCols'));
      if (saved !== null) {
        const parsed = JSON.parse(saved);
        setPinnedCols(parsed.length > 0 ? parsed : DEFAULT_PINNED);
      }
    } catch { }
  }, [caseId, colKey]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollLeft = 0;
  }, [caseId, artifactTypes.join(',')]);

  const [clientSort, setClientSort] = useState(null);

  const handleColSort = useCallback((colKey, shiftKey) => {
    if (SERVER_SORTABLE_COLS.has(colKey)) {
      setSort(colKey, shiftKey);
      setClientSort(null);
    } else {
      setClientSort(prev =>
        prev?.col === colKey
          ? { col: colKey, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
          : { col: colKey, dir: 'asc' }
      );
    }
  }, [setSort]);

  const displayRecords = useMemo(() => {
    if (!clientSort) return records;
    return [...records].sort((a, b) => {
      const va = String(getGroupValue(a, clientSort.col));
      const vb = String(getGroupValue(b, clientSort.col));
      const cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
      return clientSort.dir === 'asc' ? cmp : -cmp;
    });
  }, [records, clientSort]);

  const dynamicCols = useMemo(() => {
    if (artifactTypes.length !== 1) return [];
    return buildDynamicCols(records, artifactTypes[0], caseId);
  }, [artifactTypes, records, caseId, dynamicColsRev]);

  const visibleCols = useMemo(() => {
    const descIdx = LEDGER_COLS.findIndex(c => c.key === 'description');
    const insertAt = descIdx !== -1 ? descIdx + 1 : LEDGER_COLS.length;
    const combined = [
      ...LEDGER_COLS.slice(0, insertAt),
      ...dynamicCols,
      ...LEDGER_COLS.slice(insertAt),
    ];
    const base = orderColumns(combined, colOrder).filter(c => !hiddenCols.has(c.key));
    return base.map(c => {
      const w = colWidths.get(c.key);
      if (w) return { ...c, size: w };
      if (c.key === 'timestamp') return { ...c, size: timestampColumnWidth(density) };
      return c;
    });
  }, [dynamicCols, hiddenCols, colWidths, colOrder, density]);

  const reorderCols = useCallback((fromKey, toKey) => {
    setColOrder(prev => {
      const current = prev.length ? prev : visibleCols.map(c => c.key);
      const next = moveColumn(current.includes(fromKey) ? current : [...current, fromKey], fromKey, toKey);
      try { localStorage.setItem(colKey('colOrder'), JSON.stringify(next)); } catch { }
      return next;
    });
  }, [visibleCols, colKey]);

  const constantCols = useMemo(
    () => constantColumns(records, visibleCols.map(c => c.key)),
    [records, visibleCols]);

  const gridTemplate = useMemo(() => {
    return `${PREFIX} ${visibleCols.map(c => (c.meta?.flex && c.size == null) ? '1fr' : `${c.size ?? 120}px`).join(' ')}`;
  }, [visibleCols]);

  const pinnedOffsets = useMemo(() => {
    const offsets = new Map();
    let left = 4;
    for (const col of visibleCols) {
      if (pinnedCols.includes(col.key)) {
        offsets.set(col.key, left);
      }
      left += col.meta?.flex ? 0 : (col.size ?? 120);
    }
    return offsets;
  }, [visibleCols, pinnedCols]);

  const totalGridMinWidth = useMemo(() => {
    return 4 + visibleCols.reduce((sum, col) => sum + (col.meta?.flex ? 160 : (col.size ?? 120)), 0);
  }, [visibleCols]);

  const [expandedGroups, setExpandedGroups] = useState({});
  const groupKey = groupByFields.map(f => f.key).join('|');
  const resetKey = `${caseId ?? ''}|${groupKey}`;
  const [prevResetKey, setPrevResetKey] = useState(resetKey);

  if (prevResetKey !== resetKey) {
    setPrevResetKey(resetKey);
    setExpandedGroups({});
  }

  function getGroupValue(record, colKey) {
    if (colKey.startsWith('raw.')) return String(readRawPath(record.raw, colKey.slice(4)) ?? '—');
    if (colKey === '_source')      return String(record.source ?? '—');
    return String(record[colKey] ?? '—');
  }

  const flatRows = useMemo(() => {
    let rows;
    if (groupByFields.length > 0) {
      const fields = groupByFields.map(f => f.key);
      const sorted = [...displayRecords].sort((a, b) => {
        for (const f of fields) {
          const va = getGroupValue(a, f), vb = getGroupValue(b, f);
          if (va < vb) return -1; if (va > vb) return 1;
        }
        return 0;
      });
      const counts = new Map();
      const spans  = new Map();
      sorted.forEach(r => {
        const ts = r.timestamp ? new Date(r.timestamp).getTime() : NaN;
        let path = '';
        fields.forEach(f => {
          path += '␟' + getGroupValue(r, f);
          counts.set(path, (counts.get(path) || 0) + 1);
          if (!Number.isNaN(ts)) {
            const cur = spans.get(path);
            if (!cur) spans.set(path, { first: ts, last: ts });
            else { if (ts < cur.first) cur.first = ts; if (ts > cur.last) cur.last = ts; }
          }
        });
      });
      const result   = [];
      const prevVals = new Array(fields.length).fill(null);
      const stack    = new Array(fields.length).fill(null);
      const vis      = new Array(fields.length).fill(true);
      sorted.forEach(r => {
        let changed = -1;
        for (let lv = 0; lv < fields.length; lv++) {
          if (getGroupValue(r, fields[lv]) !== prevVals[lv]) { changed = lv; break; }
        }
        if (changed !== -1) {
          for (let lv = changed; lv < fields.length; lv++) {
            const val = getGroupValue(r, fields[lv]);
            prevVals[lv] = val;
            const parentId = lv === 0 ? '' : stack[lv - 1];
            const id = parentId + '␟' + String(val);
            stack[lv] = id;
            const parentVis = lv === 0 ? true : vis[lv - 1] && expandedGroups[stack[lv - 1]] === true;
            vis[lv] = parentVis;
            const label = groupByFields[lv]?.label ?? fields[lv];
            if (parentVis) result.push({ type: 'group', level: lv, field: label, value: val, id,
              count: counts.get(id) || 0, span: spans.get(id) || null });
            for (let d = lv + 1; d < fields.length; d++) prevVals[d] = null;
          }
        }
        const allExp = stack.slice(0, fields.length).every(id => expandedGroups[id] === true);
        if (allExp) result.push({ type: 'row', record: r });
      });
      rows = result;
    } else {
      rows = displayRecords.map(record => ({ type: 'row', record }));
    }
    if (page < totalPages) rows = [...rows, { type: 'loadmore' }];
    return rows;
  }, [displayRecords, groupByFields, expandedGroups, page, totalPages]);

  const virt = useVirtualizer({
    count:            flatRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize:     i => rowHeightFor(density, flatRows[i]),
    overscan: 12,
  });

  useEffect(() => { virt.measure(); }, [density]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable) return;
      if ((e.key === 'c' || e.key === 'C') && (e.ctrlKey || e.metaKey) && selectedRowId != null) {
        e.preventDefault();
        const rec = records.find(r => r.id === selectedRowId);
        if (!rec) return;
        const line = visibleCols.map(col => {
          let val;
          if (col.meta?.dynamic) {
            val = rec.raw?.[col.meta.rawKey] ?? '';
          } else if (col.key === '_source') {
            val = rec.source ?? '';
          } else if (col.key === '_verdict') {
            val = '';
          } else {
            val = rec[col.key] ?? '';
          }
          const str = String(val).replace(/"/g, '""');
          return str.includes(',') || str.includes('"') || str.includes('\n')
            ? `"${str}"` : str;
        }).join(',');
        navigator.clipboard.writeText(line).catch(() => {});
        return;
      }
      if (e.key === 'Escape' && selectedRowId != null) {
        useTimelineStore.getState().closeDetail();
        return;
      }
      if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && selectedRowId != null) {
        e.preventDefault();
        const dataRows = flatRows.filter(fr => fr.type === 'row');
        const idx  = dataRows.findIndex(fr => fr.record.id === selectedRowId);
        const next = e.key === 'ArrowDown' ? idx + 1 : idx - 1;
        if (next >= 0 && next < dataRows.length) {
          const nextId  = dataRows[next].record.id;
          const flatIdx = flatRows.findIndex(fr => fr.type === 'row' && fr.record.id === nextId);
          setSelectedRow(nextId);
          if (flatIdx >= 0) virt.scrollToIndex(flatIdx, { align: 'auto' });
        }
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selectedRowId, flatRows, virt, setSelectedRow, visibleCols, records]);

  useEffect(() => {
    const el = loadMoreRef.current;
    if (!el || loading || page >= totalPages) return;
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) loadMore(); },
      { threshold: 0.1 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [loadMoreRef.current, loading, page, totalPages, loadMore]);

  const handleRowClick = useCallback((record) => {
    const { selectedRowId: cur, setSelectedRow: set_ } = useTimelineStore.getState();
    set_(record.id === cur ? null : record.id);
  }, []);

  const handleExportCsv = useCallback(async () => {
    const s = useTimelineStore.getState();
    const params = {
      sort_dir: s.sortDir, sort_col: s.sortCol,
      ...(s.search        ? { search: s.search, search_op: s.searchOp } : {}),
      ...(s.artifactTypes.length ? { artifact_types: s.artifactTypes.join(',') } : {}),
      ...(s.startTime     ? { start_time: new Date(s.startTime).toISOString() } : {}),
      ...(s.endTime       ? { end_time:   new Date(s.endTime).toISOString()   } : {}),
      ...(s.hostFilter    ? { host_name:  s.hostFilter  } : {}),
      ...(s.userFilter    ? { user_name:  s.userFilter  } : {}),
      ...(s.toolFilter    ? { tool:       s.toolFilter  } : {}),
      ...(s.eventIdFilter ? { event_id:   s.eventIdFilter } : {}),
      ...(s.extFilter     ? { ext:        s.extFilter   } : {}),
      ...(s.tagFilter     ? { tag:        s.tagFilter   } : {}),
      ...(s.hitsOnly      ? { detections: 'hits_only'  } : {}),
      ...(s.dedupe        ? { dedupe:     'collapse'   } : {}),
    };
    try {
      const res = await collectionAPI.exportCsv(s.caseId, params);
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }));
      const a   = document.createElement('a');
      a.href     = url;
      a.download = `timeline-${s.caseId}-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('CSV export failed', err);
    }
  }, []);

  const [showColManager,   setShowColManager]   = useState(false);
  const [showRulesManager, setShowRulesManager] = useState(false);
  const [ctxMenu, setCtxMenu] = useState(null);
  useEffect(() => {
    const close = () => setCtxMenu(null);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);

  const vitems = virt.getVirtualItems();

  const pivotBtnStyle = {
    display: 'block', width: '100%', textAlign: 'left', padding: '5px 14px',
    background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-purple)', fontSize: 11,
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--fl-bg)' }}>

      <div style={{ height: 28, background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)',
        display: 'flex', alignItems: 'center', padding: '0 10px', gap: 6, flexShrink: 0 }}>
        {loading && <Loader2 size={12} style={{ color: 'var(--fl-accent)', animation: 'spin 1s linear infinite', flexShrink: 0 }} />}
        <button
          onClick={() => setShowRulesManager(true)}
          title="Color rules"
          style={{
            background: 'none', border: 'none', cursor: 'pointer', padding: '2px 5px',
            borderRadius: 3, display: 'flex', alignItems: 'center',
          }}
          onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
        >
          <Palette size={11} style={{ color: colorRules.length > 0 ? 'var(--fl-accent)' : 'var(--fl-subtle)' }} />
        </button>
        <button
          onClick={handleExportCsv}
          title="Export timeline as CSV (current filters)"
          style={{
            background: 'none', border: 'none', cursor: 'pointer', padding: '2px 6px',
            borderRadius: 3, display: 'flex', alignItems: 'center', gap: 3,
            fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.background = 'var(--fl-panel)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; e.currentTarget.style.background = 'none'; }}
        >
          <Download size={11} style={INLINE_PICTO} /> CSV
        </button>
        <div style={{ flex: 1 }} />
        {artifactTypes.length === 1 && (
          <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 3,
            background: `color-mix(in srgb, ${artifactColor(artifactTypes[0])} 9%, transparent)`, color: artifactColor(artifactTypes[0]),
            border: `1px solid color-mix(in srgb, ${artifactColor(artifactTypes[0])} 25%, transparent)` }}>
            {artifactTypes[0].toUpperCase()} · {t('timeline.schema_hint')}
          </span>
        )}
        <span style={{ fontSize: 9, color: countState.kind === 'count' ? 'var(--fl-muted)' : 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          {countState.kind === 'loading' ? t('timeline.count_loading')
            : countState.kind === 'empty' ? t('timeline.count_empty')
            : `${countState.total.toLocaleString(i18n.language)} events`}
        </span>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowColManager(v => !v)}
            title="Show/hide columns"
            style={{
              background: 'none', border: 'none', cursor: 'pointer', padding: '2px 5px',
              borderRadius: 3, display: 'flex', alignItems: 'center',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
          >
            <Columns size={11} style={{ color: hiddenCols.size > 0 ? 'var(--fl-accent)' : 'var(--fl-subtle)' }} />
          </button>
          {showColManager && (
            <ColumnManager
              allCols={[...LEDGER_COLS, ...dynamicCols]}
              hiddenCols={hiddenCols}
              constantCols={constantCols}
              onToggle={key => setHiddenCols(prev => {
                const next = new Set(prev);
                next.has(key) ? next.delete(key) : next.add(key);
                try { localStorage.setItem(colKey('hiddenCols'), JSON.stringify([...next])); } catch { }
                return next;
              })}
              onReset={() => {
                setHiddenCols(new Set());
                try { localStorage.removeItem(colKey('hiddenCols')); } catch { }
                setShowColManager(false);
              }}
              onClose={() => setShowColManager(false)}
            />
          )}
        </div>
      </div>

      <GroupPanel />

      <div
        ref={scrollRef}
        onScroll={e => {
          const el = e.currentTarget;
          const sl = el.scrollLeft;
          scrollLeftRef.current = sl;
          groupRowEls.current.forEach(r => { if (r) r.style.transform = `translateX(${sl}px)`; });
          el.querySelectorAll('[data-sticky-left]').forEach(r => { r.style.transform = `translateX(${sl}px)`; });
          if (!loading && page < totalPages && el.scrollTop + el.clientHeight >= el.scrollHeight - 300) {
            loadMore();
          }
        }}
        style={{
          flex: 1,
          overflow: 'auto',
          position: 'relative',
          '--tl-row-h': `${rowHeightFor(density, { type: 'row' })}px`,
        }}
      >
        <div style={{
          position: 'sticky', top: 0, zIndex: 10,
          background: 'var(--fl-bg)', borderBottom: '2px solid var(--fl-border)',
          display: 'grid', gridTemplateColumns: gridTemplate,
          height: 26, minWidth: totalGridMinWidth,
        }}>
          <div style={{ width: 4 }} />
          {visibleCols.map(col => (
            <ColumnHeader key={col.key} col={col}
              sortState={{ col: sortCol, dir: sortDir }} multiSort={multiSort}
              onSort={(key, shift) => handleColSort(key, shift)}
              onReorder={reorderCols}
              isPinned={pinnedCols.includes(col.key)}
              pinnedOffset={pinnedOffsets.get(col.key)}
              clientSort={clientSort}
              scrollLeftRef={scrollLeftRef}
              onPin={key => setPinnedCols(prev => {
                const next = prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key];
                try { localStorage.setItem(colKey('pinnedCols'), JSON.stringify(next)); } catch { }
                return next;
              })}
              onResize={(key, width) => setColWidths(prev => {
                const next = new Map(prev);
                next.set(key, width);
                try { localStorage.setItem(colKey('colWidths'), JSON.stringify(Object.fromEntries(next))); } catch { }
                return next;
              })}
            />
          ))}
        </div>
        <div style={{ height: virt.getTotalSize(), position: 'relative', minWidth: totalGridMinWidth }}>
          {vitems.map(vi => {
            const item = flatRows[vi.index];
            if (!item) return null;
            const style = { position: 'absolute', top: vi.start, left: 0, width: '100%', minWidth: totalGridMinWidth };

            if (item.type === 'loadmore') {
              return (
                <div ref={loadMoreRef} key={vi.key} style={{ ...style, display: 'flex', alignItems: 'center', justifyContent: 'center', height: rowHeightFor(density, item), borderTop: '1px solid var(--fl-border)', background: 'var(--fl-bg)' }}>
                  {loading
                    ? <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', display: 'flex', alignItems: 'center', gap: 6 }}><Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> Loading…</span>
                    : <button
                        onClick={loadMore}
                        style={{ padding: '5px 16px', borderRadius: 5, background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', color: 'var(--fl-accent)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                      >
                        ↓ Load next {pageSize} events
                        <span style={{ color: 'var(--fl-muted)', marginLeft: 6 }}>(showing {records.length.toLocaleString(i18n.language)} of {total.toLocaleString(i18n.language)})</span>
                      </button>
                  }
                </div>
              );
            }

            if (item.type === 'group') {
              return (
                <div
                  key={vi.key}
                  ref={el => {
                    if (el) {
                      groupRowEls.current.set(vi.key, el);
                      el.style.transform = `translateX(${scrollLeftRef.current}px)`;
                    } else {
                      groupRowEls.current.delete(vi.key);
                    }
                  }}
                  style={{ position: 'absolute', top: vi.start, left: 0, width: '100vw' }}
                >
                  <GroupRow
                    field={item.field} value={item.value} count={item.count} level={item.level}
                    span={item.span}
                    locale={i18n.language}
                    height={rowHeightFor(density, item)}
                    isOpen={expandedGroups[item.id] === true}
                    onClick={() => setExpandedGroups(prev => ({ ...prev, [item.id]: prev[item.id] === true ? undefined : true }))}
                  />
                </div>
              );
            }

            const r = item.record;
            return (
              <div key={vi.key} style={style}>
                <EventRow
                  record={r}
                  stacked={stacksTimestamp(density)}
                  nowMs={nowMs}
                  gridTemplate={gridTemplate}
                  visibleCols={visibleCols}
                  isSelected={selectedRowId === r.id}
                  hasNote={notedRefs.has(computeRef(r))}
                  tagEntry={tagData.get(r.id)}
                  colorRules={colorRules}
                  searchTerm={search}
                  onClick={() => handleRowClick(r)}
                  onCellContextMenu={(e, col, row) => setCtxMenu({ x: e.clientX, y: e.clientY, col, row })}
                  pinnedCols={pinnedCols}
                  pinnedOffsets={pinnedOffsets}
                  scrollLeftRef={scrollLeftRef}
                  tsLabels={tsLabels}
                />
              </div>
            );
          })}
        </div>

        {!loading && records.length === 0 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, textAlign: 'center', padding: '0 24px' }}>
            {huntMessage || 'No events match current filters'}
          </div>
        )}
      </div>

      {showRulesManager && (
        <div
          onClick={() => setShowRulesManager(false)}
          style={{
            position: 'fixed', inset: 0, zIndex: 4000,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          <div onClick={e => e.stopPropagation()} style={{ maxHeight: '80vh', overflowY: 'auto' }}>
            <ColorRulesManager
              open={showRulesManager}
              caseId={caseId}
              onClose={() => setShowRulesManager(false)}
              onRulesChange={rules => {
                useTimelineStore.getState().setColorRules(rules);
              }}
            />
          </div>
        </div>
      )}

      {ctxMenu && (
        <div onMouseDown={e => e.stopPropagation()} style={{
          position: 'fixed', top: ctxMenu.y, left: ctxMenu.x, zIndex: 2000,
          background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 8,
          padding: '4px 0', minWidth: 220, boxShadow: '0 8px 28px rgba(0,0,0,0.7)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
        }}>
          <div style={{ padding: '3px 12px 5px', fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid var(--fl-border)' }}>
            {ctxMenu.col.label} — <span style={{ color: '#556070' }}>{String(ctxMenu.row[ctxMenu.col.key] ?? ctxMenu.row.raw?.[ctxMenu.col.meta?.rawKey] ?? '').slice(0, 40)}</span>
          </div>
          {[
            { label: '⊃ Filter contains', fn: () => { const s = useTimelineStore.getState(); const v = String(ctxMenu.row[ctxMenu.col.key] ?? ctxMenu.row.raw?.[ctxMenu.col.meta?.rawKey] ?? ''); s.setFilter('search', v); s.applyFilters(); } },
            { label: '＝ Filter equals',   fn: () => { const s = useTimelineStore.getState(); const v = String(ctxMenu.row[ctxMenu.col.key] ?? ctxMenu.row.raw?.[ctxMenu.col.meta?.rawKey] ?? ''); s.setFilter('searchOp', 'equals'); s.setFilter('search', v); s.applyFilters(); } },
            { label: '⊄ Exclude value',   fn: () => { const s = useTimelineStore.getState(); const v = String(ctxMenu.row[ctxMenu.col.key] ?? ctxMenu.row.raw?.[ctxMenu.col.meta?.rawKey] ?? ''); s.setFilter('searchOp', 'not_contains'); s.setFilter('search', v); s.applyFilters(); } },
          ].map(item => (
            <button
              key={item.label}
              onClick={() => { item.fn(); setCtxMenu(null); }}
              style={{ display: 'block', width: '100%', textAlign: 'left', padding: '5px 14px', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', fontSize: 11 }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
            >
              {item.label}
            </button>
          ))}

          {((ctxMenu.col.key === 'host_name' && ctxMenu.row.host_name) ||
            (ctxMenu.col.key === 'user_name' && ctxMenu.row.user_name) ||
            ctxMenu.row.process_name) && (
            <>
              <div style={{ height: 1, background: 'var(--fl-card)', margin: '3px 0' }} />
              {ctxMenu.col.key === 'host_name' && ctxMenu.row.host_name && (
                <button
                  onClick={() => { const s = useTimelineStore.getState(); s.setFilter('hostFilter', ctxMenu.row.host_name); s.applyFilters(); setCtxMenu(null); }}
                  style={pivotBtnStyle}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-panel)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'none'}
                >→ Focus on this Host</button>
              )}
              {ctxMenu.col.key === 'user_name' && ctxMenu.row.user_name && (
                <button
                  onClick={() => { const s = useTimelineStore.getState(); s.setFilter('userFilter', ctxMenu.row.user_name); s.applyFilters(); setCtxMenu(null); }}
                  style={pivotBtnStyle}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-panel)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'none'}
                >→ Focus on this User</button>
              )}
              {ctxMenu.row.process_name && (
                <button
                  onClick={() => { const s = useTimelineStore.getState(); s.setFilter('search', ctxMenu.row.process_name); s.applyFilters(); setCtxMenu(null); }}
                  style={pivotBtnStyle}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-panel)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'none'}
                >→ Focus on this Process</button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
