import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { ChevronRight, ChevronDown, X, Loader2, Layers, GripVertical } from 'lucide-react';
import { collectionAPI } from '../../utils/api';
import { fmtTs as fmtTsUtil } from '../../utils/formatters';

const GROUPABLE_COLS = [
  { key: 'tool',                label: 'Tool' },
  { key: 'artifact_type',       label: 'Artifact' },
  { key: 'event_id',            label: 'Event ID' },
  { key: 'host_name',           label: 'Host' },
  { key: 'user_name',           label: 'User' },
  { key: 'process_name',        label: 'Process' },
  { key: 'ext',                 label: 'Extension' },
  { key: 'mitre_technique_id',  label: 'MITRE T-ID' },
  { key: 'source',              label: 'Source' },
];
const GROUPABLE_KEYS = new Set(GROUPABLE_COLS.map(c => c.key));
const LABEL_BY_KEY = Object.fromEntries(GROUPABLE_COLS.map(c => [c.key, c.label]));

function storageKey(caseId) { return `te.grouping.${caseId}`; }
function loadGrouping(caseId) {
  try { const raw = localStorage.getItem(storageKey(caseId)); if (raw) return JSON.parse(raw); } catch (_e) {}
  return [];
}
function saveGrouping(caseId, g) {
  try { localStorage.setItem(storageKey(caseId), JSON.stringify(g)); } catch (_e) {}
}

function buildTree(flatGroups, depth) {
  if (depth === 1) {
    return flatGroups.map(g => ({ ...g, leafChildren: null }));
  }
  const root = new Map();
  for (const g of flatGroups) {
    let cursor = root;
    let node = null;
    for (let d = 0; d < g.key.length; d++) {
      const k = g.key[d];
      const isLeaf = d === g.key.length - 1;
      let entry = cursor.get(k);
      if (!entry) {
        entry = { key: g.key.slice(0, d + 1), count: 0, first_ts: null, last_ts: null, sample_ids: [], children: new Map() };
        cursor.set(k, entry);
      }
      entry.count += g.count;
      if (!entry.first_ts || g.first_ts < entry.first_ts) entry.first_ts = g.first_ts;
      if (!entry.last_ts || g.last_ts > entry.last_ts) entry.last_ts = g.last_ts;
      if (isLeaf) {
        entry.sample_ids = g.sample_ids;
      }
      cursor = entry.children;
      node = entry;
    }
  }
  function walk(map) {
    return [...map.values()].map(n => ({
      key: n.key, count: n.count, first_ts: n.first_ts, last_ts: n.last_ts,
      sample_ids: n.sample_ids,
      children: n.children.size ? walk(n.children) : null,
    })).sort((a, b) => b.count - a.count);
  }
  return walk(root);
}

function flattenForRender(tree, expanded, depth = 0, parentKey = '') {
  const out = [];
  for (const node of tree) {
    const id = parentKey + '/' + node.key.join('|');
    out.push({ type: 'group', depth, id, node });
    if (expanded[id] && node.children) {
      out.push(...flattenForRender(node.children, expanded, depth + 1, id));
    }
  }
  return out;
}

export default function TimelineExplorer({ caseId, filters = {}, onClose }) {
  const [grouping, setGrouping]   = useState(() => loadGrouping(caseId));
  const [groups, setGroups]       = useState([]);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState(null);
  const [expanded, setExpanded]   = useState({});
  const [meta, setMeta]           = useState({ total_groups: 0, elapsed_ms: 0 });
  const [dragOverPanel, setDragOverPanel] = useState(false);

  useEffect(() => { saveGrouping(caseId, grouping); }, [caseId, grouping]);

  useEffect(() => {
    if (!caseId || grouping.length === 0) { setGroups([]); setMeta({ total_groups: 0, elapsed_ms: 0 }); return; }
    setLoading(true);
    setError(null);
    collectionAPI.timelineGroups(caseId, grouping, filters)
      .then(r => {
        setGroups(r.data?.groups || []);
        setMeta({ total_groups: r.data?.total_groups || 0, elapsed_ms: r.data?.elapsed_ms || 0 });
      })
      .catch(e => setError(e?.response?.data?.error || e?.message || 'group request failed'))
      .finally(() => setLoading(false));
  }, [caseId, grouping, JSON.stringify(filters)]);

  const tree = useMemo(() => buildTree(groups, grouping.length || 1), [groups, grouping.length]);
  const rows = useMemo(() => flattenForRender(tree, expanded), [tree, expanded]);

  const scrollRef = useRef(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 30,
    overscan: 30,
  });

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOverPanel(false);
    const colKey = e.dataTransfer.getData('application/x-tl-column') || e.dataTransfer.getData('text/plain');
    if (!colKey || !GROUPABLE_KEYS.has(colKey)) return;
    setGrouping(prev => {
      if (prev.includes(colKey)) return prev;
      if (prev.length >= 3) return prev;
      return [...prev, colKey];
    });
  }, []);

  function removeChip(idx) {
    setGrouping(prev => prev.filter((_, i) => i !== idx));
  }
  function moveChip(from, to) {
    setGrouping(prev => {
      const next = [...prev];
      const [it] = next.splice(from, 1);
      next.splice(to, 0, it);
      return next;
    });
  }

  const allRowsCount = useMemo(() => groups.reduce((acc, g) => acc + g.count, 0), [groups]);

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', height: '100%',
      background: 'var(--fl-bg)', color: 'var(--fl-on-dark)', fontFamily: 'monospace', fontSize: 11,
    }}>
      {/* ─ Group panel (drop zone + chip strip) ─ */}
      <div
        onDragOver={e => { if (Array.from(e.dataTransfer.types || []).includes('application/x-tl-column')) { e.preventDefault(); setDragOverPanel(true); } }}
        onDragLeave={() => setDragOverPanel(false)}
        onDrop={handleDrop}
        style={{
          padding: '10px 14px',
          borderBottom: '1px solid var(--fl-sep)',
          background: dragOverPanel ? 'rgba(201,104,152,0.12)' : 'var(--fl-card)',
          borderTop: `2px dashed ${dragOverPanel ? 'var(--fl-purple)' : 'transparent'}`,
          display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        }}>
        <Layers size={13} style={{ color: 'var(--fl-purple)' }} />
        <strong style={{ color: 'var(--fl-purple)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Group by
        </strong>
        {grouping.length === 0 && (
          <span style={{ color: 'var(--fl-muted)', fontStyle: 'italic' }}>
            Drag a column header here to group by that column (max 3 levels)
          </span>
        )}
        {grouping.map((k, i) => (
          <span key={k}
            draggable
            onDragStart={e => { e.dataTransfer.setData('application/x-tl-chip-index', String(i)); }}
            onDragOver={e => e.preventDefault()}
            onDrop={e => {
              const from = parseInt(e.dataTransfer.getData('application/x-tl-chip-index'), 10);
              if (Number.isFinite(from) && from !== i) moveChip(from, i);
              e.stopPropagation();
            }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '4px 8px', borderRadius: 6,
              background: 'rgba(201,104,152,0.10)', border: '1px solid var(--fl-purple)',
              color: 'var(--fl-on-dark)', cursor: 'grab',
            }}>
            <GripVertical size={10} style={{ color: 'var(--fl-muted)' }} />
            <span style={{ color: 'var(--fl-muted)', fontSize: 9 }}>{i + 1}.</span>
            <span>{LABEL_BY_KEY[k] || k}</span>
            <button onClick={() => removeChip(i)}
              style={{ background: 'none', border: 'none', color: 'var(--fl-dim)', cursor: 'pointer', padding: 0, display: 'flex' }}
              title="Remove">
              <X size={11} />
            </button>
          </span>
        ))}
        <span style={{ marginLeft: 'auto', color: 'var(--fl-dim)', fontSize: 10 }}>
          {loading
            ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> aggregating…</span>
            : grouping.length > 0 && `${meta.total_groups.toLocaleString('fr-FR')} buckets · ${allRowsCount.toLocaleString('fr-FR')} rows · ${meta.elapsed_ms} ms`}
        </span>
        {onClose && (
          <button onClick={onClose}
            className="fl-btn fl-btn-ghost fl-btn-sm"
            style={{ color: 'var(--fl-dim)' }}>
            <X size={11} /> Close
          </button>
        )}
      </div>

      {/* ─ Hint when nothing grouped — show a palette of clickable group cols ─ */}
      {grouping.length === 0 && !loading && (
        <div style={{ padding: '14px', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          <span style={{ color: 'var(--fl-muted)', alignSelf: 'center', marginRight: 4 }}>Quick group:</span>
          {GROUPABLE_COLS.map(c => (
            <button key={c.key}
              onClick={() => setGrouping([c.key])}
              draggable
              onDragStart={e => { e.dataTransfer.setData('application/x-tl-column', c.key); e.dataTransfer.effectAllowed = 'copy'; }}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title={`Group by ${c.label} (drag-able)`}
              style={{ color: 'var(--fl-accent)', border: '1px solid var(--fl-border)' }}>
              {c.label}
            </button>
          ))}
        </div>
      )}

      {/* ─ Error state ─ */}
      {error && (
        <div style={{ padding: 14, color: 'var(--fl-danger)', borderBottom: '1px solid var(--fl-sep)' }}>
          {error}
        </div>
      )}

      {/* ─ Virtualized list of groups + expanded leaves ─ */}
      <div ref={scrollRef} style={{ flex: 1, overflow: 'auto', position: 'relative' }}>
        {rows.length > 0 && (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map(vi => {
              const item = rows[vi.index];
              if (!item) return null;
              const node = item.node;
              const isExpanded = !!expanded[item.id];
              const indent = item.depth * 18 + 10;
              const colKey = grouping[item.depth];
              const valLabel = node.key[node.key.length - 1];
              return (
                <div key={item.id}
                  style={{
                    position: 'absolute', top: 0, left: 0, width: '100%',
                    transform: `translateY(${vi.start}px)`, height: vi.size,
                    display: 'flex', alignItems: 'center', gap: 10,
                    paddingLeft: indent, paddingRight: 14,
                    borderBottom: '1px solid var(--fl-sep)',
                    background: item.depth === 0 ? 'rgba(77,130,192,0.05)' : 'transparent',
                    cursor: 'pointer',
                  }}
                  onClick={() => setExpanded(prev => ({ ...prev, [item.id]: !prev[item.id] }))}>
                  <span style={{ color: 'var(--fl-dim)', display: 'inline-flex' }}>
                    {(node.children || (item.depth === grouping.length - 1 && node.sample_ids?.length))
                      ? (isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />)
                      : <span style={{ width: 12 }} />}
                  </span>
                  <span style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase' }}>
                    {LABEL_BY_KEY[colKey] || colKey}
                  </span>
                  <span style={{ color: 'var(--fl-on-dark)', fontWeight: 600 }}>
                    {valLabel === null || valLabel === undefined || valLabel === '' ? <em style={{ color: 'var(--fl-muted)' }}>∅</em> : String(valLabel)}
                  </span>
                  <span style={{ marginLeft: 'auto', color: 'var(--fl-accent)' }}>
                    {Number(node.count).toLocaleString('fr-FR')}
                  </span>
                  <span style={{ color: 'var(--fl-dim)', fontSize: 10, minWidth: 220, textAlign: 'right' }}>
                    {fmtTsUtil(node.first_ts)} → {fmtTsUtil(node.last_ts)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
        {!loading && grouping.length > 0 && rows.length === 0 && !error && (
          <div style={{ padding: 24, color: 'var(--fl-muted)', textAlign: 'center' }}>
            No groups for this filter set.
          </div>
        )}
      </div>
    </div>
  );
}

export { GROUPABLE_COLS, GROUPABLE_KEYS };
