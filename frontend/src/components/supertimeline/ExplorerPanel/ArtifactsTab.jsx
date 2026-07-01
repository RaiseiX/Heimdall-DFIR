import { useState, useEffect, useCallback } from 'react';
import { Plus, X, Loader2, ChevronDown, ChevronRight } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { tabColor, GROUP_BY_FIELDS } from '../utils/timelineUtils';
import { collectionAPI } from '../../../utils/api';

// Detection summary severity rows
const SEV_ROWS = [
  { key: 'critical', color: 'var(--fl-danger)', label: 'Critical' },
  { key: 'high',     color: 'var(--fl-warn)', label: 'High'     },
  { key: 'medium',   color: 'var(--fl-gold)', label: 'Medium'   },
  { key: 'low',      color: 'var(--fl-ok)', label: 'Low'      },
];

function buildGroupParams(store) {
  const p = {};
  if (store.search)             { p.search = store.search; p.search_op = store.searchOp; }
  if (store.artifactTypes.length) p.artifact_types = store.artifactTypes.join(',');
  if (store.startTime)            p.start_time = new Date(store.startTime).toISOString();
  if (store.endTime)              p.end_time   = new Date(store.endTime).toISOString();
  if (store.hostFilter)           p.host_name  = store.hostFilter;
  if (store.userFilter)           p.user_name  = store.userFilter;
  if (store.evidenceId)           p.evidence_id = store.evidenceId;
  if (store.evidenceIds?.length)  p.evidence_ids = store.evidenceIds.join(',');
  if (store.hitsOnly)             p.detections = 'hits_only';
  return p;
}

function GroupBySection({ field, label, onRemove }) {
  const store = useTimelineStore();
  const { caseId } = store;
  const [groups,   setGroups]   = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [expanded, setExpanded] = useState(true);
  const [showAll,  setShowAll]  = useState(false);

  const load = useCallback(async () => {
    if (!caseId || !field) return;
    setLoading(true);
    try {
      const res = await collectionAPI.timelineGroups(caseId, field, buildGroupParams(useTimelineStore.getState()));
      setGroups(res.data?.groups || []);
    } catch { setGroups([]); }
    finally  { setLoading(false); }
  }, [caseId, field]);

  useEffect(() => { load(); }, [load]);

  const filterSig = [store.search, store.artifactTypes.join(','), store.startTime, store.endTime,
    store.hostFilter, store.userFilter, store.hitsOnly].join('|');
  useEffect(() => { load(); }, [filterSig]); // eslint-disable-line react-hooks/exhaustive-deps

  function applyGroupValue(value) {
    const s = useTimelineStore.getState();
    if (field === 'artifact_type')   { s.toggleArtifactType(value); return; }
    if (field === 'host_name')       { s.setFilter('hostFilter', value); }
    else if (field === 'user_name')  { s.setFilter('userFilter', value); }
    else if (field === 'tool')       { s.setFilter('toolFilter', value); }
    else if (field === 'event_id')   { s.setFilter('eventIdFilter', String(value)); }
    else if (field === 'ext')        { s.setFilter('extFilter', value); }
    else                             { s.setFilter('search', String(value)); }
    s.applyFilters();
  }

  const visible  = groups.slice(0, showAll ? groups.length : 7);
  const maxCount = groups[0]?.count || 1;
  const col      = field === 'artifact_type' ? 'var(--fl-accent)' : 'var(--fl-purple)';

  return (
    <div style={{ marginBottom: 2 }}>
      <div onClick={() => setExpanded(v => !v)}
        style={{ padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
        {expanded ? <ChevronDown size={9} style={{ color: 'var(--fl-muted)' }} /> : <ChevronRight size={9} style={{ color: 'var(--fl-muted)' }} />}
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: col, flexShrink: 0 }} />
        <span style={{ flex: 1, fontSize: 10, color: '#6a8ab0', fontWeight: 600 }}>{label}</span>
        {loading && <Loader2 size={9} style={{ color: 'var(--fl-muted)', animation: 'spin 1s linear infinite' }} />}
        {!loading && groups.length > 0 && (
          <span style={{ fontSize: 9, color: 'var(--fl-muted)', background: 'var(--fl-panel)',
            border: '1px solid var(--fl-raised)', borderRadius: 3, padding: '1px 5px' }}>{groups.length}</span>
        )}
        <button onClick={e => { e.stopPropagation(); onRemove(); }}
          style={{ background: 'none', border: 'none', color: 'var(--fl-subtle)', cursor: 'pointer', display: 'flex', padding: '1px 2px' }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
          <X size={9} />
        </button>
      </div>
      {expanded && visible.map((g, i) => {
        const barPct = Math.round((g.count / maxCount) * 100);
        const gc = field === 'artifact_type' ? tabColor(g.value) : col;
        return (
          <div key={i} onClick={() => applyGroupValue(g.value)}
            style={{ padding: '3px 10px 3px 22px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}>
            <div style={{ width: 40, height: 4, background: 'var(--fl-panel)', borderRadius: 2, overflow: 'hidden', flexShrink: 0 }}>
              <div style={{ height: 4, width: `${barPct}%`, background: gc, borderRadius: 2 }} />
            </div>
            <span style={{ flex: 1, fontSize: 10, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {String(g.value ?? '—')}
            </span>
            <span style={{ fontSize: 8, color: 'var(--fl-muted)', minWidth: 36, textAlign: 'right' }}>
              {g.count.toLocaleString()}
            </span>
          </div>
        );
      })}
      {groups.length > 7 && (
        <button onClick={() => setShowAll(v => !v)}
          style={{ display: 'block', width: '100%', textAlign: 'left', padding: '3px 22px',
            background: 'none', border: 'none', cursor: 'pointer', fontSize: 9, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
          {showAll ? '▲ Show less' : `+ ${groups.length - 7} more…`}
        </button>
      )}
    </div>
  );
}

export default function ArtifactsTab() {
  const store = useTimelineStore();
  const { caseId, availTypes, typeCounts, artifactTypes, setFilter, applyFilters,
          groupByFields, addGroupByField, removeGroupByField,
          bookmarks, loadBookmarks } = store;
  const [detSummary, setDetSummary]   = useState(null);
  const [groupsOpen, setGroupsOpen]   = useState(true);
  const [showPicker, setShowPicker]   = useState(false);

  useEffect(() => {
    if (!caseId) return;
    collectionAPI.detectionsSummary(caseId)
      .then(r => setDetSummary(r.data))
      .catch(() => setDetSummary(null));
  }, [caseId]);

  useEffect(() => { if (caseId) loadBookmarks(); }, [caseId]); // eslint-disable-line

  const usedKeys  = new Set(groupByFields.map(f => f.key));
  const available = GROUP_BY_FIELDS.filter(f => !usedKeys.has(f.key));
  const totalDets = detSummary ? SEV_ROWS.reduce((acc, s) => acc + (detSummary[s.key] || 0), 0) : 0;

  return (
    <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>

      {/* Artifact list */}
      <div style={{ padding: '4px 0 2px' }}>
        <div style={{ padding: '2px 10px 4px', display: 'flex', alignItems: 'center' }}>
          <span style={{ flex: 1, fontSize: 8, fontWeight: 700, letterSpacing: '0.14em',
            textTransform: 'uppercase', color: 'var(--fl-subtle)' }}>
            Artifacts · {availTypes.length}
          </span>
          {artifactTypes.length > 0 && (
            <button
              onClick={() => store.clearArtifactTypes()}
              title="Clear artifact filter"
              style={{ background: 'none', border: 'none', color: 'var(--fl-subtle)', cursor: 'pointer',
                display: 'flex', padding: '1px 2px', borderRadius: 2 }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
              <X size={9} />
            </button>
          )}
        </div>
        {availTypes.map(t => {
          const col    = tabColor(t);
          const active = artifactTypes.includes(t);
          const count  = typeCounts[t];
          return (
            <div key={t} onClick={() => store.toggleArtifactType(t)}
              style={{ padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 7,
                cursor: 'pointer', borderLeft: active ? `2px solid ${col}` : '2px solid transparent',
                background: active ? 'var(--fl-card)' : 'transparent' }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--fl-panel)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = active ? 'var(--fl-card)' : 'transparent'; }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: active ? col : `color-mix(in srgb, ${col} 40%, transparent)`, flexShrink: 0 }} />
              <span style={{ flex: 1, fontSize: 10, color: active ? col : '#6a8ab0', fontWeight: active ? 700 : 400 }}>{t}</span>
              {count != null && (
                <span style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {count.toLocaleString()}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Detection summary */}
      {totalDets > 0 && (
        <div style={{ borderTop: '1px solid var(--fl-card)', paddingTop: 4 }}>
          <div style={{ padding: '2px 10px 4px', fontSize: 8, fontWeight: 700, letterSpacing: '0.14em',
            textTransform: 'uppercase', color: 'var(--fl-subtle)' }}>
            Detections · {totalDets.toLocaleString()}
          </div>
          {SEV_ROWS.map(s => {
            const count = detSummary?.[s.key] || 0;
            if (!count) return null;
            const pct = Math.round((count / totalDets) * 100);
            return (
              <div key={s.key} onClick={() => { setFilter('detSeverity', s.key); applyFilters(); }}
                style={{ padding: '3px 10px', display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer' }}
                onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}>
                <div style={{ width: 7, height: 7, borderRadius: '50%', background: s.color, flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: 10, color: '#7a8ba0' }}>{s.label}</span>
                <div style={{ width: 36, height: 3, background: 'var(--fl-panel)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: 3, width: `${pct}%`, background: s.color, borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 9, fontWeight: 700, color: s.color, minWidth: 28, textAlign: 'right' }}>
                  {count.toLocaleString()}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Group by accordion */}
      <div style={{ borderTop: '1px solid var(--fl-card)', paddingTop: 2 }}>
        <div onClick={() => setGroupsOpen(v => !v)}
          style={{ padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          {groupsOpen ? <ChevronDown size={9} style={{ color: 'var(--fl-muted)' }} /> : <ChevronRight size={9} style={{ color: 'var(--fl-muted)' }} />}
          <span style={{ flex: 1, fontSize: 8, fontWeight: 700, letterSpacing: '0.14em',
            textTransform: 'uppercase', color: 'var(--fl-subtle)' }}>Group by</span>
          <div style={{ position: 'relative' }}>
            <button onClick={e => { e.stopPropagation(); setShowPicker(v => !v); }}
              style={{ background: 'none', border: 'none', color: 'var(--fl-subtle)', cursor: 'pointer', display: 'flex', padding: '1px 2px', borderRadius: 2 }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
              <Plus size={12} />
            </button>
            {showPicker && available.length > 0 && (
              <div style={{ position: 'absolute', right: 0, top: '100%', zIndex: 200, marginTop: 2,
                background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 6, padding: '4px 0',
                minWidth: 160, boxShadow: '0 6px 20px rgba(0,0,0,0.7)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                {available.map(f => (
                  <button key={f.key}
                    onClick={() => { addGroupByField(f); setShowPicker(false); }}
                    style={{ display: 'block', width: '100%', textAlign: 'left', padding: '5px 12px',
                      background: 'none', border: 'none', color: 'var(--fl-dim)', fontSize: 10, cursor: 'pointer' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; e.currentTarget.style.color = 'var(--fl-accent)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--fl-dim)'; }}>
                    {f.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        {groupsOpen && groupByFields.map(f => (
          <GroupBySection key={f.key} field={f.key} label={f.label}
            onRemove={() => { removeGroupByField(f.key); }} />
        ))}
      </div>

      {/* Bookmarks section */}
      {bookmarks.length > 0 && (
        <div style={{ borderTop: '1px solid var(--fl-card)', paddingTop: 2 }}>
          <div style={{ padding: '4px 10px', fontSize: 8, fontWeight: 700,
            letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--fl-subtle)' }}>
            Bookmarks · {bookmarks.length}
          </div>
          {bookmarks.map(b => (
            <div
              key={b.id}
              onClick={() => {
                const s = useTimelineStore.getState();
                const rawTs = b.event_timestamp || b.timestamp;
                if (rawTs) {
                  const ts  = new Date(rawTs);
                  const fmt = d => d.toISOString().slice(0, 16);
                  s.setFilter('startTime', fmt(new Date(ts.getTime() - 30000)));
                  s.setFilter('endTime',   fmt(new Date(ts.getTime() + 30000)));
                  s.applyFilters();
                }
              }}
              style={{ padding: '4px 10px 4px 18px', cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 1 }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
            >
              <span style={{ fontSize: 10, color: 'var(--fl-gold)', overflow: 'hidden',
                textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                ★ {b.title || b.label || b.ref || '—'}
              </span>
              {(b.event_timestamp || b.timestamp) && (
                <span style={{ fontSize: 8, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {new Date(b.event_timestamp || b.timestamp).toISOString().slice(0, 19).replace('T', ' ')}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
