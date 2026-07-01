// frontend/src/components/supertimeline/CommandBar/CommandBar.jsx
import { useRef, useState, useEffect, useCallback } from 'react';
import { Search, X, ChevronDown } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { tabColor } from '../utils/timelineUtils';

const CHIP_STYLES = {
  search:       { bg: '#112030', color: '#6aabdb', border: '#1e3a50' },
  artifactType: { bg: '#0e2218', color: 'var(--fl-ok)', border: '#1a3520' },
  host:         { bg: '#1a1030', color: 'var(--fl-purple)', border: '#2a1a50' },
  user:         { bg: '#1a1030', color: 'var(--fl-pink)', border: '#2a1a50' },
  sev:          { bg: '#2a0f0f', color: 'var(--fl-danger)', border: '#3a1818' },
  after:        { bg: '#1a1808', color: 'var(--fl-gold)', border: '#3a3010' },
  before:       { bg: '#1a1808', color: 'var(--fl-gold)', border: '#3a3010' },
  tag:          { bg: 'var(--fl-card)', color: 'var(--fl-purple)', border: 'var(--fl-raised)' },
  tool:         { bg: 'var(--fl-card)', color: 'var(--fl-accent)', border: 'var(--fl-raised)' },
  eventId:      { bg: 'var(--fl-card)', color: 'var(--fl-dim)', border: 'var(--fl-raised)' },
  ext:          { bg: 'var(--fl-card)', color: 'var(--fl-dim)', border: 'var(--fl-raised)' },
};

function Chip({ kind, label, onRemove }) {
  const s = CHIP_STYLES[kind] || CHIP_STYLES.search;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 7px 2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
      whiteSpace: 'nowrap', flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
      {label}
      <span onClick={onRemove}
        style={{ opacity: 0.5, cursor: 'pointer', fontSize: 12, lineHeight: 1,
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 12, height: 12, borderRadius: 2, userSelect: 'none' }}
        onMouseEnter={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.background = 'rgba(255,255,255,0.1)'; }}
        onMouseLeave={e => { e.currentTarget.style.opacity = '0.5'; e.currentTarget.style.background = 'none'; }}>
        x
      </span>
    </span>
  );
}

function parseToken(raw) {
  const m = raw.trim().match(/^(type|host|user|after|before|sev|tag|tool|eid|ext):(.+)$/i);
  if (!m) return { kind: 'search', value: raw.trim() };
  const kindMap = { type: 'artifactType', host: 'host', user: 'user', after: 'after',
                    before: 'before', sev: 'sev', tag: 'tag', tool: 'tool', eid: 'eventId', ext: 'ext' };
  return { kind: kindMap[m[1].toLowerCase()] || m[1].toLowerCase(), value: m[2] };
}

export default function CommandBar() {
  const store = useTimelineStore();
  const {
    search, artifactTypes, hostFilter, userFilter, startTime, endTime,
    detSeverity, tagFilter, toolFilter, eventIdFilter, extFilter,
    hitsOnly, dedupe, availTypes, typeCounts,
    setFilter, applyFilters, clearFilters, toggleArtifactType, soloArtifactType,
  } = store;

  const inputRef = useRef(null);
  const [inputVal, setInputVal] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const advancedRef = useRef(null);

  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable) return;
      if (e.key === '/' || (e.key === 'k' && (e.ctrlKey || e.metaKey))) {
        e.preventDefault(); inputRef.current?.focus();
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const h = e => { if (advancedRef.current && !advancedRef.current.contains(e.target)) setShowAdvanced(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const applyToken = useCallback(token => {
    const s = useTimelineStore.getState();
    switch (token.kind) {
      case 'search':       s.setFilter('search', token.value); break;
      case 'artifactType': s.toggleArtifactType(token.value); return;
      case 'host':         s.setFilter('hostFilter', token.value); break;
      case 'user':         s.setFilter('userFilter', token.value); break;
      case 'after':        s.setFilter('startTime', token.value); break;
      case 'before':       s.setFilter('endTime', token.value); break;
      case 'sev':          s.setFilter('detSeverity', token.value); break;
      case 'tag':          s.setFilter('tagFilter', token.value); break;
      case 'tool':         s.setFilter('toolFilter', token.value); break;
      case 'eventId':      s.setFilter('eventIdFilter', token.value); break;
      case 'ext':          s.setFilter('extFilter', token.value); break;
      default: break;
    }
    s.applyFilters();
  }, []);

  const handleKeyDown = useCallback(e => {
    if (e.key === 'Enter') {
      const token = parseToken(inputVal);
      if (token.value) { applyToken(token); setInputVal(''); }
      else applyFilters();
    } else if (e.key === 'Escape') {
      setInputVal(''); inputRef.current?.blur();
    }
  }, [inputVal, applyToken, applyFilters]);

  const chips = [
    ...(search ? [{ kind: 'search', label: search, remove: () => { setFilter('search', ''); applyFilters(); } }] : []),
    // artifactTypes are shown via the pills row below — no chips here to avoid overflow
    ...(hostFilter  ? [{ kind: 'host',    label: `host:${hostFilter}`,  remove: () => { setFilter('hostFilter', '');  applyFilters(); } }] : []),
    ...(userFilter  ? [{ kind: 'user',    label: `user:${userFilter}`,  remove: () => { setFilter('userFilter', '');  applyFilters(); } }] : []),
    ...(startTime   ? [{ kind: 'after',   label: `after:${startTime.slice(0, 10)}`,  remove: () => { setFilter('startTime', '');  applyFilters(); } }] : []),
    ...(endTime     ? [{ kind: 'before',  label: `before:${endTime.slice(0, 10)}`,   remove: () => { setFilter('endTime', '');    applyFilters(); } }] : []),
    ...(detSeverity ? [{ kind: 'sev',     label: `sev:${detSeverity}`,  remove: () => { setFilter('detSeverity', ''); applyFilters(); } }] : []),
    ...(tagFilter   ? [{ kind: 'tag',     label: `tag:${tagFilter}`,    remove: () => { setFilter('tagFilter', '');   applyFilters(); } }] : []),
    ...(toolFilter  ? [{ kind: 'tool',    label: `tool:${toolFilter}`,  remove: () => { setFilter('toolFilter', '');  applyFilters(); } }] : []),
    ...(eventIdFilter ? [{ kind: 'eventId', label: `eid:${eventIdFilter}`, remove: () => { setFilter('eventIdFilter', ''); applyFilters(); } }] : []),
    ...(extFilter   ? [{ kind: 'ext',     label: `ext:${extFilter}`,    remove: () => { setFilter('extFilter', '');   applyFilters(); } }] : []),
  ];
  const hasFilters = chips.length > 0 || hitsOnly || dedupe || artifactTypes.length > 0;

  return (
    <div style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-raised)', padding: '7px 14px', flexShrink: 0 }}>
      {/* Input row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--fl-panel)',
        border: '1px solid var(--fl-subtle)', borderRadius: 6, padding: '0 10px', height: 34 }}>
        <Search size={13} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, flex: 1, flexWrap: 'nowrap', overflow: 'hidden' }}>
          {chips.map((c, i) => <Chip key={i} kind={c.kind} label={c.label} onRemove={c.remove} />)}
          <input ref={inputRef} value={inputVal}
            onChange={e => setInputVal(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={chips.length === 0 ? 'Search… or type:evtx · host:DC01 · sev:critical · after:2024-01-15' : ''}
            style={{ flex: 1, background: 'none', border: 'none', outline: 'none',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-dim)', minWidth: 100 }} />
        </div>
        {hasFilters && (
          <button onClick={clearFilters} title="Clear all filters"
            style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', padding: '2px 4px', borderRadius: 3 }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
            <X size={12} />
          </button>
        )}
        <div style={{ width: 1, height: 18, background: 'var(--fl-raised)', flexShrink: 0 }} />
        <div ref={advancedRef} style={{ position: 'relative' }}>
          <button onClick={() => setShowAdvanced(v => !v)} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: showAdvanced ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${showAdvanced ? 'color-mix(in srgb, var(--fl-accent) 38%, transparent)' : 'var(--fl-raised)'}`,
            color: showAdvanced ? 'var(--fl-accent)' : 'var(--fl-muted)', cursor: 'pointer',
          }}>
            Filters <ChevronDown size={9} style={{ verticalAlign: 'middle' }} />
          </button>
          {showAdvanced && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 14, width: 320, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                { label: 'Tool',      field: 'toolFilter',     hint: 'EvtxECmd,Hayabusa…',      val: toolFilter },
                { label: 'Event ID',  field: 'eventIdFilter',  hint: '4624,4625,4688',           val: eventIdFilter },
                { label: 'Extension', field: 'extFilter',      hint: 'exe,dll,ps1',              val: extFilter },
                { label: 'Tag',       field: 'tagFilter',      hint: 'mimikatz_markers,T1059…',  val: tagFilter },
              ].map(f => (
                <label key={f.field} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                  <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{f.label}</span>
                  <input
                    value={f.val}
                    placeholder={f.hint}
                    onChange={e => setFilter(f.field, e.target.value)}
                    style={{ background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: '1px solid var(--fl-raised)', borderRadius: 5, padding: '5px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, outline: 'none' }} />
                </label>
              ))}
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderRadius: 5, border: '1px solid #1a3020', background: '#0a1810', cursor: 'pointer' }}>
                <input type="checkbox" checked={hitsOnly} onChange={e => setFilter('hitsOnly', e.target.checked)} style={{ accentColor: 'var(--fl-warn)' }} />
                <span style={{ color: 'var(--fl-warn)' }}>🎯 Detections only (hits)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderRadius: 5, border: '1px solid var(--fl-raised)', background: 'var(--fl-panel)', cursor: 'pointer' }}>
                <input type="checkbox" checked={dedupe} onChange={e => setFilter('dedupe', e.target.checked)} />
                <span>Deduplicate (collapse)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', minWidth: 80 }}>Min severity</span>
                <select value={detSeverity} onChange={e => setFilter('detSeverity', e.target.value)}
                  style={{ flex: 1, background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: '1px solid var(--fl-raised)', borderRadius: 5, padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, outline: 'none' }}>
                  <option value="">All severities</option>
                  <option value="greyware">Greyware+</option>
                  <option value="medium">Medium+</option>
                  <option value="high">High+</option>
                  <option value="critical">Critical only</option>
                </select>
              </label>
              <div style={{ display: 'flex', gap: 6, paddingTop: 4, borderTop: '1px solid var(--fl-card)' }}>
                <button onClick={() => { setShowAdvanced(false); applyFilters(); }} style={{ flex: 1, padding: '5px', borderRadius: 5, background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', color: 'var(--fl-accent)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Apply</button>
                <button onClick={() => { clearFilters(); setShowAdvanced(false); }} style={{ padding: '5px 10px', borderRadius: 5, background: 'transparent', border: '1px solid var(--fl-raised)', color: 'var(--fl-dim)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Reset</button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Artifact type pills */}
      {availTypes.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 5, alignItems: 'center' }}>
          <button onClick={() => { useTimelineStore.getState().setFilter('artifactTypes', []); useTimelineStore.getState().applyFilters(); }}
            style={{ padding: '2px 8px', borderRadius: 10, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
              background: artifactTypes.length === 0 ? 'color-mix(in srgb, var(--fl-accent) 9%, transparent)' : 'transparent',
              color: artifactTypes.length === 0 ? 'var(--fl-accent)' : 'var(--fl-dim)',
              border: `1px solid ${artifactTypes.length === 0 ? 'color-mix(in srgb, var(--fl-accent) 21%, transparent)' : 'var(--fl-border)'}` }}>All</button>
          {artifactTypes[0] !== '__NONE__' && (
            <button
              onClick={() => useTimelineStore.getState().clearArtifactTypes()}
              title="Deselect all artifacts"
              style={{ padding: '2px 6px', borderRadius: 10, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                background: 'transparent', color: 'var(--fl-muted)',
                border: '1px solid var(--fl-border)', display: 'flex', alignItems: 'center', gap: 3 }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-danger) 25%, transparent)'; }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
              <X size={8} /> clear
            </button>
          )}
          {availTypes.map(t => {
            const col    = tabColor(t);
            const active = artifactTypes.length === 0 || artifactTypes.includes(t);
            const solo   = artifactTypes.length === 1 && artifactTypes[0] === t;
            const count  = typeCounts[t];
            return (
              <button key={t} onClick={e => e.ctrlKey || e.metaKey ? soloArtifactType(t) : toggleArtifactType(t)} title="Click to toggle · Ctrl+click to isolate (shows schema columns)" style={{
                padding: '3px 9px', borderRadius: 6, fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 5,
                background: solo ? `color-mix(in srgb, ${col} 10%, transparent)` : active ? 'var(--fl-card)' : 'transparent',
                color:      active ? 'var(--fl-dim)' : 'var(--fl-subtle)',
                border:     `1px solid ${solo ? `color-mix(in srgb, ${col} 35%, transparent)` : active ? 'var(--fl-border)' : 'transparent'}`,
                textDecoration: active ? 'none' : 'line-through',
                transition: 'all 0.1s',
              }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, flexShrink: 0,
                  background: active ? col : `color-mix(in srgb, ${col} 30%, transparent)`, display: 'inline-block' }} />
                {t} {count != null && <span style={{ fontSize: 8, color: 'var(--fl-muted)' }}>({count.toLocaleString('fr-FR')})</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
