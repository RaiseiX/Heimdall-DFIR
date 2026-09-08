import { useRef, useState, useEffect, useCallback } from 'react';
import { Search, X, Save, Share2, Trash2, Pencil, Crosshair } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { useTranslation } from 'react-i18next';
import { controlStyle, controlHover, fieldStyle } from '../../ui/controlIdiom';
import { tabColor } from '../utils/timelineUtils';
import { groupArtifactTypes, stripTypes, sumRows } from '../utils/artifactGroups';
import { currentUser } from '../../../utils/auth';

const FS_TINY = 9;
const FS_XS = 10;
const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const FAM_ROW_STYLE = { display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 6, alignItems: 'baseline' };
const FAM_LABEL_STYLE = { fontSize: FS_TINY, fontFamily: MONO, textTransform: 'uppercase',
  letterSpacing: '.12em', color: 'var(--fl-subtle)', paddingRight: 12,
  borderRight: '1px solid var(--fl-border2)' };
const FAM_COUNT_STYLE = { fontSize: FS_TINY, color: 'var(--fl-muted)' };
const SEARCH_WRAP_STYLE = { display: 'flex', alignItems: 'baseline', gap: 6, marginLeft: 'auto',
  paddingLeft: 12, borderLeft: '1px solid var(--fl-border2)' };
const SEARCH_INPUT_STYLE = { background: 'none', border: 'none', outline: 'none', fontFamily: MONO,
  fontSize: FS_XS, color: 'var(--fl-text)', width: 130 };
const SEARCH_ICON_STYLE = { color: 'var(--fl-muted)', alignSelf: 'center' };
const TALLY_STYLE = { fontSize: FS_TINY, fontFamily: MONO, color: 'var(--fl-muted)', marginTop: 8 };
const TALLY_KEY_STYLE = { color: 'var(--fl-text)' };
const TALLY_PIN_STYLE = { color: 'var(--fl-warn)' };
const TYPE_COUNT_STYLE = { fontSize: FS_TINY, color: 'var(--fl-muted)' };

const famBtnStyle = (active, col) => ({
  padding: '2px 0', fontSize: FS_XS, fontFamily: MONO, cursor: 'pointer',
  display: 'flex', alignItems: 'baseline', gap: 5,
  background: 'transparent', border: 'none',
  borderBottom: `1px solid ${active ? col : 'transparent'}`,
  color: active ? 'var(--fl-text)' : col,
});

const typeBtnStyle = (active, solo, col) => ({
  padding: '2px 0', fontSize: FS_XS, fontFamily: MONO, cursor: 'pointer',
  display: 'flex', alignItems: 'baseline', gap: 5,
  background: 'transparent', border: 'none',
  borderBottom: `1px solid ${solo ? col : 'transparent'}`,
  color: active ? col : 'var(--fl-subtle)',
  opacity: active ? 1 : 0.55,
  textDecoration: active ? 'none' : 'line-through',
});

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
    savedSearches, applySavedSearch, saveCurrentSearch,
    promoteSavedSearch, deleteSavedSearch, updateSavedSearch,
  } = store;

  const inputRef = useRef(null);
  const [inputVal, setInputVal] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showAllTypes, setShowAllTypes] = useState(false);
  const [typeFamily, setTypeFamily] = useState(null);
  const [typeSearch, setTypeSearch] = useState('');
  const { t: tr, i18n } = useTranslation();
  const advancedRef = useRef(null);
  const [showSearches, setShowSearches] = useState(false);
  const searchesRef = useRef(null);
  const [saveName, setSaveName] = useState('');
  const [saveShared, setSaveShared] = useState(false);
  const me = currentUser().id;

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

  useEffect(() => {
    const h = e => { if (searchesRef.current && !searchesRef.current.contains(e.target)) setShowSearches(false); };
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

  const isMine = s => s.scope === 'personal' || s.author_id === me;
  const mine   = savedSearches.filter(isMine);
  const shared = savedSearches.filter(s => !isMine(s));

  const handleSave = async () => {
    const name = saveName.trim();
    if (!name) return;
    try {
      await saveCurrentSearch(name, saveShared ? 'case' : 'personal');
      setSaveName(''); setSaveShared(false);
    } catch (e) {
      alert(e?.response?.data?.error || 'Échec de la sauvegarde');
    }
  };

  return (
    <div style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-raised)', padding: '7px 14px', flexShrink: 0 }}>
      <div style={fieldStyle()}>
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
        <div ref={searchesRef} style={{ position: 'relative' }}>
          <button onClick={() => setShowSearches(v => !v)} aria-pressed={showSearches}
            style={controlStyle(showSearches)} {...controlHover(showSearches)}>
            Recherches
          </button>
          {showSearches && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 12, width: 320, maxHeight: 420, overflowY: 'auto', boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 10 }}>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em',
                  display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Save size={11} strokeWidth={1.6} />{tr('timeline.save_current_search')}
                </span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input value={saveName} placeholder="Nom de la recherche…"
                    onChange={e => setSaveName(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') handleSave(); }}
                    style={{ flex: 1, background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: '1px solid var(--fl-raised)', borderRadius: 5, padding: '5px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, outline: 'none' }} />
                  <button onClick={handleSave} disabled={!saveName.trim()}
                    style={{ padding: '5px 8px', borderRadius: 5, background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-purple) 30%, transparent)', color: 'var(--fl-purple)', cursor: saveName.trim() ? 'pointer' : 'not-allowed', opacity: saveName.trim() ? 1 : 0.5, display: 'flex', alignItems: 'center' }}>
                    <Save size={12} />
                  </button>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: 'var(--fl-dim)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={saveShared} onChange={e => setSaveShared(e.target.checked)} />
                  Partager avec toute l'équipe du cas
                </label>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, borderTop: '1px solid var(--fl-card)', paddingTop: 8 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Mes recherches</span>
                {mine.length === 0 && <span style={{ fontSize: 10, color: 'var(--fl-muted)' }}>{tr('timeline.no_saved_search')}</span>}
                {mine.map(s => (
                  <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <button onClick={() => { applySavedSearch(s.query); setShowSearches(false); }}
                      title="Appliquer cette recherche"
                      style={{ flex: 1, textAlign: 'left', background: 'transparent', border: 'none', color: 'var(--fl-on-dark)', cursor: 'pointer', padding: '4px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'flex', alignItems: 'center', gap: 6 }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
                      {s.name}
                      {s.scope === 'case' && <span style={{ fontSize: 8, color: 'var(--fl-purple)' }}>partagée</span>}
                    </button>
                    {s.scope !== 'case' && (
                      <button onClick={() => promoteSavedSearch(s.id)} title="Partager avec le cas"
                        style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', padding: 2 }}>
                        <Share2 size={12} />
                      </button>
                    )}
                    <button onClick={() => { const n = prompt('Nouveau nom', s.name); if (n && n.trim()) updateSavedSearch(s.id, { name: n.trim() }).catch(err => alert(err?.response?.data?.error || 'Échec du renommage')); }} title="Renommer"
                      style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', padding: 2 }}>
                      <Pencil size={12} />
                    </button>
                    <button onClick={() => { if (confirm(`Supprimer « ${s.name} » ?`)) deleteSavedSearch(s.id).catch(err => alert(err?.response?.data?.error || 'Échec de la suppression')); }} title="Supprimer"
                      style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', padding: 2 }}
                      onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                ))}
              </div>

              {shared.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, borderTop: '1px solid var(--fl-card)', paddingTop: 8 }}>
                  <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Partagées au cas</span>
                  {shared.map(s => (
                    <button key={s.id} onClick={() => { applySavedSearch(s.query); setShowSearches(false); }}
                      title={`Par ${s.author_name || s.username || 'un membre'}`}
                      style={{ textAlign: 'left', background: 'transparent', border: 'none', color: 'var(--fl-on-dark)', cursor: 'pointer', padding: '4px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'flex', alignItems: 'center', gap: 6 }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
                      {s.name}
                      <span style={{ fontSize: 8, color: 'var(--fl-muted)' }}>· {s.author_name || s.username || '—'}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <div style={{ width: 1, height: 18, background: 'var(--fl-raised)', flexShrink: 0 }} />
        <div ref={advancedRef} style={{ position: 'relative' }}>
          <button onClick={() => setShowAdvanced(v => !v)} aria-pressed={showAdvanced}
            style={controlStyle(showAdvanced)} {...controlHover(showAdvanced)}>
            Filters
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
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderRadius: 5, border: '1px solid var(--fl-raised)', background: 'var(--fl-panel)', cursor: 'pointer' }}>
                <input type="checkbox" checked={hitsOnly} onChange={e => setFilter('hitsOnly', e.target.checked)} style={{ accentColor: 'var(--fl-warn)' }} />
                <span style={{ color: hitsOnly ? 'var(--fl-warn)' : 'var(--fl-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Crosshair size={12} strokeWidth={1.6} />Detections only (hits)
                </span>
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

      {availTypes.length > 0 && (
        <div style={FAM_ROW_STYLE}>
          <span style={FAM_LABEL_STYLE}>{tr('timeline.types.families')}</span>
          {groupArtifactTypes(availTypes, typeCounts).map(g => (
            <button key={g.family}
              onClick={() => setTypeFamily(f => (f === g.family ? null : g.family))}
              style={famBtnStyle(typeFamily === g.family, tabColor(g.types[0].type))}>
              {g.label}
              <span style={FAM_COUNT_STYLE}>{g.typeCount}</span>
            </button>
          ))}
          <span style={SEARCH_WRAP_STYLE}>
            <Search size={10} style={SEARCH_ICON_STYLE} />
            <input
              value={typeSearch}
              onChange={e => setTypeSearch(e.target.value)}
              placeholder={tr('timeline.types.filter_placeholder')}
              aria-label={tr('timeline.types.filter_placeholder')}
              style={SEARCH_INPUT_STYLE}
            />
          </span>
        </div>
      )}

      {availTypes.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 6, alignItems: 'baseline' }}>
          <span style={{ display: 'flex', alignItems: 'baseline', gap: 9, paddingRight: 12,
            borderRight: '1px solid var(--fl-border2)' }}>
            <button onClick={() => { useTimelineStore.getState().setFilter('artifactTypes', []); useTimelineStore.getState().applyFilters(); }}
              style={{ padding: 0, background: 'transparent', border: 'none', cursor: 'pointer',
                fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                color: artifactTypes.length === 0 ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>
              {tr('timeline.type_all')}
            </button>
            {artifactTypes[0] !== '__NONE__' && (
              <button
                onClick={() => useTimelineStore.getState().clearArtifactTypes()}
                title={tr('timeline.type_clear_hint')}
                style={{ padding: 0, background: 'transparent', border: 'none', cursor: 'pointer',
                  fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
                {tr('timeline.type_clear')}
              </button>
            )}
          </span>
          {(() => {
            const strip = stripTypes({ availTypes, typeCounts, family: typeFamily,
              search: typeSearch, selected: artifactTypes, visible: 12 });
            const visible = showAllTypes ? [...strip.shown, ...strip.hidden] : strip.shown;
            return (<>
          {visible.map(t => {
            const col    = tabColor(t);
            const active = artifactTypes.length === 0 || artifactTypes.includes(t);
            const solo   = artifactTypes.length === 1 && artifactTypes[0] === t;
            const count  = typeCounts[t];
            return (
              <button key={t} onClick={e => e.ctrlKey || e.metaKey ? soloArtifactType(t) : toggleArtifactType(t)}
                title={tr('timeline.type_toggle_hint')}
                style={typeBtnStyle(active, solo, col)}>
                {t}
                {count != null && <span style={TYPE_COUNT_STYLE}>{count.toLocaleString(i18n.language)}</span>}
              </button>
            );
          })}
          {strip.hidden.length > 0 && (
            <button onClick={() => setShowAllTypes(v => !v)}
              title={showAllTypes ? undefined : strip.hidden.slice(0, 12).join(', ')}
              style={{ padding: '2px 0', fontSize: 10, cursor: 'pointer',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'transparent',
                color: 'var(--fl-muted)', border: 'none', textDecoration: 'underline',
                textUnderlineOffset: 3 }}>
              {showAllTypes ? tr('timeline.types.collapse') : tr('timeline.types.more', { count: strip.hidden.length })}
            </button>
          )}
            </>);
          })()}
        </div>
      )}

      {availTypes.length > 0 && (() => {
        const strip = stripTypes({ availTypes, typeCounts, family: typeFamily,
          search: typeSearch, selected: artifactTypes, visible: 12 });
        if (!strip.filtering && !strip.restricting) return null;
        const rows = sumRows(strip.shown, typeCounts);
        return (
          <p style={TALLY_STYLE}>
            {strip.filtering && (
              <span style={TALLY_KEY_STYLE}>
                {tr('timeline.types.tally', { shown: strip.matched, total: strip.total })}
              </span>
            )}
            {strip.filtering && rows != null && ` · ${tr('timeline.types.rows', { n: rows.toLocaleString(i18n.language) })}`}
            {strip.restricting && (
              <span style={TALLY_PIN_STYLE}>
                {`${strip.filtering ? ' · ' : ''}${tr('timeline.types.restricted', { included: strip.included, total: strip.total })}`}
              </span>
            )}
          </p>
        );
      })()}
    </div>
  );
}
