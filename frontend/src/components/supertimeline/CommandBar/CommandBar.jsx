// frontend/src/components/supertimeline/CommandBar/CommandBar.jsx
import { useRef, useState, useEffect, useCallback } from 'react';
import { Search, X, ChevronDown, Save, Share2, Trash2, Pencil, Clock, Star, Tag } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { collectionAPI } from '../../../utils/api';
import { tabColor, parseFlexibleTimestamp } from '../utils/timelineUtils';
import { currentUser } from '../../../utils/auth';

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
    caseId,
    hitsOnly, dedupe, availTypes, typeCounts,
    setFilter, applyFilters, clearFilters, toggleArtifactType, soloArtifactType,
    savedSearches, applySavedSearch, saveCurrentSearch,
    promoteSavedSearch, deleteSavedSearch, updateSavedSearch,
    bookmarks, jumpToBookmark, removeBookmark,
  } = store;

  const inputRef = useRef(null);
  const [inputVal, setInputVal] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const advancedRef = useRef(null);
  const [showSearches, setShowSearches] = useState(false);
  const searchesRef = useRef(null);
  const [showTags, setShowTags] = useState(false);
  const tagsRef = useRef(null);
  const [tagCounts, setTagCounts] = useState([]);
  const [showBookmarks, setShowBookmarks] = useState(false);
  const bookmarksRef = useRef(null);
  const [showJump, setShowJump] = useState(false);
  const jumpRef = useRef(null);
  const jumpInputRef = useRef(null);
  const [jumpVal, setJumpVal] = useState('');
  const [jumpWindow, setJumpWindow] = useState(15);
  const [jumpError, setJumpError] = useState('');
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

  useEffect(() => {
    const h = e => { if (tagsRef.current && !tagsRef.current.contains(e.target)) setShowTags(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  useEffect(() => {
    const h = e => { if (bookmarksRef.current && !bookmarksRef.current.contains(e.target)) setShowBookmarks(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  useEffect(() => {
    const h = e => { if (jumpRef.current && !jumpRef.current.contains(e.target)) { setShowJump(false); setJumpError(''); } };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  useEffect(() => {
    if (showJump) jumpInputRef.current?.focus();
  }, [showJump]);

  const applyToken = useCallback(token => {
    const s = useTimelineStore.getState();
    switch (token.kind) {
      case 'search':       s.setFilter('search', token.value); break;
      case 'artifactType': s.toggleArtifactType(token.value); return;
      case 'host':         s.setFilter('hostFilter', token.value); break;
      case 'user':         s.setFilter('userFilter', token.value); break;
      case 'after': {
        const d = parseFlexibleTimestamp(token.value);
        s.setFilter('startTime', d ? d.toISOString() : token.value);
        break;
      }
      case 'before': {
        const d = parseFlexibleTimestamp(token.value);
        s.setFilter('endTime', d ? d.toISOString() : token.value);
        break;
      }
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

  const doJump = useCallback(() => {
    const d = parseFlexibleTimestamp(jumpVal);
    if (!d) { setJumpError('Format de date invalide'); return; }
    if (useTimelineStore.getState().jumpToTime(d.toISOString(), jumpWindow)) {
      setShowJump(false); setJumpVal(''); setJumpError('');
    }
  }, [jumpVal, jumpWindow]);

  // Keep milliseconds so after:/before: chips show the exact bookmark time.
  const fmtTs = iso => (iso ? iso.replace('T', ' ').replace('Z', '').slice(0, 23) : '');

  // ── Tag filter (tags text[] overlap) ──────────────────────────────────────
  // tagFilter holds a comma-joined list (OR semantics — the backend matches
  // `tags && ARRAY[...]`). The dropdown lists the case's tag distribution and
  // toggles tags in/out; the chips render one per active tag so each can be
  // removed individually. The free-text search also matches tags (backend
  // SEARCH_COLS includes tags::text), so typing a tag name works too.
  const activeTags = (tagFilter || '').split(',').map(t => t.trim()).filter(Boolean);
  const loadTags = () => {
    if (!caseId) return;
    collectionAPI.tagger(caseId, {}).then(r => setTagCounts(r.data?.tag_counts || [])).catch(() => {});
  };
  const toggleTag = (tag) => {
    const cur = activeTags.includes(tag) ? activeTags.filter(t => t !== tag) : [...activeTags, tag];
    setFilter('tagFilter', cur.join(','));
    applyFilters();
  };
  const removeTag = (tag) => {
    setFilter('tagFilter', activeTags.filter(t => t !== tag).join(','));
    applyFilters();
  };

  const chips = [
    ...(search ? [{ kind: 'search', label: search, remove: () => { setFilter('search', ''); applyFilters(); } }] : []),
    // artifactTypes are shown via the pills row below — no chips here to avoid overflow
    ...(hostFilter  ? [{ kind: 'host',    label: `host:${hostFilter}`,  remove: () => { setFilter('hostFilter', '');  applyFilters(); } }] : []),
    ...(userFilter  ? [{ kind: 'user',    label: `user:${userFilter}`,  remove: () => { setFilter('userFilter', '');  applyFilters(); } }] : []),
    ...(startTime   ? [{ kind: 'after',   label: `after:${fmtTs(startTime)}`,  remove: () => { setFilter('startTime', '');  applyFilters(); } }] : []),
    ...(endTime     ? [{ kind: 'before',  label: `before:${fmtTs(endTime)}`,   remove: () => { setFilter('endTime', '');    applyFilters(); } }] : []),
    ...(detSeverity ? [{ kind: 'sev',     label: `sev:${detSeverity}`,  remove: () => { setFilter('detSeverity', ''); applyFilters(); } }] : []),
    ...(activeTags.map(tag => ({ kind: 'tag', label: `tag:${tag}`, remove: () => removeTag(tag) }))),
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
      // 409 duplicate name is the common case — surface minimally, keep the field open.
      alert(e?.response?.data?.error || 'Échec de la sauvegarde');
    }
  };

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
            placeholder={chips.length === 0 ? 'Search… or type:evtx · host:DC01 · sev:critical · tag:LateralMovement · after:2024-01-15' : ''}
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
          <button onClick={() => setShowSearches(v => !v)} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: showSearches ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${showSearches ? 'color-mix(in srgb, var(--fl-purple) 38%, transparent)' : 'var(--fl-raised)'}`,
            color: showSearches ? 'var(--fl-purple)' : 'var(--fl-muted)', cursor: 'pointer',
          }}>
            Recherches <ChevronDown size={9} style={{ verticalAlign: 'middle' }} />
          </button>
          {showSearches && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 12, width: 320, maxHeight: 420, overflowY: 'auto', boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 10 }}>

              {/* Save current search */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  💾 Sauvegarder la recherche actuelle
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

              {/* Mes recherches */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, borderTop: '1px solid var(--fl-card)', paddingTop: 8 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Mes recherches</span>
                {mine.length === 0 && <span style={{ fontSize: 10, color: 'var(--fl-muted)' }}>Aucune</span>}
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

              {/* Partagées au cas (des autres) */}
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
        <div ref={tagsRef} style={{ position: 'relative' }}>
          <button onClick={() => { const next = !showTags; setShowTags(next); if (next) loadTags(); }} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: showTags ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${showTags ? 'color-mix(in srgb, var(--fl-purple) 38%, transparent)' : 'var(--fl-raised)'}`,
            color: showTags ? 'var(--fl-purple)' : 'var(--fl-muted)', cursor: 'pointer',
            display: 'inline-flex', alignItems: 'center', gap: 4,
          }}>
            <Tag size={9} style={{ verticalAlign: 'middle' }} />
            {activeTags.length > 0 ? `Tags (${activeTags.length})` : 'Tags'}
            <ChevronDown size={9} style={{ verticalAlign: 'middle' }} />
          </button>
          {showTags && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 8, width: 300, maxHeight: 380, overflowY: 'auto', boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', padding: '4px 6px 6px' }}>
                Filtrer par tag — cliquer pour (dés)activer
              </span>
              {tagCounts.length === 0 && <span style={{ fontSize: 10, color: 'var(--fl-muted)', padding: '4px 6px' }}>Aucun tag sur cette timeline</span>}
              {tagCounts.map(({ tag, cnt }) => {
                const on = activeTags.includes(tag);
                return (
                  <button key={tag} onClick={() => toggleTag(tag)} title={`${cnt} événement(s)`}
                    style={{ display: 'flex', alignItems: 'center', gap: 8, textAlign: 'left', background: 'transparent', border: 'none',
                      color: 'var(--fl-on-dark)', cursor: 'pointer', padding: '5px 6px', borderRadius: 5, fontSize: 11,
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
                    <span style={{ width: 12, display: 'inline-flex', justifyContent: 'center', color: on ? 'var(--fl-purple)' : 'var(--fl-muted)' }}>
                      {on ? '✓' : ''}
                    </span>
                    <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: on ? 'var(--fl-purple)' : 'var(--fl-on-dark)' }}>{tag}</span>
                    <span style={{ fontSize: 9.5, color: 'var(--fl-dim)' }}>{cnt}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        <div ref={bookmarksRef} style={{ position: 'relative' }}>
          <button onClick={() => { const next = !showBookmarks; setShowBookmarks(next); if (next) useTimelineStore.getState().loadBookmarks(); }} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: showBookmarks ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${showBookmarks ? 'color-mix(in srgb, var(--fl-gold) 38%, transparent)' : 'var(--fl-raised)'}`,
            color: showBookmarks ? 'var(--fl-gold)' : 'var(--fl-muted)', cursor: 'pointer',
            display: 'inline-flex', alignItems: 'center', gap: 4,
          }}>
            <Star size={9} style={{ verticalAlign: 'middle' }} />
            {bookmarks.length > 0 ? `Bookmarks (${bookmarks.length})` : 'Bookmarks'}
            <ChevronDown size={9} style={{ verticalAlign: 'middle' }} />
          </button>
          {showBookmarks && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 10, width: 340, maxHeight: 420, overflowY: 'auto', boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', padding: '0 4px 4px' }}>
                ★ Bookmarks · {bookmarks.length}
              </span>
              {bookmarks.length === 0 ? (
                <span style={{ fontSize: 10, color: 'var(--fl-muted)', padding: '4px 6px' }}>
                  Aucun bookmark. Cliquez sur ☆ d'un événement pour le marquer.
                </span>
              ) : [...bookmarks]
                .sort((a, b) => new Date(b.event_timestamp || b.timestamp) - new Date(a.event_timestamp || a.timestamp))
                .map(b => {
                  const rawTs = b.event_timestamp || b.timestamp;
                  const tsTxt = rawTs ? new Date(rawTs).toISOString().replace('T', ' ').slice(0, 23) : '';
                  return (
                    <div key={b.id}
                      onClick={() => { jumpToBookmark(b); setShowBookmarks(false); }}
                      title="Aller à cet événement (after: à son timestamp, +15 min)"
                      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 7px', borderRadius: 5, cursor: 'pointer' }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                    >
                      <span style={{ color: 'var(--fl-gold)', fontSize: 11, flexShrink: 0 }}>★</span>
                      <span style={{ flex: 1, minWidth: 0 }}>
                        <span style={{ display: 'block', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10.5 }}>
                          {b.title || b.label || b.ref || '—'}
                        </span>
                        {tsTxt && <span style={{ display: 'block', fontSize: 8.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{tsTxt}</span>}
                      </span>
                      <button
                        onClick={e => { e.stopPropagation(); removeBookmark(b); }}
                        title="Retirer le bookmark"
                        style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', padding: 2, display: 'inline-flex', flexShrink: 0 }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                      >
                        <X size={10} />
                      </button>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
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
        <div ref={jumpRef} style={{ position: 'relative' }}>
          <button onClick={() => { setShowJump(v => !v); setJumpError(''); }} title="Aller à un timestamp précis pour voir les événements autour" style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: showJump ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${showJump ? 'color-mix(in srgb, var(--fl-gold) 38%, transparent)' : 'var(--fl-raised)'}`,
            color: showJump ? 'var(--fl-gold)' : 'var(--fl-muted)', cursor: 'pointer',
            display: 'inline-flex', alignItems: 'center', gap: 4,
          }}>
            <Clock size={11} style={{ verticalAlign: 'middle' }} /> Aller à…
          </button>
          {showJump && (
            <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
              padding: 14, width: 300, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-on-dark)',
              display: 'flex', flexDirection: 'column', gap: 10 }}>
              <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                ⏱ Aller à un timestamp
              </span>
              <input ref={jumpInputRef} value={jumpVal}
                placeholder="2024-01-15 14:32:05"
                onChange={e => { setJumpVal(e.target.value); setJumpError(''); }}
                onKeyDown={e => { if (e.key === 'Enter') doJump(); else if (e.key === 'Escape') setShowJump(false); }}
                style={{ background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: `1px solid ${jumpError ? 'var(--fl-danger)' : 'var(--fl-raised)'}`, borderRadius: 5, padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, outline: 'none' }} />
              <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Fenêtre autour</span>
                <select value={jumpWindow} onChange={e => setJumpWindow(parseInt(e.target.value, 10))}
                  style={{ background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: '1px solid var(--fl-raised)', borderRadius: 5, padding: '5px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, outline: 'none' }}>
                  <option value={1}>± 1 min</option>
                  <option value={5}>± 5 min</option>
                  <option value={15}>± 15 min</option>
                  <option value={60}>± 1 h</option>
                  <option value={360}>± 6 h</option>
                  <option value={1440}>± 24 h</option>
                </select>
              </label>
              {jumpError && <span style={{ fontSize: 10, color: 'var(--fl-danger)' }}>{jumpError}</span>}
              <div style={{ display: 'flex', gap: 6, paddingTop: 2, borderTop: '1px solid var(--fl-card)' }}>
                <button onClick={doJump} disabled={!jumpVal.trim()}
                  style={{ flex: 1, padding: '5px', borderRadius: 5, background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-gold) 25%, transparent)', color: 'var(--fl-gold)', cursor: jumpVal.trim() ? 'pointer' : 'not-allowed', opacity: jumpVal.trim() ? 1 : 0.5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Aller</button>
                <button onClick={() => { setShowJump(false); setJumpError(''); }}
                  style={{ padding: '5px 10px', borderRadius: 5, background: 'transparent', border: '1px solid var(--fl-raised)', color: 'var(--fl-dim)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Fermer</button>
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
