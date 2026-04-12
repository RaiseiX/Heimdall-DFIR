
import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Clock, Search, ChevronLeft, ChevronRight, Download, Loader2,
  Star, Eye, SortAsc, SortDesc, X, Filter, Tag, MessageSquare, Send, Trash2, Pencil,
} from 'lucide-react';
import { collectionAPI, artifactsAPI } from '../../utils/api';
import { useTheme } from '../../utils/theme';
import TimelineHistogram from './TimelineHistogram';

const ARTIFACT_COLORS = {
  evtx:      '#4d82c0', prefetch:  '#22c55e', mft:       '#8b72d6',
  lnk:       '#d97c20', registry:  '#c96898', amcache:   '#c89d1d',
  appcompat: '#f59e0b', shellbags: '#06b6d4', jumplist:  '#8b5cf6',
  srum:      '#f43f5e', recycle:   '#84cc16', wxtcmd:    '#d946ef',
  bits:      '#64748b', sum:       '#0ea5e9',
};
function artifactColor(t) { return ARTIFACT_COLORS[t] || '#7d8590'; }

const CONFIDENCE_LEVELS = [
  { key: 'critical', label: 'Malveillant', color: '#ef4444', bg: '#ef444418', dot: '●' },
  { key: 'high',     label: 'Suspect',     color: '#d97c20', bg: '#d97c2012', dot: '●' },
  { key: 'medium',   label: 'À analyser',  color: '#c89d1d', bg: '#c89d1d10', dot: '●' },
  { key: 'low',      label: 'Bénin',       color: '#22c55e', bg: '#22c55e08', dot: '●' },
];
const CONFIDENCE_MAP = Object.fromEntries(CONFIDENCE_LEVELS.map(l => [l.key, l]));

const FORENSIC_TAGS = [
  { key: 'exec',       label: 'Exécution',            color: '#d97c20' },
  { key: 'persist',    label: 'Persistance',           color: '#c96898' },
  { key: 'lateral',    label: 'Latéralisation',        color: '#8b72d6' },
  { key: 'exfil',      label: 'Exfiltration',          color: '#f43f5e' },
  { key: 'privesc',    label: 'Élév. privilèges',      color: '#c89d1d' },
  { key: 'credential', label: 'Accès credentials',     color: '#06b6d4' },
  { key: 'network',    label: 'Activité réseau',       color: '#4d82c0' },
  { key: 'file',       label: 'Accès fichier',         color: '#22c55e' },
  { key: 'logon',      label: 'Connexion utilisateur', color: '#8b5cf6' },
  { key: 'defense',    label: 'Contournement défense', color: '#64748b' },
  { key: 'registry',   label: 'Registre',              color: '#d946ef' },
  { key: 'ioc',        label: 'IOC confirmé',          color: '#00ff88' },
  { key: 'recon',      label: 'Reconnaissance',        color: '#7dd3fc' },
  { key: 'ransom',     label: 'Ransomware',            color: '#ff6b6b' },
];
const FORENSIC_TAG_MAP = Object.fromEntries(FORENSIC_TAGS.map(t => [t.key, t]));

const COLUMNS = [
  { key: 'timestamp',     label: 'Horodatage (UTC)',  width: 174, mono: true },
  { key: 'artifact_type', label: 'Type',              width: 88              },
  { key: 'source_short',  label: 'Source',            width: 120, mono: true },
  { key: 'event_type',    label: "Type d'Événement",  width: 116             },
  { key: 'category',      label: 'Catégorie',         width: 90              },
  { key: 'description',   label: 'Détails',           flex: true             },
  { key: 'record_id',     label: 'ID',                width: 52,  mono: true },
  { key: 'username',      label: 'Utilisateur',       width: 96,  mono: true },
  { key: 'security_id',   label: 'ID Sec',            width: 80,  mono: true },
];
const PAGE_SIZES = [200, 500, 1000];

function computeRef(r) {
  const str = `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`;
  let h = 5381;
  for (let i = 0; i < str.length; i++) {
    h = (((h << 5) + h) ^ str.charCodeAt(i)) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function getSortValue(r, colKey) {
  const raw = r.raw || {};
  switch (colKey) {
    case 'timestamp':     return r.timestamp || '';
    case 'artifact_type': return r.artifact_type || '';
    case 'source_short':  return (r.source || '').replace(/^.*[/\\]/, '');
    case 'event_type':    return String(raw.EventType || raw.event_type || raw.Type || raw.type || '');
    case 'category':      return String(raw.Category || raw.category || r.artifact_type || '');
    case 'description':   return r.description || '';
    case 'record_id':     return String(raw.RecordNumber || raw.Id || raw.id || raw.EventRecordID || '');
    case 'username':      return String(raw.UserName || raw.Username || raw.user || raw.User || raw.SubjectUserName || '');
    case 'security_id':   return String(raw.SecurityId || raw.security_id || raw.SID || raw.SubjectUserSid || '');
    default:              return String(r[colKey] ?? '');
  }
}

function fmtTs(ts) {
  if (!ts) return '-';
  try {
    const d = new Date(ts);
    const p = (n, l = 2) => String(n).padStart(l, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} `
         + `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`
         + `.${p(d.getUTCMilliseconds(), 3)}`;
  } catch { return ts; }
}

function Highlight({ text, term }) {
  const str = String(text ?? '');
  if (!term) return str;
  const idx = str.toLowerCase().indexOf(term.toLowerCase());
  if (idx === -1) return str;
  return (
    <>{str.slice(0, idx)}
      <mark style={{ background: '#f59e0b35', color: '#f59e0b', borderRadius: 2, padding: '0 1px' }}>
        {str.slice(idx, idx + term.length)}
      </mark>
      {str.slice(idx + term.length)}</>
  );
}

function TagPicker({ globalIdx, tagData, onChange, onClose, anchorRef }) {
  const current = tagData.get(globalIdx) || { level: null, tags: [] };
  const ref = useRef(null);
  const T = useTheme();
  const isDark = T.mode === 'dark';

  useEffect(() => {
    function h(e) {
      if (ref.current && !ref.current.contains(e.target) &&
          anchorRef.current && !anchorRef.current.contains(e.target)) {
        onClose();
      }
    }
    setTimeout(() => document.addEventListener('mousedown', h), 0);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  function setLevel(lvl) {
    onChange(globalIdx, { ...current, level: current.level === lvl ? null : lvl });
  }
  function toggleTag(key) {
    const tags = current.tags.includes(key)
      ? current.tags.filter(t => t !== key)
      : [...current.tags, key];
    onChange(globalIdx, { ...current, tags });
  }
  function clearAll() { onChange(globalIdx, { level: null, tags: [] }); onClose(); }

  return (
    <div ref={ref} style={{
      position: 'fixed', zIndex: 1000, width: 300,
      background: isDark ? 'linear-gradient(160deg, #3a6fa0 0%, #2d5880 100%)' : '#ffffff',
      border: isDark ? '1px solid #5c9fd4' : '1px solid #c8d8ea',
      borderRadius: 10,
      boxShadow: isDark
        ? '0 20px 60px rgba(0,0,0,0.85), 0 0 0 1px rgba(92,159,212,0.4)'
        : '0 8px 32px rgba(0,0,0,0.15), 0 0 0 1px rgba(13,105,218,0.15)',
      padding: 16,
    }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontFamily: 'monospace', fontSize: 9,
          color: isDark ? '#ffffff' : '#0969da',
          textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8, fontWeight: 700 }}>
          Niveau de confiance
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {CONFIDENCE_LEVELS.map(l => {
            const active = current.level === l.key;
            return (
              <button key={l.key} onClick={() => setLevel(l.key)}
                style={{
                  flex: 1, padding: '7px 4px', borderRadius: 6, fontSize: 10,
                  fontFamily: 'monospace', cursor: 'pointer', fontWeight: 700,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
                  background: active ? l.bg : (isDark ? 'rgba(255,255,255,0.08)' : '#f0f6ff'),
                  color: active ? l.color : (isDark ? '#ffffff' : '#1f2328'),
                  border: `1px solid ${active ? l.color + '80' : (isDark ? 'rgba(255,255,255,0.2)' : '#c8d8ea')}`,
                  transition: 'all 0.12s',
                }}>
                <span style={{ fontSize: 7, lineHeight: 1, color: l.color }}>●</span>
                {l.label}
              </button>
            );
          })}
        </div>
      </div>
      <div>
        <div style={{ fontFamily: 'monospace', fontSize: 9,
          color: isDark ? '#ffffff' : '#0969da',
          textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8, fontWeight: 700 }}>
          Catégorie forensique
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          {FORENSIC_TAGS.map(t => {
            const active = current.tags.includes(t.key);
            return (
              <button key={t.key} onClick={() => toggleTag(t.key)}
                style={{
                  padding: '4px 10px', borderRadius: 10, fontSize: 10,
                  fontFamily: 'monospace', cursor: 'pointer', fontWeight: 600,
                  background: active ? `${t.color}35` : (isDark ? 'rgba(255,255,255,0.08)' : '#f0f6ff'),
                  color: active ? t.color : (isDark ? '#ffffff' : '#1f2328'),
                  border: `1px solid ${active ? t.color + '70' : (isDark ? 'rgba(255,255,255,0.2)' : '#c8d8ea')}`,
                  transition: 'all 0.12s',
                }}>
                {t.label}
              </button>
            );
          })}
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginTop: 14, paddingTop: 10,
        borderTop: `1px solid ${isDark ? 'rgba(255,255,255,0.15)' : '#e0eaf4'}` }}>
        <button onClick={clearAll}
          style={{ fontSize: 10, fontFamily: 'monospace',
            color: isDark ? 'rgba(255,255,255,0.55)' : '#57606a',
            background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0' }}>
          Effacer
        </button>
        <button onClick={onClose}
          style={{ padding: '5px 14px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
            background: isDark ? 'rgba(255,255,255,0.15)' : '#0969da',
            border: isDark ? '1px solid rgba(255,255,255,0.3)' : '1px solid #0969da',
            color: '#ffffff', cursor: 'pointer', fontWeight: 600 }}>
          Fermer
        </button>
      </div>
    </div>
  );
}

export default function CaseTimelineExplorer({ caseId, onTotalChange, reloadKey = 0 }) {
  const [records, setRecords]       = useState([]);
  const [total, setTotal]           = useState(0);
  const [page, setPage]             = useState(1);
  const [pageSize, setPageSize]     = useState(500);
  const [totalPages, setTotalPages] = useState(0);
  const [availTypes, setAvailTypes] = useState([]);
  const [loading, setLoading]       = useState(false);

  const [search, setSearch]         = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [startTime, setStartTime]   = useState('');
  const [endTime, setEndTime]       = useState('');

  const [selectedRow, setSelectedRow]       = useState(null);
  const [bookmarks, setBookmarks]           = useState(new Set());
  const [showBookmarksOnly, setShowBookmarks] = useState(false);
  const [sortCol, setSortCol]               = useState('timestamp');
  const [sortDir, setSortDir]               = useState('desc');
  const [serverSortCol, setServerSortCol]   = useState('timestamp');
  const [serverSortDir, setServerSortDir]   = useState('desc');
  const [hiddenCols, setHiddenCols]         = useState(new Set());
  const [showColMenu, setShowColMenu]       = useState(false);
  const [jumpPage, setJumpPage]             = useState('');

  const [tagData, setTagData]               = useState(new Map());
  const [tagPickerIdx, setTagPickerIdx]     = useState(null);
  const [tagPickerPos, setTagPickerPos]     = useState({ top: 0, left: 0 });
  const [confidenceFilter, setConfidenceFilter]   = useState(null);
  const [forensicTagFilter, setForensicTagFilter] = useState(null);
  const tagAnchorRef = useRef(null);
  const colMenuRef   = useRef(null);

  const [inspectorTab, setInspectorTab]   = useState('details');
  const [notes, setNotes]                 = useState([]);
  const [noteText, setNoteText]           = useState('');
  const [noteSaving, setNoteSaving]       = useState(false);
  const [noteEditId, setNoteEditId]       = useState(null);
  const [noteEditText, setNoteEditText]   = useState('');
  const [notedRefs, setNotedRefs]         = useState(new Set());

  useEffect(() => {
    function h(e) {
      if (colMenuRef.current && !colMenuRef.current.contains(e.target)) setShowColMenu(false);
    }
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const loadTimeline = useCallback(async (pg, tf, srch, st, et, ps, sd = 'desc', sc = 'timestamp') => {
    if (!caseId) return;
    setLoading(true);
    setSelectedRow(null);
    setTagPickerIdx(null);
    try {
      const params = { page: pg, limit: ps, sort_dir: sd, sort_col: sc };
      if (tf && tf !== 'all') params.artifact_types = tf;
      if (srch) params.search = srch;
      if (st) params.start_time = new Date(st).toISOString();
      if (et) params.end_time   = new Date(et).toISOString();
      const res = await collectionAPI.timeline(caseId, params);
      if (res.data) {
        const t = res.data.total || 0;
        setRecords(res.data.records || []);
        setTotal(t);
        setTotalPages(res.data.total_pages || 0);
        setAvailTypes(res.data.artifact_types_available || []);
        if (onTotalChange) onTotalChange(t);
      }
    } catch {
      setRecords([]);
      setTotal(0);
      if (onTotalChange) onTotalChange(0);
    }
    setLoading(false);
  }, [caseId, onTotalChange]);

  useEffect(() => {
    setPage(1); setTypeFilter('all'); setSearch('');
    setStartTime(''); setEndTime(''); setSelectedRow(null);
    loadTimeline(1, 'all', '', '', '', pageSize, 'desc', 'timestamp');
  }, [caseId, reloadKey]);

  function applyFilter() { setPage(1); loadTimeline(1, typeFilter, search, startTime, endTime, pageSize, serverSortDir, serverSortCol); }
  function clearFilters() {
    setSearch(''); setTypeFilter('all'); setStartTime(''); setEndTime('');
    setSortCol('timestamp'); setSortDir('desc');
    setServerSortCol('timestamp'); setServerSortDir('desc');
    setPage(1); loadTimeline(1, 'all', '', '', '', pageSize, 'desc', 'timestamp');
  }
  function changePage(p) { setPage(p); loadTimeline(p, typeFilter, search, startTime, endTime, pageSize, serverSortDir, serverSortCol); }
  function changePageSize(s) { setPageSize(s); setPage(1); loadTimeline(1, typeFilter, search, startTime, endTime, s, serverSortDir, serverSortCol); }

  const loadNotedRefs = useCallback(() => {
    if (!caseId) return;
    artifactsAPI.refsWithNotes(caseId)
      .then(res => setNotedRefs(new Set(res.data?.refs ?? [])))
      .catch(e => console.warn('[TimelineExplorer] noted refs:', e.message));
  }, [caseId]);

  useEffect(() => { loadNotedRefs(); }, [loadNotedRefs]);

  useEffect(() => {
    if (inspectorTab !== 'notes' || selectedRow === null) return;
    const r = displayedRecords?.[selectedRow];
    if (!r || !caseId) return;
    const ref = computeRef(r);
    artifactsAPI.getNotes(caseId, ref)
      .then(res => setNotes(res.data?.notes ?? []))
      .catch(() => setNotes([]));
  }, [inspectorTab, selectedRow, caseId]);

  useEffect(() => {
    setInspectorTab('details');
    setNotes([]);
    setNoteText('');
    setNoteEditId(null);
  }, [selectedRow]);

  async function submitNote(r) {
    if (!noteText.trim()) return;
    setNoteSaving(true);
    try {
      await artifactsAPI.createNote(caseId, computeRef(r), noteText.trim());
      setNoteText('');
      const res = await artifactsAPI.getNotes(caseId, computeRef(r));
      setNotes(res.data?.notes ?? []);
      loadNotedRefs();
    } catch {}
    setNoteSaving(false);
  }

  async function saveEditNote(caseId2, ref, noteId) {
    if (!noteEditText.trim()) return;
    try {
      await artifactsAPI.updateNote(caseId2, ref, noteId, noteEditText.trim());
      const res = await artifactsAPI.getNotes(caseId2, ref);
      setNotes(res.data?.notes ?? []);
      setNoteEditId(null);
    } catch {}
  }

  async function deleteNote(caseId2, ref, noteId) {
    try {
      await artifactsAPI.deleteNote(caseId2, ref, noteId);
      const res = await artifactsAPI.getNotes(caseId2, ref);
      setNotes(res.data?.notes ?? []);
      loadNotedRefs();
    } catch {}
  }

  const SERVER_SORTABLE = new Set(['timestamp', 'artifact_type', 'description', 'source_short']);
  const SERVER_COL_MAP  = { source_short: 'source' };

  function handleSort(colKey) {
    if (SERVER_SORTABLE.has(colKey)) {
      const backendCol = SERVER_COL_MAP[colKey] || colKey;
      const newDir = (serverSortCol === backendCol && serverSortDir === 'desc') ? 'asc' : 'desc';
      setSortCol(colKey);
      setSortDir(newDir);
      setServerSortCol(backendCol);
      setServerSortDir(newDir);
      setPage(1);
      loadTimeline(1, typeFilter, search, startTime, endTime, pageSize, newDir, backendCol);
    } else {

      if (sortCol === colKey) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
      else { setSortCol(colKey); setSortDir('asc'); }
    }
  }

  const sortedRecords = useMemo(() => {

    if (SERVER_SORTABLE.has(sortCol) || !sortCol) return records;
    return [...records].sort((a, b) => {
      const va = getSortValue(a, sortCol), vb = getSortValue(b, sortCol);
      return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  }, [records, sortCol, sortDir]);

  const displayedRecords = useMemo(() => {
    let r = sortedRecords;
    if (showBookmarksOnly) r = r.filter((_, i) => bookmarks.has((page - 1) * pageSize + i));
    if (confidenceFilter)  r = r.filter((_, i) => tagData.get((page-1)*pageSize+i)?.level === confidenceFilter);
    if (forensicTagFilter) r = r.filter((_, i) => tagData.get((page-1)*pageSize+i)?.tags?.includes(forensicTagFilter));
    return r;
  }, [sortedRecords, showBookmarksOnly, bookmarks, confidenceFilter, forensicTagFilter, tagData, page, pageSize]);

  function toggleBookmark(e, globalIdx) {
    e.stopPropagation();
    setBookmarks(prev => { const n = new Set(prev); n.has(globalIdx) ? n.delete(globalIdx) : n.add(globalIdx); return n; });
  }

  function openTagPicker(e, globalIdx) {
    e.stopPropagation();
    if (tagPickerIdx === globalIdx) { setTagPickerIdx(null); return; }
    const rect = e.currentTarget.getBoundingClientRect();
    setTagPickerPos({
      top:  Math.min(rect.bottom + 4, window.innerHeight - 320),
      left: Math.min(rect.left,       window.innerWidth  - 296),
    });
    setTagPickerIdx(globalIdx);
  }

  function handleTagChange(globalIdx, data) {
    setTagData(prev => { const n = new Map(prev); n.set(globalIdx, data); return n; });
  }

  const taggedCount = useMemo(
    () => [...tagData.values()].filter(d => d.level || d.tags?.length).length,
    [tagData]
  );
  const confidenceCounts = useMemo(() => {
    const c = {};
    for (const d of tagData.values()) if (d.level) c[d.level] = (c[d.level] || 0) + 1;
    return c;
  }, [tagData]);

  function exportCSV() {
    if (!records.length) return;
    const cols = ['timestamp','artifact_type','timestamp_column','description','source','_confidence','_tags'];
    const rows = records.map((r, i) => {
      const g  = (page - 1) * pageSize + i;
      const td = tagData.get(g) || {};
      return [
        ...['timestamp','artifact_type','timestamp_column','description','source']
          .map(c => `"${String(r[c] ?? '').replace(/"/g, '""')}"`),
        `"${td.level || ''}"`,
        `"${(td.tags || []).join(';')}"`,
      ].join(',');
    });
    const csv  = [cols.join(','), ...rows].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `supertimeline-${caseId}-p${page}.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  const visibleCols = COLUMNS.filter(c => !hiddenCols.has(c.key));
  const hasFilters  = search || typeFilter !== 'all' || startTime || endTime;

  if (!loading && total === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 0', borderRadius: 10, background: '#07101f', border: '1px solid #1a2035' }}>
        <Clock size={32} style={{ color: '#1a2035', margin: '0 auto 10px' }} />
        <p style={{ fontFamily: 'monospace', fontSize: 12, color: '#3d5070' }}>
          Aucune donnée dans la Super Timeline — importez et parsez une collecte.
        </p>
      </div>
    );
  }

  const S = {
    btn: (active, col) => ({
      display: 'flex', alignItems: 'center', gap: 4,
      padding: '3px 8px', borderRadius: 5, fontSize: 11,
      fontFamily: 'monospace', cursor: 'pointer',
      background: active ? `${col}18` : '#0d1117',
      color: active ? col : '#7d8590',
      border: `1px solid ${active ? col + '35' : '#1e2a3a'}`,
    }),
    chip: (active, col) => ({
      padding: '2px 8px', borderRadius: 10, fontSize: 10,
      fontFamily: 'monospace', cursor: 'pointer',
      display: 'flex', alignItems: 'center', gap: 4,
      background: active ? `${col}18` : 'transparent',
      color: active ? col : '#484f58',
      border: `1px solid ${active ? col + '35' : '#1e2a3a'}`,
    }),
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      
      {total > 0 && <TimelineHistogram records={records} availTypes={availTypes} />}

      {tagPickerIdx !== null && (
        <div style={{ position: 'fixed', top: tagPickerPos.top, left: tagPickerPos.left, zIndex: 1000 }}>
          <TagPicker
            globalIdx={tagPickerIdx} tagData={tagData}
            onChange={handleTagChange} onClose={() => setTagPickerIdx(null)}
            anchorRef={tagAnchorRef}
          />
        </div>
      )}

      <div style={{
        display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'nowrap',
        padding: '6px 10px', marginBottom: 4,
        background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 8,
      }}>
        
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <Search size={11} style={{ position: 'absolute', left: 7, top: '50%', transform: 'translateY(-50%)', color: '#484f58', pointerEvents: 'none' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyFilter()}
            placeholder="Rechercher… (Entrée)"
            style={{
              paddingLeft: 22, paddingRight: 8, paddingTop: 4, paddingBottom: 4,
              borderRadius: 5, fontSize: 11, fontFamily: 'monospace', width: 200,
              background: '#060a10', border: '1px solid #1e2a3a', color: '#e6edf3', outline: 'none',
            }} />
        </div>

        <input type="datetime-local" value={startTime} onChange={e => setStartTime(e.target.value)}
          style={{ padding: '3px 6px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace', flexShrink: 0,
            background: '#060a10', border: '1px solid #1e2a3a', color: startTime ? '#8899bb' : '#334155', colorScheme: 'dark', outline: 'none' }} />
        <span style={{ fontSize: 10, color: '#2a3a50', flexShrink: 0 }}>→</span>
        <input type="datetime-local" value={endTime} onChange={e => setEndTime(e.target.value)}
          style={{ padding: '3px 6px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace', flexShrink: 0,
            background: '#060a10', border: '1px solid #1e2a3a', color: endTime ? '#8899bb' : '#334155', colorScheme: 'dark', outline: 'none' }} />

        <button onClick={applyFilter} style={{ ...S.btn(false, '#4d82c0'), flexShrink: 0 }}>
          <Filter size={10} /> Filtrer
        </button>
        {hasFilters && (
          <button onClick={clearFilters} style={{ ...S.btn(false, '#7d8590'), flexShrink: 0 }}>
            <X size={10} /> Reset
          </button>
        )}

        <div style={{ flex: 1, minWidth: 0 }} />

        {total > 0 && (
          <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, flexShrink: 0,
            background: '#4d82c010', color: '#4d82c0', border: '1px solid #4d82c020' }}>
            {total.toLocaleString()} enreg.
          </span>
        )}

        {bookmarks.size > 0 && (
          <button onClick={() => setShowBookmarks(v => !v)} style={{ ...S.btn(showBookmarksOnly, '#f59e0b'), flexShrink: 0 }}>
            <Star size={10} fill={showBookmarksOnly ? '#f59e0b' : 'none'} />
            {bookmarks.size}
          </button>
        )}

        {taggedCount > 0 && (
          <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, flexShrink: 0,
            background: '#8b72d610', color: '#8b72d6', border: '1px solid #8b72d620' }}>
            ⬤ {taggedCount} taggé{taggedCount > 1 ? 's' : ''}
          </span>
        )}

        <div style={{ display: 'flex', gap: 2, flexShrink: 0 }}>
          {PAGE_SIZES.map(s => (
            <button key={s} onClick={() => changePageSize(s)}
              style={{ padding: '2px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                background: pageSize === s ? '#4d82c018' : 'transparent',
                color: pageSize === s ? '#4d82c0' : '#334155',
                border: `1px solid ${pageSize === s ? '#4d82c030' : '#1e2a3a'}` }}>
              {s}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative', flexShrink: 0 }} ref={colMenuRef}>
          <button onClick={() => setShowColMenu(v => !v)} style={S.btn(showColMenu, '#7d8590')}>
            <Eye size={10} /> Colonnes
          </button>
          {showColMenu && (
            <div style={{
              position: 'absolute', right: 0, top: 'calc(100% + 4px)', zIndex: 50,
              background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 8,
              padding: '6px 4px', minWidth: 150,
              boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
            }}>
              {COLUMNS.map(c => (
                <label key={c.key} style={{
                  display: 'flex', alignItems: 'center', gap: 7, padding: '4px 8px',
                  fontFamily: 'monospace', fontSize: 11, cursor: 'pointer', borderRadius: 4,
                  color: hiddenCols.has(c.key) ? '#334155' : '#c0cce0',
                }}>
                  <input type="checkbox" checked={!hiddenCols.has(c.key)}
                    onChange={() => setHiddenCols(prev => {
                      const n = new Set(prev); n.has(c.key) ? n.delete(c.key) : n.add(c.key); return n;
                    })} />
                  {c.label}
                </label>
              ))}
            </div>
          )}
        </div>

        <button onClick={exportCSV} disabled={!records.length} style={{
          ...S.btn(false, '#22c55e'), flexShrink: 0,
          color: records.length ? '#22c55e' : '#334155',
          cursor: records.length ? 'pointer' : 'default',
        }}>
          <Download size={10} /> CSV
        </button>
      </div>

      {total > 0 && availTypes.length > 0 && (
        <div style={{
          display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center',
          padding: '5px 10px', marginBottom: 4,
          background: '#080d15', border: '1px solid #1a2030', borderRadius: 7,
        }}>
          {['all', ...availTypes].map(t => {
            const col = t === 'all' ? '#4d82c0' : artifactColor(t);
            const active = typeFilter === t;
            return (
              <button key={t}
                onClick={() => { setTypeFilter(t); setPage(1); loadTimeline(1, t, search, startTime, endTime, pageSize, serverSortDir, serverSortCol); }}
                style={S.chip(active, col)}>
                {t !== 'all' && (
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: col, display: 'inline-block', flexShrink: 0 }} />
                )}
                {t === 'all' ? 'Tous' : t}
              </button>
            );
          })}
        </div>
      )}

      {taggedCount > 0 && (
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center',
          padding: '5px 10px', marginBottom: 4,
          background: '#080d15', border: '1px solid #1a2030', borderRadius: 7,
        }}>
          <Tag size={10} style={{ color: '#2a3a50', flexShrink: 0 }} />
          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#2a3a50' }}>Tags :</span>
          {CONFIDENCE_LEVELS.map(l => {
            if (!confidenceCounts[l.key]) return null;
            const active = confidenceFilter === l.key;
            return (
              <button key={l.key} onClick={() => setConfidenceFilter(active ? null : l.key)} style={S.chip(active, l.color)}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: l.color, display: 'inline-block' }} />
                {l.label} ({confidenceCounts[l.key]})
              </button>
            );
          })}
          {FORENSIC_TAGS.map(t => {
            const count = [...tagData.values()].filter(d => d.tags?.includes(t.key)).length;
            if (!count) return null;
            const active = forensicTagFilter === t.key;
            return (
              <button key={t.key} onClick={() => setForensicTagFilter(active ? null : t.key)} style={S.chip(active, t.color)}>
                {t.label} ({count})
              </button>
            );
          })}
          {(confidenceFilter || forensicTagFilter) && (
            <button onClick={() => { setConfidenceFilter(null); setForensicTagFilter(null); }}
              style={{ ...S.btn(false, '#7d8590'), fontSize: 10 }}>
              <X size={9} /> Reset
            </button>
          )}
        </div>
      )}

      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '48px 0', gap: 8 }}>
          <Loader2 size={18} className="animate-spin" style={{ color: '#4d82c0' }} />
          <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#334155' }}>Chargement…</span>
        </div>
      )}

      {!loading && (
        <>
          <div style={{
            overflowX: 'auto', overflowY: 'auto',
            border: '1px solid #1e2a3a', borderRadius: 8,
            height: selectedRow !== null ? 'calc(100vh - 730px)' : 'calc(100vh - 530px)',
            minHeight: selectedRow !== null ? 160 : 260,
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, tableLayout: 'fixed' }}>
              <colgroup>
                <col style={{ width: 26 }} />
                <col style={{ width: 20 }} />
                <col style={{ width: 28 }} />
                {visibleCols.map(c => <col key={c.key} style={{ width: c.flex ? undefined : c.width }} />)}
              </colgroup>
              <thead>
                <tr style={{ background: '#060a10', position: 'sticky', top: 0, zIndex: 10 }}>
                  <th style={{ padding: '5px 4px', borderBottom: '1px solid #1e2a3a' }} />
                  <th style={{ padding: '5px 4px', borderBottom: '1px solid #1e2a3a' }} />
                  <th style={{
                    padding: '5px 4px', borderBottom: '1px solid #1e2a3a',
                    fontFamily: 'monospace', fontSize: 9, color: '#2a3a50', textAlign: 'center',
                  }}>
                    <Tag size={9} />
                  </th>
                  {visibleCols.map(col => (
                    <th key={col.key} onClick={() => handleSort(col.key)}
                      style={{
                        padding: '5px 8px', textAlign: 'left', cursor: 'pointer', userSelect: 'none',
                        fontFamily: 'monospace', fontSize: 10, fontWeight: 600,
                        letterSpacing: '0.07em', textTransform: 'uppercase',
                        color: sortCol === col.key ? '#4d82c0' : '#3d5070',
                        borderBottom: '1px solid #1e2a3a', whiteSpace: 'nowrap',
                        background: sortCol === col.key ? '#4d82c008' : 'transparent',
                      }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        {col.label}
                        {sortCol === col.key && (sortDir === 'asc' ? <SortAsc size={9} /> : <SortDesc size={9} />)}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayedRecords.map((r, i) => {
                  const globalIdx = (page - 1) * pageSize + i;
                  const acol      = artifactColor(r.artifact_type);
                  const isSel     = selectedRow === i;
                  const isBkm     = bookmarks.has(globalIdx);
                  const hasNote   = notedRefs.has(computeRef(r));
                  const td        = tagData.get(globalIdx) || {};
                  const lvl       = td.level ? CONFIDENCE_MAP[td.level] : null;
                  const rowBg     = isSel
                    ? '#0d1e38'
                    : lvl ? lvl.bg
                    : i % 2 === 0 ? 'transparent' : '#060c16';

                  return (
                    <tr key={i} onClick={() => setSelectedRow(isSel ? null : i)}
                      style={{
                        background: rowBg,
                        borderLeft: `3px solid ${lvl ? lvl.color : isSel ? acol : acol + '55'}`,
                        borderBottom: '1px solid #0d1525',
                        cursor: 'pointer',
                        transition: 'background 0.08s',
                      }}>

                      <td onClick={e => toggleBookmark(e, globalIdx)}
                        style={{ padding: '2px 2px', textAlign: 'center', width: 26 }}>
                        <Star size={9} fill={isBkm ? '#f59e0b' : 'none'}
                          style={{ color: isBkm ? '#f59e0b' : '#1e2a3a' }} />
                      </td>

                      <td style={{ padding: '2px 2px', textAlign: 'center', width: 20 }}>
                        {hasNote && (
                          <MessageSquare size={9} style={{ color: '#4d82c0' }} fill="#4d82c020" />
                        )}
                      </td>

                      <td ref={tagPickerIdx === globalIdx ? tagAnchorRef : null}
                        onClick={e => openTagPicker(e, globalIdx)}
                        style={{ padding: '2px 2px', textAlign: 'center', width: 28 }}>
                        {lvl ? (
                          <span style={{ fontSize: 12, color: lvl.color }} title={lvl.label}>{lvl.dot}</span>
                        ) : td.tags?.length > 0 ? (
                          <Tag size={9} style={{ color: '#2a3a50' }} />
                        ) : (
                          <span style={{ fontSize: 9, color: '#1e2a3a' }}>○</span>
                        )}
                      </td>

                      {visibleCols.map(col2 => {
                        let content;
                        const raw = r.raw || {};
                        if (col2.key === 'timestamp') {
                          content = <span style={{ color: isSel ? '#93c5fd' : '#6a8aaf' }}>{fmtTs(r.timestamp)}</span>;
                        } else if (col2.key === 'artifact_type') {
                          content = (
                            <span style={{
                              padding: '1px 5px', borderRadius: 3, fontSize: 10,
                              fontWeight: 700, fontFamily: 'monospace',
                              background: `${acol}15`, color: acol, border: `1px solid ${acol}28`,
                            }}>
                              {r.artifact_type}
                            </span>
                          );
                        } else if (col2.key === 'source_short') {
                          const s = (r.source || '').replace(/^.*[/\\]/, '').substring(0, 32);
                          content = <span style={{ color: '#3d5070' }}><Highlight text={s || '-'} term={search} /></span>;
                        } else if (col2.key === 'event_type') {
                          const et = raw.EventType || raw.event_type || raw.Type || raw.type || '-';
                          content = <span style={{ color: '#7d8590' }}>{String(et).substring(0, 22)}</span>;
                        } else if (col2.key === 'category') {
                          const cat = raw.Category || raw.category || r.artifact_type || '-';
                          content = <span style={{ color: '#484f58' }}>{String(cat).substring(0, 18)}</span>;
                        } else if (col2.key === 'description') {
                          content = (
                            <span style={{ color: isSel ? '#e8f0fe' : '#c0cce0' }}>
                              <Highlight text={r.description || '-'} term={search} />
                              {td.tags?.length > 0 && (
                                <span style={{ marginLeft: 6 }}>
                                  {td.tags.map(key => {
                                    const ft = FORENSIC_TAG_MAP[key];
                                    return ft ? (
                                      <span key={key} style={{
                                        marginLeft: 3, padding: '0px 5px', borderRadius: 8,
                                        fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
                                        background: `${ft.color}20`, color: ft.color, border: `1px solid ${ft.color}30`,
                                      }}>
                                        {ft.label}
                                      </span>
                                    ) : null;
                                  })}
                                </span>
                              )}
                            </span>
                          );
                        } else if (col2.key === 'record_id') {
                          const rid = raw.RecordNumber || raw.Id || raw.id || raw.EventRecordID || (globalIdx + 1);
                          content = <span style={{ color: '#3d5070' }}>{String(rid).substring(0, 10)}</span>;
                        } else if (col2.key === 'username') {
                          const un = raw.UserName || raw.Username || raw.user || raw.User || raw.SubjectUserName || '-';
                          content = <span style={{ color: '#7d8590' }}>{String(un).substring(0, 22)}</span>;
                        } else if (col2.key === 'security_id') {
                          const sid = raw.SecurityId || raw.security_id || raw.SID || raw.SubjectUserSid || '-';
                          content = <span style={{ color: '#2a3a50' }}>{String(sid).substring(0, 18)}</span>;
                        } else {
                          content = <span style={{ color: '#3d5070' }}>{r[col2.key] || '-'}</span>;
                        }
                        return (
                          <td key={col2.key} style={{
                            padding: '3px 8px',
                            fontFamily: col2.mono ? 'monospace' : undefined,
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            maxWidth: col2.flex ? 0 : undefined,
                          }}>
                            {content}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
                {displayedRecords.length === 0 && (
                  <tr>
                    <td colSpan={visibleCols.length + 2} style={{
                      textAlign: 'center', padding: '32px 0',
                      fontFamily: 'monospace', fontSize: 11, color: '#334155',
                    }}>
                      Aucun résultat pour ce filtre
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {selectedRow !== null && displayedRecords[selectedRow] && (() => {
            const r    = displayedRecords[selectedRow];
            const acol = artifactColor(r.artifact_type);
            const gIdx = (page - 1) * pageSize + selectedRow;
            const td   = tagData.get(gIdx) || {};
            const lvl  = td.level ? CONFIDENCE_MAP[td.level] : null;
            const raw  = r.raw || {};
            const rid  = raw.RecordNumber || raw.Id || raw.id || raw.EventRecordID || (gIdx + 1);

            return (
              <div style={{ marginTop: 6, border: '1px solid #1a2035', borderRadius: 8, overflow: 'hidden' }}>
                
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '6px 14px', background: '#07101f', borderBottom: '1px solid #1a2035',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    
                    {['details', 'notes'].map(tab => (
                      <button key={tab} onClick={() => setInspectorTab(tab)} style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        padding: '3px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                        fontWeight: inspectorTab === tab ? 600 : 400,
                        color: inspectorTab === tab ? '#4d82c0' : '#3d5070',
                        borderBottom: inspectorTab === tab ? '2px solid #4d82c0' : '2px solid transparent',
                      }}>
                        {tab === 'details' ? 'Détails' : (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <MessageSquare size={10} />
                            Notes {notes.length > 0 && `(${notes.length})`}
                          </span>
                        )}
                      </button>
                    ))}
                    {lvl && (
                      <span style={{ padding: '1px 7px', borderRadius: 8, fontSize: 10, fontFamily: 'monospace', fontWeight: 700, background: lvl.bg, color: lvl.color, border: `1px solid ${lvl.color}40` }}>
                        {lvl.label}
                      </span>
                    )}
                    {td.tags?.map(key => {
                      const ft = FORENSIC_TAG_MAP[key];
                      return ft ? (
                        <span key={key} style={{ padding: '1px 7px', borderRadius: 8, fontSize: 10, fontFamily: 'monospace', background: `${ft.color}18`, color: ft.color, border: `1px solid ${ft.color}30` }}>
                          {ft.label}
                        </span>
                      ) : null;
                    })}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#3d5070' }}>
                      ID {rid} — <span style={{ color: acol }}>{r.artifact_type}</span>
                    </span>
                    <button onClick={() => setSelectedRow(null)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#2a3a50', display: 'flex' }}>
                      <X size={13} />
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', maxHeight: '40vh', minHeight: 200, overflow: 'hidden' }}>
                {inspectorTab === 'notes' ? (

                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#040810' }}>
                    
                    <div style={{ flex: 1, overflow: 'auto', padding: '8px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {notes.length === 0 ? (
                        <div style={{ color: '#2a3a50', fontFamily: 'monospace', fontSize: 11, textAlign: 'center', marginTop: 24 }}>
                          Aucune note — ajoutez-en une ci-dessous
                        </div>
                      ) : notes.map(n => (
                        <div key={n.id} style={{ borderRadius: 6, border: '1px solid #1a2a3a', background: '#060e1c', padding: '8px 10px' }}>
                          {noteEditId === n.id ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                              <textarea value={noteEditText} onChange={e => setNoteEditText(e.target.value)}
                                style={{ width: '100%', background: '#050c18', border: '1px solid #2a3a50', borderRadius: 4,
                                  color: '#c8d8ec', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px',
                                  resize: 'vertical', minHeight: 60, outline: 'none', boxSizing: 'border-box' }} />
                              <div style={{ display: 'flex', gap: 6 }}>
                                <button onClick={() => saveEditNote(caseId, computeRef(r), n.id)}
                                  style={{ padding: '3px 10px', borderRadius: 4, background: '#1a3a5a', border: '1px solid #2a5080',
                                    color: '#4d82c0', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                                  Enregistrer
                                </button>
                                <button onClick={() => setNoteEditId(null)}
                                  style={{ padding: '3px 10px', borderRadius: 4, background: 'none', border: '1px solid #1a2a3a',
                                    color: '#3d5070', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                                  Annuler
                                </button>
                              </div>
                            </div>
                          ) : (
                            <>
                              <div style={{ fontSize: 11, color: '#c8d8ec', lineHeight: 1.5, wordBreak: 'break-word', marginBottom: 6 }}>
                                {n.note}
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <span style={{ fontSize: 9, color: '#3d5070', fontFamily: 'monospace' }}>
                                  {n.author_name || n.author_username} · {new Date(n.created_at).toLocaleString('fr-FR')}
                                  {n.updated_at !== n.created_at && ' (modifié)'}
                                </span>
                                <div style={{ display: 'flex', gap: 6 }}>
                                  <button onClick={() => { setNoteEditId(n.id); setNoteEditText(n.note); }}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3d5070', display: 'flex' }}>
                                    <Pencil size={10} />
                                  </button>
                                  <button onClick={() => deleteNote(caseId, computeRef(r), n.id)}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#5a2020', display: 'flex' }}>
                                    <Trash2 size={10} />
                                  </button>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                    
                    <div style={{ flexShrink: 0, padding: '8px 14px', borderTop: '1px solid #0d1525', display: 'flex', gap: 8 }}>
                      <textarea value={noteText} onChange={e => setNoteText(e.target.value)}
                        placeholder="Ajouter une note d'investigation…"
                        onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) submitNote(r); }}
                        style={{ flex: 1, background: '#050c18', border: '1px solid #1a2a3a', borderRadius: 4,
                          color: '#c8d8ec', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px',
                          resize: 'none', height: 52, outline: 'none' }} />
                      <button onClick={() => submitNote(r)} disabled={noteSaving || !noteText.trim()}
                        style={{ padding: '0 12px', borderRadius: 4, background: noteText.trim() ? '#1a3a5a' : '#0a1020',
                          border: `1px solid ${noteText.trim() ? '#2a5080' : '#0e1828'}`,
                          color: noteText.trim() ? '#4d82c0' : '#1e2a3a', cursor: noteText.trim() ? 'pointer' : 'default',
                          display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace' }}>
                        <Send size={11} /> Envoyer
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                  
                  <div style={{ flexShrink: 0, padding: '8px 14px', borderBottom: '1px solid #0d1525', display: 'flex', flexDirection: 'column', gap: 6 }}>
                    
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4d6080', minWidth: 84, flexShrink: 0, paddingTop: 1 }}>Horodatage</span>
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#7abfff', fontWeight: 600 }}>
                        {fmtTs(r.timestamp)}
                      </span>
                    </div>
                    
                    {r.source && (
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4d6080', minWidth: 84, flexShrink: 0, paddingTop: 1 }}>Source</span>
                        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#8aa8c8', wordBreak: 'break-all', lineHeight: 1.4 }}>{r.source}</span>
                      </div>
                    )}
                    
                    {r.description && (
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4d6080', minWidth: 84, flexShrink: 0, paddingTop: 1 }}>Détails</span>
                        <span style={{ fontSize: 11, color: '#c8d8ec', lineHeight: 1.5, wordBreak: 'break-word' }}>{r.description}</span>
                      </div>
                    )}
                  </div>

                  <div style={{ flex: 1, overflow: 'auto', background: '#040810' }}>
                    
                    <div style={{
                      position: 'sticky', top: 0, zIndex: 1,
                      padding: '4px 14px', background: '#060c18', borderBottom: '1px solid #0d1525',
                      fontFamily: 'monospace', fontSize: 9, color: '#3d5070',
                      textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                      Données brutes CSV — {Object.entries(raw).filter(([,v]) => v !== null && v !== undefined && v !== '').length} champs
                    </div>
                    
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10.5 }}>
                      <tbody>
                        {Object.entries(raw).map(([k, v]) => {
                          if (v === null || v === undefined || v === '') return null;
                          const strV = typeof v === 'object' ? JSON.stringify(v) : String(v);
                          return (
                            <tr key={k} style={{ borderBottom: '1px solid #080e1a' }}>
                              <td style={{
                                padding: '4px 14px',
                                fontFamily: 'monospace', fontSize: 10, color: '#4d7090',
                                whiteSpace: 'nowrap', verticalAlign: 'top',
                                width: '30%', maxWidth: 180,
                                userSelect: 'none',
                              }}>
                                {k}
                              </td>
                              <td style={{
                                padding: '4px 14px 4px 6px',
                                fontFamily: 'monospace', fontSize: 10, color: '#a8bfd4',
                                wordBreak: 'break-all', lineHeight: 1.5,
                              }}>
                                {strV}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  </>
                )}
                </div>
              </div>
            );
          })()}

          {totalPages > 1 && (
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginTop: 6, padding: '5px 2px',
            }}>
              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#2a3a50' }}>
                {((page - 1) * pageSize + 1).toLocaleString()}–{Math.min(page * pageSize, total).toLocaleString()} / {total.toLocaleString()}
              </span>

              <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                <button disabled={page <= 1} onClick={() => changePage(1)}
                  style={{ ...S.btn(false, '#7d8590'), color: page <= 1 ? '#1e2a3a' : '#484f58', cursor: page <= 1 ? 'default' : 'pointer' }}>
                  «
                </button>
                <button disabled={page <= 1} onClick={() => changePage(page - 1)}
                  style={{ ...S.btn(false, '#7d8590'), color: page <= 1 ? '#1e2a3a' : '#484f58', cursor: page <= 1 ? 'default' : 'pointer' }}>
                  <ChevronLeft size={11} />
                </button>
                <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#484f58', padding: '0 8px', whiteSpace: 'nowrap' }}>
                  {page} <span style={{ color: '#2a3a50' }}>/</span> {totalPages}
                </span>
                <button disabled={page >= totalPages} onClick={() => changePage(page + 1)}
                  style={{ ...S.btn(false, '#7d8590'), color: page >= totalPages ? '#1e2a3a' : '#484f58', cursor: page >= totalPages ? 'default' : 'pointer' }}>
                  <ChevronRight size={11} />
                </button>
                <button disabled={page >= totalPages} onClick={() => changePage(totalPages)}
                  style={{ ...S.btn(false, '#7d8590'), color: page >= totalPages ? '#1e2a3a' : '#484f58', cursor: page >= totalPages ? 'default' : 'pointer' }}>
                  »
                </button>
                <input value={jumpPage} onChange={e => setJumpPage(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter') {
                      const p = parseInt(jumpPage);
                      if (p >= 1 && p <= totalPages) { changePage(p); setJumpPage(''); }
                    }
                  }}
                  placeholder="aller à…"
                  style={{
                    width: 66, padding: '3px 6px', borderRadius: 4, textAlign: 'center',
                    fontFamily: 'monospace', fontSize: 10, outline: 'none',
                    background: '#060a10', border: '1px solid #1e2a3a', color: '#484f58',
                  }} />
              </div>

              <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#2a3a50' }}>
                {taggedCount > 0 ? `⬤ ${taggedCount} taggé${taggedCount > 1 ? 's' : ''}` : ''}
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}
