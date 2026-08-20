import { useState, useEffect, useCallback, useMemo, useRef, Fragment } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Boxes, Search, Loader2, ChevronLeft, ChevronRight, ChevronDown,
  ChevronRight as ChevronRightSm, FileText, Database, X, ArrowUpDown,
  Folder, FolderOpen, ListTree, Table2, AlertTriangle, Filter,
  Regex, FileSearch, Clock,
} from 'lucide-react';
import { collectionAPI } from '../utils/api';
import { artifactColor } from '../constants/artifactColors';
import { parseFlexibleTimestamp } from '../components/supertimeline/utils/timelineUtils';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const PAGE_SIZE = 100;

// Curated, high-signal columns per artifact type. The full parser column set is
// still available in the expanded row detail; the table stays compact/readable.
const PRIMARY_COLUMNS = {
  evtx:      ['EventId', 'Channel', 'MapDescription', 'Computer', 'Provider'],
  mft:       ['FileName', 'ParentPath', 'Extension', 'IsDirectory', 'InUse'],
  usn:       ['Name', 'ParentPath', 'UpdateReasons'],
  indx:      ['FileName', 'ParentPath'],
  prefetch:  ['ExecutableName', 'RunCount', 'FullPath', 'LastRun'],
  lnk:       ['LocalPath', 'SourceFile', 'TargetPath'],
  registry:  ['HivePath', 'KeyPath', 'ValueName', 'ValueData', 'ValueType'],
  amcache:   ['ProgramName', 'FullPath', 'FileKeyLastWriteTimestamp'],
  appcompat: ['Path', 'LastModifiedTimeUTC'],
  shellbags: ['AbsolutePath', 'HiveUser'],
  jumplist:  ['AppIdDescription', 'LocalPath', 'TargetPath'],
  srum:      ['ExeInfo', 'AppId'],
  wxtcmd:    ['DisplayText', 'AppId'],
  hayabusa:  ['RuleTitle', 'Level', 'Channel'],
  recycle:   ['FileName', 'SourceName'],
  bits:      ['JobName', 'TargetDirectory'],
  userassist:['ProgramName', 'RunCount'],
  usb:       ['DeviceDescription', 'DeviceInstanceId'],
  schtasks:  ['TaskName', 'Command'],
  pwsh:      ['Command', 'UserName'],
  dns:       ['Entry', 'Type'],
  webcache:  ['Url', 'ContainerType'],
  wmi:       ['Type', 'Name', 'Detail'],
  sqle:      ['Title', 'URL'],
  auditd:    ['AuditType', 'Exe'],
  syslog:    ['Program', 'Message'],
  bash_history: ['Command', 'UserName'],
  unified_log: ['ProcessName', 'Message'],
};

function fmtTs(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    const p = (n, l = 2) => String(n).padStart(l, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  } catch { return String(iso); }
}

function fmtSize(b) {
  if (b == null) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, n = Number(b);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function cell(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

// Convert a user-supplied timestamp to a UTC ISO string. Naive timestamps
// ("2025-12-26 00:57:43.723") are treated as UTC — consistent with how the
// table displays timestamps — never shifted by the browser's local TZ.
function toUtcIso(v) {
  if (!v) return '';
  const d = parseFlexibleTimestamp(v);
  if (d) return d.toISOString();
  try {
    const d2 = new Date(v);
    return Number.isNaN(d2.getTime()) ? '' : d2.toISOString();
  } catch { return ''; }
}

// Pull after:/before: tokens out of a search string. A token runs to the end
// of the string or to the next known prefixed token (timestamps may contain
// spaces). Returns { start, end } as UTC ISO strings plus the remaining text.
function extractTimeFilters(q) {
  const out = { start: '', end: '', rest: String(q || '') };
  out.rest = out.rest.replace(
    /(?:^|\s)(after|before):([^\s].*?)(?=\s+(?:after|before|type|host|user|sev|tag|tool|eid|ext):|$)/gi,
    (m, kw, val) => {
      const v = val.trim();
      if (kw.toLowerCase() === 'after') out.start = toUtcIso(v);
      else out.end = toUtcIso(v);
      return ' ';
    },
  ).replace(/\s+/g, ' ').trim();
  return out;
}

const BASE_COLS = [
  { key: 'timestamp', label: 'Timestamp', w: 150 },
  { key: 'description', label: 'Description', w: 220 },
  { key: 'source', label: 'Source', w: 200 },
];

export default function CollectionArtifactsPage() {
  const { t } = useTranslation();
  const ctx = useOutletContext() || {};
  const caseId = ctx.caseId;
  const collectionId = ctx.collectionId;
  const navigate = useNavigate();

  const [types, setTypes] = useState([]);
  const [typesLoading, setTypesLoading] = useState(true);
  const [selected, setSelected] = useState('');
  const [viewMode, setViewMode] = useState('table');

  const [records, setRecords] = useState([]);
  const [columns, setColumns] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [sortDir, setSortDir] = useState('asc');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState(null);

  // EVTX filters: raw-column filters (dropdowns fed by facets) applied server-side.
  const [filters, setFilters] = useState({});
  const [facets, setFacets] = useState({});
  const [facetsLoading, setFacetsLoading] = useState(false);

  // Search scope: 'type' filters the selected artifact type; 'all' runs a
  // cross-type keyword/regex search (like the files browser "Tous" scope).
  const [scope, setScope] = useState('type');
  const [regexMode, setRegexMode] = useState(false);
  const [globalResults, setGlobalResults] = useState(null);
  const [globalSearching, setGlobalSearching] = useState(false);
  const [globalErr, setGlobalErr] = useState('');

  // Jump-to-timestamp: symmetric window around a precise time (same UX as the
  // SuperTimeline CommandBar). timeStart/timeEnd are UTC ISO strings.
  const [timeStart, setTimeStart] = useState('');
  const [timeEnd, setTimeEnd] = useState('');
  const [jumpOpen, setJumpOpen] = useState(false);
  const [jumpVal, setJumpVal] = useState('');
  const [jumpWindow, setJumpWindow] = useState(15);
  const [jumpErr, setJumpErr] = useState('');
  const jumpRef = useRef(null);
  const jumpInputRef = useRef(null);

  useEffect(() => {
    const h = e => { if (jumpRef.current && !jumpRef.current.contains(e.target)) { setJumpOpen(false); setJumpErr(''); } };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  useEffect(() => {
    if (jumpOpen) jumpInputRef.current?.focus();
  }, [jumpOpen]);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    setTypesLoading(true);
    collectionAPI.artifactsSummary(caseId, { evidence_id: collectionId })
      .then(r => {
        const list = r.data?.artifacts || [];
        setTypes(list);
        if (list.length > 0 && !selected) setSelected(list[0].artifact_type);
      })
      .catch(() => setTypes([]))
      .finally(() => setTypesLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, collectionId]);

  useEffect(() => {
    const h = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(h);
  }, [search]);

  // Build the JSON filters payload from the current EVTX filter state.
  const filterPayload = useMemo(() => {
    const arr = [];
    const evId = String(filters.EventId || '').trim();
    if (evId) arr.push({ col: 'EventId', op: 'in', value: evId });
    for (const col of ['Channel', 'Level', 'Computer', 'Provider']) {
      const v = String(filters[col] || '').trim();
      if (v) arr.push({ col, op: 'eq', value: v });
    }
    return arr;
  }, [filters]);

  const load = useCallback(async () => {
    if (!caseId || !collectionId || !selected || scope !== 'type') return;
    setLoading(true);
    setError('');
    const tf = extractTimeFilters(debounced);
    try {
      const r = await collectionAPI.artifactRows(caseId, selected, {
        evidence_id: collectionId,
        page,
        limit: PAGE_SIZE,
        search: tf.rest,
        search_op: regexMode ? 'regex' : 'contains',
        sort_dir: sortDir,
        ...(tf.start ? { start_time: tf.start } : {}),
        ...(tf.end ? { end_time: tf.end } : {}),
        ...(timeStart ? { start_time: timeStart } : {}),
        ...(timeEnd ? { end_time: timeEnd } : {}),
        ...(filterPayload.length ? { filters: JSON.stringify(filterPayload) } : {}),
      });
      setRecords(r.data?.records || []);
      setColumns(r.data?.columns || []);
      setTotal(r.data?.total || 0);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to load artifact rows');
      setRecords([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [caseId, collectionId, selected, page, debounced, sortDir, filterPayload, scope, regexMode, timeStart, timeEnd]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => { setPage(1); setExpanded(null); }, [selected, debounced, sortDir, filterPayload, timeStart, timeEnd]);

  // Facets for EVTX filter dropdowns.
  useEffect(() => {
    if (!caseId || !collectionId || selected !== 'evtx') { setFacets({}); return; }
    setFacetsLoading(true);
    collectionAPI.artifactFacets(caseId, selected, { evidence_id: collectionId })
      .then(r => setFacets(r.data?.facets || {}))
      .catch(() => setFacets({}))
      .finally(() => setFacetsLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, collectionId, selected]);

  const selectedMeta = useMemo(
    () => types.find(x => x.artifact_type === selected) || null,
    [types, selected],
  );

  const setFilter = (col, val) => {
    setFilters(prev => {
      const n = { ...prev };
      if (val === '' || val === null || val === undefined) delete n[col];
      else n[col] = val;
      return n;
    });
    setPage(1);
  };

  const clearFilters = () => { setFilters({}); setPage(1); };
  const activeFilterCount = Object.keys(filters).filter(k => String(filters[k] || '').trim()).length;

  // Cross-type search (scope 'all'): keyword or regex across every artifact type.
  const runGlobalSearch = useCallback(async () => {
    const tf = extractTimeFilters(search);
    const q = tf.rest;
    if (!q || scope !== 'all' || !caseId || !collectionId) return;
    setGlobalSearching(true);
    setGlobalErr('');
    setGlobalResults(null);
    try {
      const res = await collectionAPI.artifactSearch(caseId, {
        evidence_id: collectionId,
        q,
        regex: regexMode ? 1 : 0,
        ...(tf.start ? { start_time: tf.start } : {}),
        ...(tf.end ? { end_time: tf.end } : {}),
      });
      setGlobalResults(res.data);
    } catch (e) {
      setGlobalErr(e.response?.data?.error || e.message || 'Search failed');
    } finally {
      setGlobalSearching(false);
    }
  }, [search, scope, regexMode, caseId, collectionId]);

  // Drop stale cross-type results when leaving 'all' scope or clearing the query.
  useEffect(() => {
    if (scope !== 'all' || !search.trim()) { setGlobalResults(null); setGlobalErr(''); }
  }, [scope, search]);

  const onSearchKey = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (scope === 'all') runGlobalSearch();
    }
  };

  const doJump = useCallback(() => {
    const d = parseFlexibleTimestamp(jumpVal);
    if (!d) { setJumpErr('Format de date invalide'); return; }
    const t = d.getTime();
    setTimeStart(new Date(t - jumpWindow * 60000).toISOString());
    setTimeEnd(new Date(t + jumpWindow * 60000).toISOString());
    setJumpOpen(false); setJumpVal(''); setJumpErr('');
    setPage(1);
  }, [jumpVal, jumpWindow]);

  const openGlobalResultType = (type) => {
    setSelected(type);
    setScope('type');
    setViewMode('table');
    setFilters({});
    setPage(1);
    setExpanded(null);
    setDebounced(search);
    setGlobalResults(null);
  };

  // Curated columns shown in the table; fall back to the full set if unknown.
  const tableColumns = useMemo(() => {
    const prim = PRIMARY_COLUMNS[selected] || [];
    if (!prim.length) return columns;
    const present = new Set(columns);
    return prim.filter(c => present.has(c));
  }, [selected, columns]);

  const extraCount = Math.max(0, columns.length - tableColumns.length);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const TREE_TYPES = ['registry', 'shellbags', 'mft'];
  const isTreeType = TREE_TYPES.includes(selected);
  const showTree = isTreeType && viewMode === 'tree';

  if (!caseId || !collectionId) {
    return <div style={{ padding: 24, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 13 }}>{t('collectionArtifacts.noContext', 'Contexte de collecte manquant')}</div>;
  }

  const color = artifactColor(selected);

  const btn = (disabled) => ({
    display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 9px', borderRadius: 6,
    cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.4 : 1,
    background: 'var(--fl-card)', border: '1px solid var(--fl-border2)', color: 'var(--fl-dim)',
    fontFamily: MONO, fontSize: 10.5, flexShrink: 0,
  });

  const toggleBtn = (active) => ({
    display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 9px', borderRadius: 6, cursor: 'pointer',
    background: active ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'var(--fl-card)',
    color: active ? 'var(--fl-accent)' : 'var(--fl-dim)',
    border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 26%, transparent)' : 'var(--fl-border2)'}`,
    fontFamily: MONO, fontSize: 10.5, fontWeight: 600, flexShrink: 0,
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
        borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap',
      }}>
        <Boxes size={15} style={{ color: 'var(--fl-purple)', flexShrink: 0 }} />
        <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>
          {t('collectionArtifacts.title', 'Artéfacts')}
        </span>
        {selected && (
          <>
            <span style={{ color: 'var(--fl-border3)' }}>·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: MONO, fontSize: 12, color: 'var(--fl-text)', fontWeight: 600 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
              {selectedMeta?.artifact_name || selected}
            </span>
            <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>
              {total.toLocaleString()} {t('collectionArtifacts.rows', 'ligne(s)')}
            </span>
          </>
        )}
        <span style={{ flex: 1 }} />

        {isTreeType && (
          <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
            <button onClick={() => setViewMode('table')} style={{ ...btn(false), color: viewMode === 'table' ? 'var(--fl-accent)' : 'var(--fl-dim)', borderColor: viewMode === 'table' ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border2)', background: viewMode === 'table' ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'var(--fl-card)' }}>
              <Table2 size={11} /> {t('collectionArtifacts.table', 'Tableau')}
            </button>
            <button onClick={() => setViewMode('tree')} style={{ ...btn(false), color: viewMode === 'tree' ? 'var(--fl-accent)' : 'var(--fl-dim)', borderColor: viewMode === 'tree' ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border2)', background: viewMode === 'tree' ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'var(--fl-card)' }}>
              <ListTree size={11} /> {t('collectionArtifacts.tree', 'Arborescence')}
            </button>
          </div>
        )}

        <button
          onClick={() => navigate(`/cases/${caseId}/collections/${collectionId}/files`)}
          style={{ ...btn(false), color: 'var(--fl-accent)' }}
          title={t('collectionArtifacts.rawFilesHint', 'Ouvrir les fichiers sources de la collecte')}
        >
          <FolderOpen size={12} /> {t('collectionArtifacts.rawFiles', 'Fichiers sources')}
        </button>
      </div>

      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '10px 14px 0', padding: '8px 12px', borderRadius: 7, background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)', color: 'var(--fl-danger)', fontSize: 12, fontFamily: MONO, flexShrink: 0 }}>
          <AlertTriangle size={13} /> {error}
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        {/* Type sidebar */}
        <div style={{ width: 250, minWidth: 200, borderRight: '1px solid var(--fl-border)', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--fl-border2)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Database size={12} style={{ color: 'var(--fl-muted)' }} />
            <span style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600 }}>
              {t('collectionArtifacts.types', 'Types')}
            </span>
            <span style={{ flex: 1 }} />
            <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)' }}>{types.length}</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 4 }}>
            {typesLoading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: 32, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
                <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
              </div>
            ) : types.length === 0 ? (
              <div style={{ padding: 28, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 11 }}>
                {t('collectionArtifacts.noTypes', 'Aucune donnée parsée. Lancez un parsing.')}
              </div>
            ) : (
              types.map(x => {
                const c = artifactColor(x.artifact_type);
                const active = x.artifact_type === selected;
                return (
                  <button
                    key={x.artifact_type}
                    onClick={() => { setSelected(x.artifact_type); setViewMode('table'); setFilters({}); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left',
                      padding: '6px 10px', borderRadius: 6, cursor: 'pointer', border: 'none',
                      background: active ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
                      fontFamily: MONO, fontSize: 12,
                      color: active ? 'var(--fl-accent)' : 'var(--fl-text)',
                    }}
                    onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--fl-card)'; }}
                    onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0 }} />
                    <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{x.artifact_type}</span>
                    <span style={{ fontSize: 9.5, color: 'var(--fl-subtle)', fontFeatureSettings: '"tnum"', flexShrink: 0 }}>
                      {Number(x.cnt || 0).toLocaleString()}
                    </span>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Main panel */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {showTree ? (
            <ArtifactTree caseId={caseId} collectionId={collectionId} type={selected} />
          ) : (
            <>
              {/* Toolbar */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--fl-border2)', flexShrink: 0, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0, maxWidth: 640 }}>
                  <button onClick={() => { setScope('type'); setGlobalResults(null); }} style={toggleBtn(scope === 'type')} title={t('collectionArtifacts.scopeType', 'Filtrer uniquement le type affiché')}>
                    <Table2 size={11} /> {t('collectionArtifacts.scopeTypeShort', 'Type')}
                  </button>
                  <button onClick={() => setScope('all')} style={toggleBtn(scope === 'all')} title={t('collectionArtifacts.scopeAll', 'Chercher dans tous les types d’artefacts')}>
                    <FileSearch size={11} /> {t('collectionArtifacts.scopeAllShort', 'Tous')}
                  </button>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0,
                    background: 'var(--fl-card)', border: '1px solid var(--fl-border2)', borderRadius: 7, padding: '5px 9px',
                  }}>
                    <Search size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
                    <input
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                      onKeyDown={onSearchKey}
                      placeholder={scope === 'all'
                        ? t('collectionArtifacts.searchAllPlaceholder', 'Mot-clé / regex dans tous les artefacts…')
                        : t('collectionArtifacts.searchPlaceholder', 'Filtrer les lignes (desc, source, champs bruts)…')}
                      style={{ flex: 1, minWidth: 0, background: 'transparent', border: 'none', outline: 'none', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11.5 }}
                    />
                    <button onClick={() => setRegexMode(m => !m)} title={t('collectionArtifacts.regexToggle', 'Expression régulière')} style={toggleBtn(regexMode)}>
                      <Regex size={11} />
                    </button>
                    {search && (
                      <button onClick={() => { setSearch(''); setGlobalResults(null); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 2, flexShrink: 0 }}>
                        <X size={12} />
                      </button>
                    )}
                  </div>
                  {scope === 'all' && (
                    <button
                      onClick={runGlobalSearch}
                      disabled={globalSearching || !search.trim()}
                      style={{ ...btn(false), opacity: search.trim() ? 1 : 0.5, color: 'var(--fl-accent)' }}
                    >
                      {globalSearching ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={11} />}
                      {t('collectionArtifacts.go', 'OK')}
                    </button>
                  )}
                </div>
                {scope === 'type' && (
                  <>
                    <div ref={jumpRef} style={{ position: 'relative', flexShrink: 0 }}>
                      <button
                        onClick={() => { setJumpOpen(v => !v); setJumpErr(''); }}
                        title={t('collectionArtifacts.jumpHint', 'Aller à un timestamp précis pour voir les événements autour')}
                        style={{ ...btn(false), color: jumpOpen ? 'var(--fl-gold)' : 'var(--fl-dim)' }}
                      >
                        <Clock size={11} /> {t('collectionArtifacts.jump', 'Aller à…')}
                      </button>
                      {jumpOpen && (
                        <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 500, marginTop: 4,
                          background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 8,
                          padding: 14, width: 300, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
                          fontFamily: MONO, fontSize: 11, color: 'var(--fl-on-dark)',
                          display: 'flex', flexDirection: 'column', gap: 10 }}>
                          <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                            ⏱ {t('collectionArtifacts.jumpTitle', 'Aller à un timestamp')}
                          </span>
                          <input ref={jumpInputRef} value={jumpVal}
                            placeholder="2024-01-15 14:32:05"
                            onChange={e => { setJumpVal(e.target.value); setJumpErr(''); }}
                            onKeyDown={e => { if (e.key === 'Enter') doJump(); else if (e.key === 'Escape') setJumpOpen(false); }}
                            style={{ background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: `1px solid ${jumpErr ? 'var(--fl-danger)' : 'var(--fl-raised)'}`, borderRadius: 5, padding: '6px 8px', fontFamily: MONO, fontSize: 11, outline: 'none' }} />
                          <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <span style={{ fontSize: 9, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('collectionArtifacts.jumpWindow', 'Fenêtre autour')}</span>
                            <select value={jumpWindow} onChange={e => setJumpWindow(parseInt(e.target.value, 10))}
                              style={{ background: 'var(--fl-panel)', color: 'var(--fl-on-dark)', border: '1px solid var(--fl-raised)', borderRadius: 5, padding: '5px 8px', fontFamily: MONO, fontSize: 11, outline: 'none' }}>
                              <option value={1}>± 1 min</option>
                              <option value={5}>± 5 min</option>
                              <option value={15}>± 15 min</option>
                              <option value={60}>± 1 h</option>
                              <option value={360}>± 6 h</option>
                              <option value={1440}>± 24 h</option>
                            </select>
                          </label>
                          {jumpErr && <span style={{ fontSize: 10, color: 'var(--fl-danger)' }}>{jumpErr}</span>}
                          <div style={{ display: 'flex', gap: 6, paddingTop: 2, borderTop: '1px solid var(--fl-card)' }}>
                            <button onClick={doJump} disabled={!jumpVal.trim()}
                              style={{ flex: 1, padding: '5px', borderRadius: 5, background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-gold) 25%, transparent)', color: 'var(--fl-gold)', cursor: jumpVal.trim() ? 'pointer' : 'not-allowed', opacity: jumpVal.trim() ? 1 : 0.5, fontSize: 10, fontFamily: MONO }}>{t('collectionArtifacts.jumpGo', 'Aller')}</button>
                            <button onClick={() => { setJumpOpen(false); setJumpErr(''); }}
                              style={{ padding: '5px 10px', borderRadius: 5, background: 'transparent', border: '1px solid var(--fl-raised)', color: 'var(--fl-dim)', cursor: 'pointer', fontSize: 10, fontFamily: MONO }}>{t('collectionArtifacts.jumpClose', 'Fermer')}</button>
                          </div>
                        </div>
                      )}
                    </div>
                    <button onClick={() => setSortDir(d => d === 'asc' ? 'desc' : 'asc')} style={btn(false)} title={t('collectionArtifacts.sortToggle', 'Inverser le tri chronologique')}>
                      <ArrowUpDown size={11} /> {sortDir === 'asc' ? t('collectionArtifacts.asc', 'ASC') : t('collectionArtifacts.desc', 'DESC')}
                    </button>
                    <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)', flexShrink: 0 }}>
                      {t('collectionArtifacts.page', 'page')} {page}/{totalPages}
                    </span>
                    <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} style={btn(page <= 1)}>
                      <ChevronLeft size={12} />
                    </button>
                    <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages} style={btn(page >= totalPages)}>
                      <ChevronRight size={12} />
                    </button>
                  </>
                )}
              </div>

              {/* Active time window (jump-to-timestamp) */}
              {scope === 'type' && (timeStart || timeEnd) && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px', borderBottom: '1px solid var(--fl-border2)', flexShrink: 0, flexWrap: 'wrap' }}>
                  <Clock size={12} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} />
                  {timeStart && (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: MONO, background: '#1a1808', color: 'var(--fl-gold)', border: '1px solid #3a3010' }}>
                      after:{fmtTs(timeStart)}
                      <button onClick={() => { setTimeStart(''); setPage(1); }} title={t('collectionArtifacts.removeTime', 'Retirer')} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, display: 'inline-flex' }}><X size={10} /></button>
                    </span>
                  )}
                  {timeEnd && (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: MONO, background: '#1a1808', color: 'var(--fl-gold)', border: '1px solid #3a3010' }}>
                      before:{fmtTs(timeEnd)}
                      <button onClick={() => { setTimeEnd(''); setPage(1); }} title={t('collectionArtifacts.removeTime', 'Retirer')} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, display: 'inline-flex' }}><X size={10} /></button>
                    </span>
                  )}
                  <button onClick={() => { setTimeStart(''); setTimeEnd(''); setPage(1); }} style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', fontFamily: MONO, fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <X size={10} /> {t('collectionArtifacts.clearTime', 'clear')}
                  </button>
                </div>
              )}

              {scope === 'all' ? (
                <GlobalArtifactSearchPanel results={globalResults} searching={globalSearching} error={globalErr} onOpenType={openGlobalResultType} />
              ) : (
              <>
              {/* EVTX filters */}
              {selected === 'evtx' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px', borderBottom: '1px solid var(--fl-border2)', flexShrink: 0, flexWrap: 'wrap', background: 'var(--fl-card)' }}>
                  <Filter size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />

                  {/* Event ID (comma-separated) */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)', borderRadius: 6, padding: '4px 8px', minWidth: 150 }}>
                    <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', flexShrink: 0 }}>Event ID</span>
                    <input
                      value={filters.EventId || ''}
                      onChange={e => setFilter('EventId', e.target.value)}
                      placeholder="4624,4625…"
                      style={{ flex: 1, minWidth: 70, background: 'transparent', border: 'none', outline: 'none', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11 }}
                    />
                  </div>

                  {/* Facet dropdowns */}
                  {['Channel', 'Level', 'Computer', 'Provider'].map(col => (
                    <div key={col} style={{ position: 'relative', flexShrink: 0 }}>
                      <select
                        value={filters[col] || ''}
                        onChange={e => setFilter(col, e.target.value)}
                        style={{
                          background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)', borderRadius: 6,
                          color: filters[col] ? 'var(--fl-accent)' : 'var(--fl-dim)', fontFamily: MONO, fontSize: 11,
                          padding: '4px 22px 4px 8px', cursor: 'pointer', outline: 'none', maxWidth: 200,
                        }}
                        title={col}
                      >
                        <option value="">{col}</option>
                        {(facets[col] || []).map(f => (
                          <option key={f.value} value={f.value}>{f.value} · {f.cnt}</option>
                        ))}
                      </select>
                    </div>
                  ))}

                  {facetsLoading && <Loader2 size={12} style={{ animation: 'spin 1s linear infinite', color: 'var(--fl-dim)', flexShrink: 0 }} />}

                  {activeFilterCount > 0 && (
                    <button
                      onClick={clearFilters}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 8px', borderRadius: 6, cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 24%, transparent)', fontFamily: MONO, fontSize: 10.5, flexShrink: 0 }}
                      title={t('collectionArtifacts.clearFilters', 'Effacer les filtres')}
                    >
                      <X size={11} /> {activeFilterCount}
                    </button>
                  )}

                  {activeFilterCount > 0 && (
                    <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-accent)', flexShrink: 0 }}>
                      {total.toLocaleString()} {t('collectionArtifacts.rows', 'ligne(s)')}
                    </span>
                  )}
                </div>
              )}

              {/* Table */}
              <div style={{ flex: 1, overflow: 'auto', background: 'var(--fl-bg)' }}>
                {loading ? (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: 48, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
                    <Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
                  </div>
                ) : records.length === 0 ? (
                  <div style={{ padding: 40, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12 }}>
                    <FileText size={28} style={{ color: 'var(--fl-border3)', margin: '0 auto 10px' }} />
                    {(debounced || activeFilterCount > 0) ? t('collectionArtifacts.noRowsFilter', 'Aucune ligne ne correspond.') : t('collectionArtifacts.noRows', 'Aucune donnée pour ce type.')}
                  </div>
                ) : (
                  <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 700, fontFamily: MONO, fontSize: 11 }}>
                    <thead>
                      <tr style={{ position: 'sticky', top: 0, background: 'var(--fl-panel)', zIndex: 2 }}>
                        <th style={th} />
                        {BASE_COLS.map(b => <th key={b.key} style={{ ...th, minWidth: b.w }}>{b.label}</th>)}
                        {tableColumns.map(c => <th key={c} style={{ ...th, minWidth: 140 }}>{c}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {records.map(r => {
                        const open = expanded === r.id;
                        return (
                          <Fragment key={r.id}>
                            <tr
                              onClick={() => setExpanded(open ? null : r.id)}
                              style={{ cursor: 'pointer', borderBottom: '1px solid color-mix(in srgb, var(--fl-border) 45%, transparent)', background: open ? 'color-mix(in srgb, var(--fl-accent) 5%, transparent)' : 'transparent' }}
                            >
                              <td style={td}><ChevronRightSm size={12} style={{ transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.1s', color: 'var(--fl-muted)' }} /></td>
                              <td style={{ ...td, whiteSpace: 'nowrap', color: 'var(--fl-accent)' }}>{fmtTs(r.timestamp)}</td>
                              <td style={{ ...td, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={cell(r.description)}>{cell(r.description)}</td>
                              <td style={{ ...td, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={cell(r.source)}>{cell(r.source)}</td>
                              {tableColumns.map(c => (
                                <td key={c} style={{ ...td, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={cell(r.raw?.[c])}>{cell(r.raw?.[c])}</td>
                              ))}
                            </tr>
                            {open && (
                              <tr>
                                <td colSpan={BASE_COLS.length + tableColumns.length + 1} style={{ background: 'var(--fl-card)', borderBottom: '1px solid var(--fl-border)' }}>
                                  <RowDetail r={r} extraHidden={extraCount} />
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const th = {
  textAlign: 'left', padding: '6px 8px', fontSize: 9.5, color: 'var(--fl-muted)',
  textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 700,
  borderBottom: '1px solid var(--fl-border)', whiteSpace: 'nowrap',
};
const td = {
  padding: '5px 8px', color: 'var(--fl-text)', verticalAlign: 'top', whiteSpace: 'nowrap',
};

function RowDetail({ r, extraHidden = 0 }) {
  const { t } = useTranslation();
  const meta = [
    ['artifact_type', r.artifact_type],
    ['host_name', r.host_name],
    ['user_name', r.user_name],
    ['process_name', r.process_name],
    ['path', r.path],
    ['ext', r.ext],
    ['event_id', r.event_id],
    ['file_size', r.file_size ? `${r.file_size} (${fmtSize(r.file_size)})` : ''],
    ['src_ip', r.src_ip],
    ['dst_ip', r.dst_ip],
    ['sha1', r.sha1],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '');
  const rawEntries = r.raw && typeof r.raw === 'object'
    ? Object.entries(r.raw).sort(([a], [b]) => a.localeCompare(b))
    : [];

  return (
    <div style={{ padding: '10px 12px' }}>
      {r.details ? (
        <div style={{ marginBottom: 10, border: '1px solid var(--fl-border2)', borderRadius: 6, background: 'var(--fl-bg)', overflow: 'hidden' }}>
          <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-gold)', padding: '4px 8px', borderBottom: '1px solid var(--fl-border2)' }}>
            {t('collectionArtifacts.payload', 'Payload')}
          </div>
          <div style={{ padding: '6px 8px', fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300, overflowY: 'auto' }}>
            {r.details}
          </div>
        </div>
      ) : null}
      {meta.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '4px 18px', marginBottom: 10 }}>
          {meta.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: 8, fontFamily: MONO, fontSize: 11 }}>
              <span style={{ color: 'var(--fl-muted)', flexShrink: 0 }}>{k}</span>
              <span style={{ color: 'var(--fl-text)', wordBreak: 'break-all' }}>{cell(v)}</span>
            </div>
          ))}
        </div>
      )}
      <div style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
        {t('collectionArtifacts.rawFields', 'Champs bruts du parser')}
        {extraHidden > 0 && <span style={{ color: 'var(--fl-subtle)', textTransform: 'none', letterSpacing: 0 }}> · {extraHidden} {t('collectionArtifacts.extraHidden', 'non affiché(s) dans le tableau')}</span>}
      </div>
      {rawEntries.length === 0 ? (
        <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-dim)' }}>—</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '4px 18px' }}>
          {rawEntries.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: 8, fontFamily: MONO, fontSize: 11, alignItems: 'flex-start' }}>
              <span style={{ color: 'var(--fl-accent)', flexShrink: 0 }}>{k}</span>
              <span style={{ color: 'var(--fl-text)', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{cell(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Cross-type search results — mirror of the files browser "Tous" scope.
function GlobalArtifactSearchPanel({ results, searching, error, onOpenType }) {
  const { t } = useTranslation();
  if (searching) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: 48, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
        <Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} /> {t('collectionArtifacts.searchingAll', 'Recherche dans tous les artefacts…')}
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', color: 'var(--fl-danger)', fontFamily: MONO, fontSize: 12 }}>
        <AlertTriangle size={13} /> {error}
      </div>
    );
  }
  if (!results) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12 }}>
        <Search size={28} style={{ color: 'var(--fl-border3)', margin: '0 auto 10px' }} />
        {t('collectionArtifacts.searchAllHint', 'Saisissez un mot-clé ou une regex puis validez pour chercher dans tous les types d’artefacts.')}
      </div>
    );
  }
  if (!results.total) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12 }}>
        {t('collectionArtifacts.noGlobalMatch', 'Aucune correspondance trouvée.')}
      </div>
    );
  }
  const byType = new Map();
  for (const r of results.records || []) {
    if (!byType.has(r.artifact_type)) byType.set(r.artifact_type, []);
    byType.get(r.artifact_type).push(r);
  }
  return (
    <div style={{ padding: '10px 14px 24px', overflow: 'auto', flex: 1 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
          {t('collectionArtifacts.searchResults', 'Résultats')}
        </span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-ok)', fontWeight: 700 }}>
          {results.total.toLocaleString()} {t('collectionArtifacts.rows', 'ligne(s)')} · {results.types.length} types
        </span>
        {results.truncated && <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-gold)' }}>{t('collectionArtifacts.truncated', 'tronqué')}</span>}
        {results.regex && <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-accent)' }}>regex</span>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {results.types.map(tp => {
          const rows = byType.get(tp.artifact_type) || [];
          const c = artifactColor(tp.artifact_type);
          return (
            <div key={tp.artifact_type} style={{ border: '1px solid var(--fl-border2)', borderRadius: 7, overflow: 'hidden', background: 'var(--fl-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px', background: 'var(--fl-panel)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0 }} />
                <span style={{ fontFamily: MONO, fontSize: 12, color: 'var(--fl-text)', fontWeight: 600 }}>{tp.artifact_type}</span>
                <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' }}>{tp.cnt.toLocaleString()} {t('collectionArtifacts.rows', 'ligne(s)')}</span>
                <span style={{ flex: 1 }} />
                <button
                  onClick={() => onOpenType(tp.artifact_type)}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 9px', borderRadius: 6, cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 22%, transparent)', fontFamily: MONO, fontSize: 10.5, flexShrink: 0 }}
                >
                  {t('collectionArtifacts.seeAll', 'Voir dans le tableau')}
                </button>
              </div>
              {rows.length === 0 ? (
                <div style={{ padding: '6px 12px', fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-dim)' }}>
                  {t('collectionArtifacts.sampleTruncated', '— aperçu tronqué, ouvrez le type pour tout voir —')}
                </div>
              ) : (
                rows.map(r => (
                  <div key={r.id} style={{ display: 'flex', gap: 12, padding: '5px 12px', borderTop: '1px solid var(--fl-border2)', fontFamily: MONO, fontSize: 11, alignItems: 'flex-start' }}>
                    <span style={{ color: 'var(--fl-accent)', whiteSpace: 'nowrap', flexShrink: 0, lineHeight: '16px' }}>{fmtTs(r.timestamp)}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: '16px' }} title={cell(r.description)}>{cell(r.description)}</div>
                      {r.details && (
                        <div style={{ color: 'var(--fl-muted)', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: '15px' }} title={cell(r.details)}>{cell(r.details)}</div>
                      )}
                    </div>
                    <span style={{ color: 'var(--fl-subtle)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0, lineHeight: '16px' }} title={cell(r.source)}>{cell(r.source)}</span>
                  </div>
                ))
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Generic artifact tree (registry hives, $MFT, shellbags) ────────────────
// One component for every tree-capable type: group selector (hives / users),
// debounced search that prunes the tree server-side, lazy rendering of nodes.
function ArtifactTree({ caseId, collectionId, type }) {
  const { t } = useTranslation();
  const [groups, setGroups] = useState([]);
  const [needsGroup, setNeedsGroup] = useState(null); // null = unknown until groups load
  const [group, setGroup] = useState('');
  const [groupsLoading, setGroupsLoading] = useState(true);
  const [tree, setTree] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');

  useEffect(() => {
    const h = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(h);
  }, [search]);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    setGroupsLoading(true);
    collectionAPI.artifactGroups(caseId, type, { evidence_id: collectionId })
      .then(r => {
        const g = r.data?.groups || [];
        setNeedsGroup(!!r.data?.needs_group);
        setGroups(g);
        if (g.length && !group) setGroup(g[0].group);
      })
      .catch(() => { setGroups([]); setNeedsGroup(false); })
      .finally(() => setGroupsLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, collectionId, type]);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    if (needsGroup === null) return; // wait until groups are known
    if (needsGroup && !group) return; // wait for auto-select
    setLoading(true);
    setError('');
    setTree(null);
    setExpanded(new Set());
    collectionAPI.artifactTree(caseId, type, {
      evidence_id: collectionId,
      ...(group ? { group } : {}),
      ...(debounced ? { search: debounced } : {}),
    })
      .then(r => setTree(r.data))
      .catch(e => setError(e.response?.data?.error || e.message))
      .finally(() => setLoading(false));
  }, [caseId, collectionId, type, group, needsGroup, debounced]);

  const toggle = (path) => setExpanded(prev => {
    const n = new Set(prev);
    if (n.has(path)) n.delete(path);
    else n.add(path);
    return n;
  });

  const isRegistry = type === 'registry';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      {/* Group selector + search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', borderBottom: '1px solid var(--fl-border2)', flexShrink: 0, flexWrap: 'wrap' }}>
        <FolderOpen size={13} style={{ color: 'var(--fl-pink)', flexShrink: 0 }} />
        {needsGroup === false ? null : groupsLoading ? (
          <Loader2 size={13} style={{ animation: 'spin 1s linear infinite', color: 'var(--fl-dim)' }} />
        ) : groups.length === 0 ? (
          <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-muted)' }}>
            {t('collectionArtifacts.noGroups', 'Aucun groupe parsé.')}
          </span>
        ) : (
          groups.map(g => {
            const active = g.group === group;
            return (
              <button
                key={g.group}
                onClick={() => setGroup(g.group)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6,
                  cursor: 'pointer', flexShrink: 0, fontFamily: MONO, fontSize: 11,
                  background: active ? 'color-mix(in srgb, var(--fl-pink) 12%, transparent)' : 'var(--fl-card)',
                  color: active ? 'var(--fl-pink)' : 'var(--fl-dim)',
                  border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-pink) 30%, transparent)' : 'var(--fl-border2)'}`,
                }}
              >
                {g.group}
                <span style={{ fontSize: 9, color: active ? 'var(--fl-pink)' : 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>
                  {Number(g.key_count || 0).toLocaleString()} {t('collectionArtifacts.keys', 'clés')}
                </span>
              </button>
            );
          })
        )}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 140, maxWidth: 300,
          background: 'var(--fl-card)', border: '1px solid var(--fl-border2)', borderRadius: 7, padding: '4px 8px',
        }}>
          <Search size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('collectionArtifacts.treeSearch', 'Rechercher dans l\'arbre…')}
            style={{ flex: 1, minWidth: 0, background: 'transparent', border: 'none', outline: 'none', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11 }}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 2, flexShrink: 0 }}>
              <X size={11} />
            </button>
          )}
        </div>
        <span style={{ flex: 1 }} />
        {tree && !loading && (
          <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)', flexShrink: 0 }}>
            {Number(tree.value_count || 0).toLocaleString()} {t('collectionArtifacts.values', 'valeurs')}
            {debounced && <span style={{ color: 'var(--fl-accent)' }}> · {t('collectionArtifacts.filtered', 'filtré')}</span>}
            {tree.truncated ? ' · ' + t('collectionArtifacts.truncated', 'tronqué') : ''}
          </span>
        )}
      </div>

      {/* Tree */}
      <div style={{ flex: 1, overflow: 'auto', padding: '6px 0', background: 'var(--fl-bg)' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: 48, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
            <Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
          </div>
        ) : error ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', color: 'var(--fl-danger)', fontFamily: MONO, fontSize: 12 }}>
            <AlertTriangle size={13} /> {error}
          </div>
        ) : !tree ? null : tree.roots.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12 }}>
            {debounced
              ? t('collectionArtifacts.noTreeMatch', 'Aucun résultat dans l\'arbre.')
              : t('collectionArtifacts.noKeys', isRegistry ? 'Aucune clé dans ce hive.' : 'Aucune donnée.')}
          </div>
        ) : (
          tree.roots.map(r => (
            <TreeNode key={r.name} node={r} path={r.name} depth={0} expanded={expanded} onToggle={toggle} type={type} />
          ))
        )}
      </div>
    </div>
  );
}

function TreeNode({ node, path, depth, expanded, onToggle, type }) {
  const hasKids = node.children && node.children.length > 0;
  const hasValues = node.values && node.values.length > 0;
  const expandable = hasKids || hasValues;
  const open = expanded.has(path);
  return (
    <div>
      <div
        onClick={() => expandable && onToggle(path)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '3px 10px',
          paddingLeft: 10 + depth * 16, cursor: expandable ? 'pointer' : 'default', borderRadius: 5,
        }}
        onMouseEnter={e => { if (expandable) e.currentTarget.style.background = 'var(--fl-card)'; }}
        onMouseLeave={e => { if (expandable) e.currentTarget.style.background = 'transparent'; }}
      >
        {expandable
          ? (open ? <ChevronDown size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} /> : <ChevronRightSm size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />)
          : <span style={{ width: 12, flexShrink: 0 }} />}
        {open ? <FolderOpen size={13} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} /> : <Folder size={13} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />}
        <span style={{ fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-text)' }}>{node.name}</span>
        {hasKids && <span style={{ fontFamily: MONO, fontSize: 9, color: 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>{node.children.length}</span>}
        {hasValues && <span style={{ fontFamily: MONO, fontSize: 9, color: 'var(--fl-gold)', fontFeatureSettings: '"tnum"' }}>{node.values.length} {type === 'registry' ? 'valeur(s)' : 'entrée(s)'}</span>}
      </div>
      {open && (
        <div>
          {node.values.map((v, i) => <TreeValue key={i} v={v} depth={depth + 1} type={type} />)}
          {node.children.map(c => (
            <TreeNode key={c.name} node={c} path={`${path}\\${c.name}`} depth={depth + 1} expanded={expanded} onToggle={onToggle} type={type} />
          ))}
        </div>
      )}
    </div>
  );
}

function TreeValue({ v, depth, type }) {
  return (
    <div style={{ display: 'flex', gap: 10, padding: '2px 10px', paddingLeft: 10 + (depth + 1) * 16, fontFamily: MONO, fontSize: 11, alignItems: 'baseline' }}>
      <span style={{ color: 'var(--fl-gold)', minWidth: 140, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }} title={cell(v.name)}>
        {cell(v.name) || (type === 'registry' ? '(défaut)' : '(—)')}
      </span>
      {v.type && <span style={{ color: 'var(--fl-subtle)', width: 78, flexShrink: 0, fontSize: 9.5 }}>{cell(v.type)}</span>}
      {v.size != null && <span style={{ color: 'var(--fl-subtle)', width: 70, flexShrink: 0, fontSize: 9.5 }}>{fmtSize(v.size)}</span>}
      <span style={{ color: 'var(--fl-text)', wordBreak: 'break-all', whiteSpace: 'pre-wrap', flex: 1 }}>{cell(v.data ?? v.description)}</span>
    </div>
  );
}
