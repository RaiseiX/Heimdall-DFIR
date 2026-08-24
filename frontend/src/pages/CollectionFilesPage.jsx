import { useState, useEffect, useCallback, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  FolderOpen, FileText, FileCode2, CornerLeftUp, ChevronRight,
  Download, Loader2, RefreshCw, AlertTriangle, HardDrive,
  Search, FileSearch, Regex, X, ArrowUp, ArrowDown, CornerDownRight, Archive,
  Copy, Check, KeyRound,
} from 'lucide-react';
import { collectionAPI } from '../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const MAX_INLINE_LINES = 20000; // above this, in-file search renders only matching lines + context

function fmtSize(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, n = Number(b);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function isTextLike(name) {
  return /\.(txt|log|csv|json|xml|yml|yaml|html?|js|ts|jsx|tsx|py|sh|bat|ps1|ini|conf|cfg|md|sql|evt|kape|properties|map)$/i.test(name);
}

// Registry hive files that the browser can open (Windows registry hives are
// binary but structured; RECmd's batch only extracts a curated subset of keys,
// so browsing the raw hive exposes the rest). Also accept transaction-log
// companions (SYSTEM.LOG1/2, NTUSER.DAT.LOG1/2) — dissect.regf reads them.
function isHiveFile(name) {
  const base = (name || '').toLowerCase();
  const stem = base.replace(/(\.(log[12]?|alt|txr))?$/, '');
  return /^(ntuser|usrclass)(\.dat)?$/.test(stem)
    || /^(system|software|sam|security|default|components|drivers|bcd|schema)$/.test(stem);
}

function formatHexDump(hex, ascii) {
  const rows = [];
  const n = ascii ? ascii.length : Math.floor(hex.length / 2);
  for (let i = 0; i < n; i += 16) {
    const h = (hex.slice(i * 2, i * 2 + 32).match(/.{1,2}/g) || []).join(' ').padEnd(47, ' ');
    rows.push({ offset: i, hex: h, ascii: (ascii || '').slice(i, i + 16) });
  }
  return rows;
}

// Split a line into [plain, hit, plain, hit…] segments for a compiled regex.
function splitMatches(text, re) {
  const parts = [];
  let last = 0;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push({ text: text.slice(last, m.index), hit: false });
    parts.push({ text: m[0], hit: true });
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++; // guard against zero-width infinite loops
  }
  if (last < text.length) parts.push({ text: text.slice(last), hit: false });
  re.lastIndex = 0;
  return parts;
}

const MARK_STYLE = {
  background: 'color-mix(in srgb, var(--fl-gold) 38%, transparent)',
  color: 'var(--fl-text)',
  borderRadius: 2,
  padding: '0 1px',
};

// Regedit-style hive browser: breadcrumb navigation, jump-to-path, recursive
// search and a two-pane layout (subkeys | values). Clicking a subkey navigates
// INTO it (instead of a deep, hard-to-scan tree), so analysts walk a hive the
// same way they browse folders.
function HiveBrowser({
  t, entry, node, loading, error,
  search, onSearch, searching, searchRes, searchErr, onOpenResult,
  pathDraft, onPathDraft, onJump,
  onNavigate, onCopy, copied,
}) {
  const path = node?.path || '';
  const crumbs = ['', ...(path ? path.split('\\') : [])];
  const activeSearch = Boolean(search.trim());

  const rowStyle = {
    display: 'flex', alignItems: 'center', gap: 6, width: '100%', textAlign: 'left',
    padding: '3px 10px', background: 'transparent', border: 'none', cursor: 'pointer',
    fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-text)', borderRadius: 0,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* Toolbar: breadcrumb + copy path + jump + search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap' }}>
        <HardDrive size={13} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} />

        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', minWidth: 0 }}>
          {crumbs.map((seg, i) => {
            const isLast = i === crumbs.length - 1;
            const segPath = i === 0 ? '' : crumbs.slice(1, i + 1).join('\\');
            const label = i === 0 ? (entry?.name || 'hive') : seg;
            return (
              <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                {i > 0 && <span style={{ color: 'var(--fl-muted)', fontSize: 11 }}>\</span>}
                <button
                  onClick={() => !isLast && onNavigate(segPath)}
                  disabled={isLast}
                  title={segPath || (entry?.name || 'hive')}
                  style={{
                    background: 'none', border: 'none', cursor: isLast ? 'default' : 'pointer',
                    color: isLast ? 'var(--fl-accent)' : 'var(--fl-text)', fontFamily: MONO,
                    fontSize: 11, padding: '2px 4px', borderRadius: 4, maxWidth: 220,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}
                  onMouseEnter={e => { if (!isLast) e.currentTarget.style.background = 'var(--fl-card)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
                >
                  {label}
                </button>
              </span>
            );
          })}
        </div>

        <button
          onClick={() => onCopy(path, 'path')}
          title={t('collectionFiles.copyPath', 'Copier le chemin')}
          style={{ display: 'inline-flex', alignItems: 'center', padding: '3px 7px', borderRadius: 5, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', flexShrink: 0 }}
        >
          {copied === 'path' ? <Check size={12} style={{ color: 'var(--fl-success)' }} /> : <Copy size={12} />}
        </button>

        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginLeft: 'auto', flexWrap: 'wrap' }}>
          <form onSubmit={e => { e.preventDefault(); onJump(); }} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <input
              value={pathDraft}
              onChange={e => onPathDraft(e.target.value)}
              placeholder={t('collectionFiles.hiveJump', 'Chemin…')}
              style={{ width: 190, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 5, color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, padding: '4px 8px' }}
            />
            <button type="submit" style={{ padding: '4px 9px', borderRadius: 5, cursor: 'pointer', background: 'var(--fl-accent)', color: 'var(--fl-bg)', border: 'none', fontFamily: MONO, fontSize: 11, fontWeight: 600 }}>
              {t('collectionFiles.go', 'Go')}
            </button>
          </form>

          <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
            <Search size={12} style={{ position: 'absolute', left: 7, color: 'var(--fl-muted)', pointerEvents: 'none' }} />
            <input
              value={search}
              onChange={e => onSearch(e.target.value)}
              placeholder={t('collectionFiles.hiveSearch', 'Rechercher clé / valeur…')}
              style={{ width: 200, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 5, color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, padding: '4px 24px' }}
            />
            {searching ? (
              <Loader2 size={12} style={{ position: 'absolute', right: 7, color: 'var(--fl-muted)', animation: 'spin 1s linear infinite' }} />
            ) : search ? (
              <button onClick={() => onSearch('')} style={{ position: 'absolute', right: 5, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 0 }}>
                <X size={12} />
              </button>
            ) : null}
          </div>
        </div>
      </div>

      {/* Body: search results or two panes */}
      <div style={{ flex: 1, minHeight: 0, display: 'flex', overflow: 'hidden' }}>
        {activeSearch ? (
          <HiveSearchResults t={t} searching={searching} searchRes={searchRes} searchErr={searchErr} onOpenResult={onOpenResult} />
        ) : loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: 40, color: 'var(--fl-dim)', fontSize: 12, width: '100%' }}>
            <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
          </div>
        ) : error ? (
          <div style={{ padding: 20, color: 'var(--fl-danger)', width: '100%' }}>{error}</div>
        ) : node ? (
          <>
            {/* Subkeys pane */}
            <div style={{ width: '42%', minWidth: 220, borderRight: '1px solid var(--fl-border)', overflowY: 'auto', overflowX: 'hidden' }}>
              <div style={{ padding: '6px 10px', fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', borderBottom: '1px solid var(--fl-border2)', position: 'sticky', top: 0, background: 'var(--fl-bg)', zIndex: 1 }}>
                {t('collectionFiles.subkeys', 'Sous-clés')} ({node.subkeys?.length ?? 0}{node.subkeysTruncated ? '+' : ''})
              </div>
              {(node.subkeys || []).length === 0 ? (
                <div style={{ padding: '10px 12px', color: 'var(--fl-muted)', fontSize: 11 }}>{t('collectionFiles.noSubkeys', 'Aucune sous-clé')}</div>
              ) : node.subkeys.map(sk => (
                <button
                  key={sk.path}
                  onClick={() => onNavigate(sk.path)}
                  style={rowStyle}
                  title={sk.lastWrite || undefined}
                  onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                >
                  <FolderOpen size={12} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sk.name}</span>
                  {sk.subkeyCount > 0 && <span style={{ color: 'var(--fl-subtle)', fontSize: 9.5, flexShrink: 0 }}>{sk.subkeyCount}</span>}
                </button>
              ))}
            </div>

            {/* Values pane */}
            <div style={{ flex: 1, minWidth: 0, overflowY: 'auto', overflowX: 'hidden' }}>
              <div style={{ padding: '6px 10px', fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', borderBottom: '1px solid var(--fl-border2)', position: 'sticky', top: 0, background: 'var(--fl-bg)', zIndex: 1 }}>
                {t('collectionFiles.values', 'Valeurs')} ({node.values?.length ?? 0}{node.valuesTruncated ? '+' : ''})
              </div>
              {(node.values || []).length === 0 ? (
                <div style={{ padding: '10px 12px', color: 'var(--fl-muted)', fontSize: 11 }}>{t('collectionFiles.noValues', 'Aucune valeur')}</div>
              ) : node.values.map((v, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '4px 10px', borderBottom: '1px solid var(--fl-border2)' }}>
                  <span style={{ color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, minWidth: 90, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }} title={v.name}>{v.name || '(Default)'}</span>
                  <span style={{ color: 'var(--fl-accent)', fontFamily: MONO, fontSize: 9.5, minWidth: 64, flexShrink: 0, paddingTop: 1 }}>{v.type}</span>
                  <span style={{ color: v.binary ? 'var(--fl-subtle)' : 'var(--fl-text)', fontFamily: MONO, fontSize: 11, flex: 1, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                    {v.data ?? ''}{v.truncated ? ' …' : ''}
                  </span>
                  <button
                    onClick={() => onCopy(v.data ?? '', `v-${i}`)}
                    title={t('collectionFiles.copyValue', 'Copier la valeur')}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 2, flexShrink: 0 }}
                  >
                    {copied === `v-${i}` ? <Check size={12} style={{ color: 'var(--fl-success)' }} /> : <Copy size={12} />}
                  </button>
                </div>
              ))}
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}

function HiveSearchResults({ t, searching, searchRes, searchErr, onOpenResult }) {
  const matches = searchRes?.matches || [];
  if (searching && matches.length === 0 && !searchErr) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: 40, color: 'var(--fl-dim)', fontSize: 12, width: '100%' }}>
        <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
      </div>
    );
  }
  if (searchErr) {
    return <div style={{ padding: 20, color: 'var(--fl-danger)', width: '100%' }}>{searchErr}</div>;
  }
  if (!searching && matches.length === 0) {
    return <div style={{ padding: 20, color: 'var(--fl-muted)', width: '100%', fontSize: 11.5 }}>{t('collectionFiles.noHiveResults', 'Aucun résultat')}</div>;
  }
  return (
    <div style={{ flex: 1, minWidth: 0, overflowY: 'auto' }}>
      <div style={{ padding: '6px 10px', fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', borderBottom: '1px solid var(--fl-border2)', position: 'sticky', top: 0, background: 'var(--fl-bg)', zIndex: 1 }}>
        {t('collectionFiles.hiveResults', 'Résultats')} ({matches.length}{searchRes?.truncated ? '+' : ''})
      </div>
      {matches.map((m, i) => (
        <button
          key={i}
          onClick={() => onOpenResult(m)}
          style={{ display: 'flex', alignItems: 'baseline', gap: 8, width: '100%', textAlign: 'left', padding: '4px 10px', background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-text)', borderBottom: '1px solid var(--fl-border2)' }}
          onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
        >
          {m.kind === 'key' ? <FolderOpen size={12} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} /> : <KeyRound size={12} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} />}
          <span style={{ color: 'var(--fl-accent)', flexShrink: 0 }}>{m.name}</span>
          <span style={{ color: 'var(--fl-subtle)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.path}</span>
          {m.snippet ? <span style={{ color: 'var(--fl-muted)', fontSize: 10, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.snippet}</span> : null}
        </button>
      ))}
    </div>
  );
}

export default function CollectionFilesPage() {
  const { t } = useTranslation();
  const ctx = useOutletContext() || {};
  const caseId = ctx.caseId;
  const collectionId = ctx.collectionId;

  const [cwd, setCwd] = useState('');
  const [entries, setEntries] = useState([]);
  const [parent, setParent] = useState(null);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [selected, setSelected] = useState(null);   // entry object { path, type, name, size }
  const [content, setContent] = useState(null);     // backend /file/content payload
  const [contentLoading, setContentLoading] = useState(false);

  // Registry hive browser state (open a hive from the Files view and walk keys).
  const [hiveView, setHiveView] = useState(false);      // true → show hive browser instead of hex preview
  const [hiveNode, setHiveNode] = useState(null);       // current key { path, name, lastWrite, values, subkeys, … }
  const [hiveLoading, setHiveLoading] = useState(false);
  const [hiveErr, setHiveErr] = useState('');
  const [hiveCopied, setHiveCopied] = useState('');     // id of the just-copied value/path (check feedback)
  const [hiveSearch, setHiveSearch] = useState('');     // recursive search term (backend)
  const [hiveSearching, setHiveSearching] = useState(false);
  const [hiveSearchRes, setHiveSearchRes] = useState(null); // { matches, truncated }
  const [hiveSearchErr, setHiveSearchErr] = useState('');
  const [hivePathDraft, setHivePathDraft] = useState('');   // jump-to-path input

  // Search state: scope 'file' = highlight within the open text file (client-side),
  // scope 'all' = keyword/regex across every text file in the collection (backend).
  const [query, setQuery] = useState('');
  const [scope, setScope] = useState('file');
  const [regexMode, setRegexMode] = useState(false);
  const [results, setResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState('');
  const [activeMatch, setActiveMatch] = useState(0);
  const [expandedResult, setExpandedResult] = useState(null);

  // Client-side filename filter applied to the current directory listing.
  const [nameFilter, setNameFilter] = useState('');

  // Export of the recovered MFT resident files (ZIP download).
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async (path) => {
    if (!caseId || !collectionId) return;
    setLoading(true);
    setError('');
    try {
      const res = await collectionAPI.files(caseId, { evidence_id: collectionId, path: path || '' });
      setEntries(res.data.entries || []);
      setParent(res.data.parent ?? null);
      setTruncated(!!res.data.truncated);
      setCwd(res.data.path || '');
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to list collection files');
    } finally {
      setLoading(false);
    }
  }, [caseId, collectionId]);

  useEffect(() => { load(''); }, [load]);

  const openEntry = (entry) => {
    if (entry.type === 'dir') { setSelected(null); setContent(null); setHiveView(false); load(entry.path); }
    else { setSelected(entry); setContent(null); setHiveView(false); setHiveNode(null); setHiveSearch(''); setHiveSearchRes(null); loadContent(entry); }
  };

  const loadContent = async (entry) => {
    setContentLoading(true);
    try {
      const res = await collectionAPI.fileContent(caseId, { evidence_id: collectionId, path: entry.path });
      setContent(res.data);
    } catch (e) {
      setContent({ error: e.response?.data?.error || e.message || 'Failed to read file' });
    } finally {
      setContentLoading(false);
    }
  };

  const loadHive = async (entry, keyPath) => {
    setHiveLoading(true);
    setHiveErr('');
    try {
      const res = await collectionAPI.fileHive(caseId, { evidence_id: collectionId, path: entry.path, key: keyPath || '' });
      setHiveNode(res.data);
    } catch (e) {
      setHiveErr(e.response?.data?.error || e.message || 'Failed to browse hive');
    } finally {
      setHiveLoading(false);
    }
  };

  const navigateHive = (keyPath) => {
    setHiveSearch('');
    setHiveSearchRes(null);
    setHiveSearchErr('');
    setHivePathDraft('');
    if (selected) loadHive(selected, keyPath);
  };

  const jumpHive = () => {
    const raw = hivePathDraft.trim();
    if (!raw) return;
    navigateHive(raw.replace(/\\+/g, '\\').replace(/^\\+|\\+$/g, ''));
  };

  const copyHiveText = async (text, id) => {
    try {
      await navigator.clipboard.writeText(String(text ?? ''));
      setHiveCopied(id);
      setTimeout(() => setHiveCopied(c => (c === id ? '' : c)), 1400);
    } catch (_e) { /* clipboard unavailable */ }
  };

  const openHiveResult = (m) => {
    if (!m?.path && m?.path !== '') return;
    navigateHive(m.path);
  };

  const openHive = (entry) => {
    setHiveView(true);
    setHiveNode(null);
    setHiveErr('');
    setHiveSearch('');
    setHiveSearchRes(null);
    setHiveSearchErr('');
    setHivePathDraft('');
    loadHive(entry, '');
  };

  const closeHive = () => {
    setHiveView(false);
    setHiveNode(null);
    setHiveErr('');
    setHiveSearch('');
    setHiveSearchRes(null);
    setHiveSearchErr('');
    setHivePathDraft('');
  };

  // Debounced recursive hive search (backend walks the hive and returns matches).
  useEffect(() => {
    if (!hiveView || !selected) return;
    const term = hiveSearch.trim();
    if (!term) { setHiveSearchRes(null); setHiveSearchErr(''); setHiveSearching(false); return; }
    let cancelled = false;
    setHiveSearching(true);
    setHiveSearchErr('');
    const h = setTimeout(async () => {
      try {
        const res = await collectionAPI.fileHive(caseId, { evidence_id: collectionId, path: selected.path, search: term });
        if (!cancelled) setHiveSearchRes(res.data);
      } catch (e) {
        if (!cancelled) setHiveSearchErr(e.response?.data?.error || e.message || 'Search failed');
      } finally {
        if (!cancelled) setHiveSearching(false);
      }
    }, 350);
    return () => { cancelled = true; clearTimeout(h); };
  }, [hiveSearch, hiveView, selected, caseId, collectionId]);

  const download = async (entry) => {
    try {
      const res = await collectionAPI.fileDownload(caseId, { evidence_id: collectionId, path: entry.path });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = entry.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Download failed');
    }
  };

  const exportMftResidents = async () => {
    if (exporting) return;
    setExporting(true);
    setError('');
    try {
      const res = await collectionAPI.mftResidentExport(caseId, { evidence_id: collectionId });
      const cd = res.headers?.['content-disposition'] || '';
      const m = /filename="?([^";]+)"?/i.exec(cd);
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = m ? m[1] : 'mft_resident.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) {
      // 404/500 come back as JSON inside a Blob (responseType: 'blob').
      let msg = e.message || 'Export failed';
      try {
        const data = e.response?.data;
        if (data instanceof Blob && data.type === 'application/json') {
          const j = JSON.parse(await data.text());
          if (j.error) msg = j.error;
        } else if (data?.error) {
          msg = data.error;
        }
      } catch { /* keep the generic message */ }
      setError(msg);
    } finally {
      setExporting(false);
    }
  };

  // Entries whose name matches the filter (case-insensitive substring).
  const filteredEntries = useMemo(() => {
    const q = nameFilter.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(e => e.name.toLowerCase().includes(q));
  }, [entries, nameFilter]);

  const crumbs = useMemo(() => {
    const segs = (cwd || '').split('/').filter(Boolean);
    const acc = [];
    let p = '';
    for (const s of segs) {
      p = p ? `${p}/${s}` : s;
      acc.push({ name: s, path: p });
    }
    return acc;
  }, [cwd]);

  const hexRows = useMemo(() => (
    content && content.binary && content.hex ? formatHexDump(content.hex, content.ascii) : []
  ), [content]);

  // Compiled query — invalid regexes simply yield no matches (and a hint).
  const queryRe = useMemo(() => {
    const q = query.trim();
    if (!q) return null;
    try {
      return new RegExp(regexMode ? q : q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    } catch {
      return null;
    }
  }, [query, regexMode]);

  const lines = useMemo(() => (
    content && !content.binary && content.text ? content.text.split('\n') : []
  ), [content]);

  // Absolute line indices (0-based) of the open file that match the query.
  const matchLines = useMemo(() => {
    if (!queryRe || lines.length === 0) return [];
    const out = [];
    for (let i = 0; i < lines.length; i++) {
      queryRe.lastIndex = 0;
      if (queryRe.test(lines[i])) out.push(i);
    }
    queryRe.lastIndex = 0;
    return out;
  }, [queryRe, lines]);

  const matchSet = useMemo(() => new Set(matchLines), [matchLines]);

  // For very large files, render only the matching lines (with ±2 context).
  const visibleSet = useMemo(() => {
    if (lines.length <= MAX_INLINE_LINES || matchLines.length === 0) return null;
    const s = new Set();
    for (const l of matchLines) {
      for (let d = -2; d <= 2; d++) if (l + d >= 0 && l + d < lines.length) s.add(l + d);
    }
    return s;
  }, [lines.length, matchLines]);

  useEffect(() => { setActiveMatch(0); }, [matchLines]);

  // Scroll the active match (or the first one on a freshly opened file) into view.
  useEffect(() => {
    if (matchLines.length === 0) return;
    const idx = Math.min(activeMatch, matchLines.length - 1);
    const el = document.getElementById(`fl-line-${matchLines[idx]}`);
    if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [activeMatch, matchLines]);

  const clearSearch = () => {
    setQuery(''); setResults(null); setSearchErr(''); setActiveMatch(0); setExpandedResult(null);
  };

  // Clear stale cross-file results when the query is emptied or narrowed to file scope.
  useEffect(() => {
    if (!query.trim() || scope !== 'all') { setResults(null); setSearchErr(''); }
  }, [query, scope]);

  const runSearch = useCallback(async () => {
    const q = query.trim();
    if (!q || scope !== 'all' || !caseId || !collectionId) return;
    setSearching(true);
    setSearchErr('');
    setResults(null);
    setExpandedResult(null);
    try {
      const res = await collectionAPI.fileSearch(caseId, {
        evidence_id: collectionId,
        q,
        regex: regexMode ? 1 : 0,
        path: cwd || '',
      });
      setResults(res.data);
    } catch (e) {
      setSearchErr(e.response?.data?.error || e.message || 'Search failed');
    } finally {
      setSearching(false);
    }
  }, [query, scope, regexMode, cwd, caseId, collectionId]);

  const stepMatch = (dir) => {
    if (matchLines.length === 0) return;
    setActiveMatch(a => (a + dir + matchLines.length) % matchLines.length);
  };

  const onSearchKey = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (scope === 'all') runSearch();
      else stepMatch(1);
    }
  };

  // Open a file from the cross-file results and jump to its first match.
  const openSearchResult = (r) => {
    setResults(null);
    setSearching(false);
    setScope('file');
    const entry = { path: r.path, name: r.name, type: 'file', size: r.size };
    setSelected(entry);
    setContent(null);
    loadContent(entry);
    setActiveMatch(0);
  };

  const searchInputStyle = {
    flex: 1, minWidth: 0, background: 'transparent', border: 'none', outline: 'none',
    color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11.5,
  };
  const toggleBtnStyle = (active) => ({
    display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 9px', borderRadius: 6, cursor: 'pointer',
    background: active ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
    color: active ? 'var(--fl-accent)' : 'var(--fl-muted)',
    border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 26%, transparent)' : 'var(--fl-border2)'}`,
    fontFamily: MONO, fontSize: 10.5, fontWeight: 600, flexShrink: 0,
  });

  if (!caseId || !collectionId) {
    return <div style={{ padding: 24, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 13 }}>{t('collectionFiles.noContext', 'Contexte de collecte manquant')}</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      {/* Header / breadcrumb */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px',
        borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap',
      }}>
        <HardDrive size={14} style={{ color: 'var(--fl-purple)', flexShrink: 0 }} />
        <button
          onClick={() => load('')}
          title={t('collectionFiles.root', 'Racine')}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 5, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-accent)', fontFamily: MONO, fontSize: 11.5, padding: '2px 4px' }}
        >
          {t('collectionFiles.collectionRoot', 'collecte')}
        </button>
        {crumbs.map((c, i) => (
          <span key={c.path} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <ChevronRight size={11} style={{ color: 'var(--fl-border3)' }} />
            <button
              onClick={() => load(c.path)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: i === crumbs.length - 1 ? 'var(--fl-text)' : 'var(--fl-dim)', fontFamily: MONO, fontSize: 11.5, padding: '2px 4px', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              title={c.path}
            >
              {c.name}
            </button>
          </span>
        ))}
        <span style={{ flex: 1 }} />

        {/* Search box */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 1, minWidth: 220, maxWidth: 480 }}>
          <button
            onClick={() => { setScope('file'); if (selected) setActiveMatch(0); }}
            style={toggleBtnStyle(scope === 'file')}
            title={t('collectionFiles.scopeFile', 'Chercher dans le fichier affiché')}
          >
            <FileText size={11} /> {t('collectionFiles.scopeFileShort', 'Fichier')}
          </button>
          <button
            onClick={() => { setScope('all'); if (query.trim()) runSearch(); }}
            style={toggleBtnStyle(scope === 'all')}
            title={t('collectionFiles.scopeAll', 'Chercher dans tous les fichiers')}
          >
            <FileSearch size={11} /> {t('collectionFiles.scopeAllShort', 'Tous')}
          </button>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0,
            background: 'var(--fl-card)', border: '1px solid var(--fl-border2)', borderRadius: 7, padding: '5px 9px',
          }}>
            <Search size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={onSearchKey}
              placeholder={scope === 'all'
                ? t('collectionFiles.searchAllPlaceholder', 'Mots-clés / regex dans tous les fichiers…')
                : t('collectionFiles.searchFilePlaceholder', 'Mots-clés / regex dans le fichier…')}
              style={searchInputStyle}
            />
            <button
              onClick={() => setRegexMode(m => !m)}
              title={t('collectionFiles.regexToggle', 'Expression régulière')}
              style={toggleBtnStyle(regexMode)}
            >
              <Regex size={11} />
            </button>
            {query && (
              <button
                onClick={clearSearch}
                title={t('collectionFiles.clearSearch', 'Effacer')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 2, flexShrink: 0 }}
              >
                <X size={12} />
              </button>
            )}
          </div>
          {scope === 'all' && (
            <button
              onClick={runSearch}
              disabled={searching || !query.trim()}
              style={{ ...toggleBtnStyle(false), opacity: query.trim() ? 1 : 0.5, color: 'var(--fl-accent)' }}
            >
              {searching ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={11} />}
              {t('collectionFiles.go', 'OK')}
            </button>
          )}
        </div>

        <button
          onClick={exportMftResidents}
          disabled={exporting}
          title={t('collectionFiles.exportMftResidents', 'Exporter tous les fichiers residents récupérés du $MFT (ZIP)')}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, cursor: exporting ? 'not-allowed' : 'pointer', opacity: exporting ? 0.6 : 1, background: 'color-mix(in srgb, var(--fl-purple) 12%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 30%, transparent)', fontFamily: MONO, fontSize: 10.5, fontWeight: 600, flexShrink: 0 }}
          onMouseEnter={e => { if (!exporting) e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-purple) 18%, transparent)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-purple) 12%, transparent)'; }}
        >
          {exporting ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Archive size={12} />}
          {t('collectionFiles.exportResidents', 'MFT residents')}
        </button>

        <button
          onClick={() => load(cwd)}
          title={t('collectionFiles.refresh', 'Rafraîchir')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 4 }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
        >
          <RefreshCw size={13} />
        </button>
      </div>

      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '10px 14px 0', padding: '8px 12px', borderRadius: 7, background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)', color: 'var(--fl-danger)', fontSize: 12, fontFamily: MONO, flexShrink: 0 }}>
          <AlertTriangle size={13} /> {error}
        </div>
      )}

      {/* Cross-file results panel */}
      {scope === 'all' && (searching || searchErr || results) && (
        <div style={{ borderBottom: '1px solid var(--fl-border)', maxHeight: 300, overflow: 'auto', flexShrink: 0, background: 'var(--fl-card)' }}>
          {searching ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '14px 18px', color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
              <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('collectionFiles.searching', 'Recherche dans les fichiers…')}
            </div>
          ) : searchErr ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 18px', color: 'var(--fl-danger)', fontFamily: MONO, fontSize: 12 }}>
              <AlertTriangle size={13} /> {searchErr}
            </div>
          ) : results && (
            <div style={{ padding: '10px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                  {t('collectionFiles.searchResults', 'Résultats')}
                </span>
                <span style={{ fontFamily: MONO, fontSize: 11, color: results.matched_files > 0 ? 'var(--fl-ok)' : 'var(--fl-gold)', fontWeight: 700 }}>
                  {results.matched_files} {t('collectionFiles.filesShort', 'fichier(s)')} · {results.scanned} {t('collectionFiles.scannedShort', 'parcourus')}
                </span>
                {results.truncated && <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-gold)' }}>{t('collectionFiles.searchTruncated', 'résultats tronqués')}</span>}
                <span style={{ flex: 1 }} />
                <button onClick={() => setResults(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', alignItems: 'center', gap: 4, fontFamily: MONO, fontSize: 10.5 }}>
                  <X size={11} /> {t('collectionFiles.close', 'Fermer')}
                </button>
              </div>
              {results.matched_files === 0 ? (
                <div style={{ padding: '6px 0 10px', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 11.5 }}>
                  {t('collectionFiles.noMatches', 'Aucune correspondance trouvée.')}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {results.files.map(r => (
                    <div key={r.path} style={{ border: '1px solid var(--fl-border2)', borderRadius: 6, overflow: 'hidden' }}>
                      <div
                        onClick={() => setExpandedResult(e => e === r.path ? null : r.path)}
                        style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px', cursor: 'pointer', background: 'var(--fl-bg)' }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'var(--fl-bg)'; }}
                      >
                        <FileText size={12} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
                        <span style={{ fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.path}</span>
                        <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', flexShrink: 0 }}>{r.matches.length} ×</span>
                        <button
                          onClick={e => { e.stopPropagation(); openSearchResult(r); }}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 5, cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 22%, transparent)', fontFamily: MONO, fontSize: 10.5, flexShrink: 0 }}
                          onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 16%, transparent)'; }}
                          onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 10%, transparent)'; }}
                        >
                          <CornerDownRight size={10} /> {t('collectionFiles.open', 'Ouvrir')}
                        </button>
                      </div>
                      {expandedResult === r.path && (
                        <div style={{ padding: '4px 10px 8px', borderTop: '1px solid var(--fl-border2)', background: 'var(--fl-bg)' }}>
                          {r.matches.map(m => (
                            <div key={m.line} style={{ display: 'flex', gap: 8, padding: '2px 0', fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-dim)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                              <span style={{ color: 'var(--fl-muted)', flexShrink: 0, minWidth: 44, textAlign: 'right' }}>{m.line}</span>
                              <span style={{ flex: 1, minWidth: 0 }}>{m.text}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        {/* Directory listing */}
        <div style={{ width: 340, minWidth: 240, borderRight: '1px solid var(--fl-border)', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--fl-border2)', display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <span style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600 }}>{t('collectionFiles.files', 'Fichiers')}</span>
            <span style={{ flex: 1 }} />
            <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)' }}>{filteredEntries.length}{truncated ? '+' : ''}</span>
          </div>
          <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--fl-border2)', display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <Search size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
            <input
              value={nameFilter}
              onChange={e => setNameFilter(e.target.value)}
              placeholder={t('collectionFiles.filterName', 'Filtrer par nom…')}
              style={{ flex: 1, minWidth: 0, background: 'transparent', border: 'none', outline: 'none', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11 }}
            />
            {nameFilter && (
              <button
                onClick={() => setNameFilter('')}
                title={t('collectionFiles.clearFilter', 'Effacer le filtre')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'inline-flex', padding: 2, flexShrink: 0 }}
              >
                <X size={11} />
              </button>
            )}
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 4 }}>
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: 32, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}>
                <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
              </div>
            ) : entries.length === 0 ? (
              <div style={{ padding: 28, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 11 }}>{t('collectionFiles.empty', 'Répertoire vide')}</div>
            ) : filteredEntries.length === 0 ? (
              <div style={{ padding: 28, textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 11 }}>{t('collectionFiles.noFilterMatch', 'Aucun fichier ne correspond au filtre.')}</div>
            ) : (
              <>
                {parent != null && (
                  <button
                    onClick={() => load(parent)}
                    style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', borderRadius: 6, background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 12 }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <CornerLeftUp size={13} /> ..
                  </button>
                )}
                {filteredEntries.map(entry => {
                  const isDir = entry.type === 'dir';
                  const Icon = isTextLike(entry.name) ? FileText : FileCode2;
                  const active = selected && selected.path === entry.path;
                  return (
                    <button
                      key={entry.path}
                      onClick={() => openEntry(entry)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left',
                        padding: '6px 10px', borderRadius: 6, cursor: 'pointer', border: 'none',
                        background: active ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
                        fontFamily: MONO, fontSize: 12,
                        color: isDir ? 'var(--fl-accent)' : 'var(--fl-text)',
                      }}
                      onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--fl-card)'; }}
                      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
                    >
                      {isDir ? <FolderOpen size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} /> : <Icon size={14} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />}
                      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.name}</span>
                      {!isDir && <span style={{ fontSize: 9.5, color: 'var(--fl-subtle)', flexShrink: 0 }}>{fmtSize(entry.size)}</span>}
                    </button>
                  );
                })}
              </>
            )}
          </div>
        </div>

        {/* Preview */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {!selected ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12, padding: 24, textAlign: 'center' }}>
              {t('collectionFiles.selectHint', 'Sélectionnez un fichier pour le lire. Les artefacts binaires (.evtx, .pf, hives…) sont affichés en hexadécimal et téléchargeables.')}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 14px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap' }}>
                {content && content.binary ? <FileCode2 size={14} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} /> : <FileText size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />}
                <span style={{ fontFamily: MONO, fontSize: 12, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{selected.name}</span>
                <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)', flexShrink: 0 }}>{fmtSize(selected.size)}</span>

                {/* In-file match navigation */}
                {queryRe && matchLines.length > 0 && (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 8px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-gold) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-gold) 22%, transparent)', fontFamily: MONO, fontSize: 10.5, flexShrink: 0 }}>
                    <button onClick={() => stepMatch(-1)} title={t('collectionFiles.prevMatch', 'Précédent')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-gold)', display: 'inline-flex', padding: 1 }}>
                      <ArrowUp size={11} />
                    </button>
                    <span style={{ color: 'var(--fl-gold)', fontWeight: 700, fontFeatureSettings: '"tnum"' }}>{Math.min(activeMatch + 1, matchLines.length)}/{matchLines.length}</span>
                    <button onClick={() => stepMatch(1)} title={t('collectionFiles.nextMatch', 'Suivant')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-gold)', display: 'inline-flex', padding: 1 }}>
                      <ArrowDown size={11} />
                    </button>
                  </span>
                )}

                {isHiveFile(selected.name) && !hiveView && (
                  <button
                    onClick={() => openHive(selected)}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-gold) 10%, transparent)', color: 'var(--fl-gold)', border: '1px solid color-mix(in srgb, var(--fl-gold) 24%, transparent)', fontFamily: MONO, fontSize: 11, flexShrink: 0 }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-gold) 18%, transparent)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-gold) 10%, transparent)'; }}
                  >
                    <HardDrive size={12} /> {t('collectionFiles.openHive', 'Ouvrir le hive')}
                  </button>
                )}
                {hiveView && (
                  <button
                    onClick={closeHive}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', fontFamily: MONO, fontSize: 11, flexShrink: 0 }}
                  >
                    <FileCode2 size={12} /> {t('collectionFiles.closeHive', 'Vue hexadécimale')}
                  </button>
                )}
                <button
                  onClick={() => download(selected)}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 22%, transparent)', fontFamily: MONO, fontSize: 11, flexShrink: 0 }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 16%, transparent)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 10%, transparent)'; }}
                >
                  <Download size={12} /> {t('collectionFiles.download', 'Télécharger')}
                </button>
              </div>

              <div style={{ flex: 1, overflow: 'auto', background: 'var(--fl-bg)', fontFamily: MONO, fontSize: 11.5, lineHeight: 1.55 }}>
                {hiveView ? (
                  <HiveBrowser
                    t={t}
                    entry={selected}
                    node={hiveNode}
                    loading={hiveLoading}
                    error={hiveErr}
                    search={hiveSearch}
                    onSearch={setHiveSearch}
                    searching={hiveSearching}
                    searchRes={hiveSearchRes}
                    searchErr={hiveSearchErr}
                    onOpenResult={openHiveResult}
                    pathDraft={hivePathDraft}
                    onPathDraft={setHivePathDraft}
                    onJump={jumpHive}
                    onNavigate={navigateHive}
                    onCopy={copyHiveText}
                    copied={hiveCopied}
                  />
                ) : contentLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, padding: 40, color: 'var(--fl-dim)', fontSize: 12 }}>
                    <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
                  </div>
                ) : !content ? null : content.error ? (
                  <div style={{ padding: 20, color: 'var(--fl-danger)' }}>{content.error}</div>
                ) : content.binary ? (
                  <div style={{ padding: '10px 14px' }}>
                    <div style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      {t('collectionFiles.hexPreview', 'Aperçu hexadécimal')} · {content.length || 0} {t('collectionFiles.bytes', 'octets')}{content.truncated ? ' · ' + t('collectionFiles.truncated', 'tronqué') : ''}
                    </div>
                    {hexRows.map(row => (
                      <div key={row.offset} style={{ display: 'flex', gap: 14, whiteSpace: 'pre', color: 'var(--fl-dim)' }}>
                        <span style={{ color: 'var(--fl-muted)', minWidth: 66 }}>{row.offset.toString(16).padStart(6, '0')}</span>
                        <span style={{ color: 'var(--fl-accent)' }}>{row.hex}</span>
                        <span style={{ color: 'var(--fl-text)' }}>{row.ascii}</span>
                      </div>
                    ))}
                  </div>
                ) : queryRe ? (
                  <div style={{ padding: '10px 14px', color: 'var(--fl-text)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    {matchLines.length === 0 ? (
                      <div style={{ fontFamily: MONO, fontSize: 10.5, color: queryRe ? 'var(--fl-muted)' : 'var(--fl-danger)', marginBottom: 10 }}>
                        {queryRe ? t('collectionFiles.noMatchInFile', 'Aucune correspondance dans ce fichier.') : t('collectionFiles.invalidRegex', 'Expression régulière invalide.')}
                      </div>
                    ) : visibleSet && (
                      <div style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-gold)', marginBottom: 8 }}>
                        {t('collectionFiles.matchesOnly', 'Fichier volumineux — seules les lignes correspondantes sont affichées.')} {matchLines.length} {t('collectionFiles.matches', 'correspondance(s)')}
                      </div>
                    )}
                    {content.truncated && !visibleSet && (
                      <div style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-gold)', marginBottom: 8 }}>
                        {t('collectionFiles.truncatedNote', 'Aperçu limité — téléchargez le fichier pour le contenu complet.')}
                      </div>
                    )}
                    {lines.map((line, i) => {
                      if (visibleSet && !visibleSet.has(i)) return null;
                      const isMatch = matchSet.has(i);
                      return (
                        <div key={i} id={`fl-line-${i}`} data-line={i + 1} style={{ minHeight: '1.2em', whiteSpace: 'pre-wrap' }}>
                          {isMatch
                            ? splitMatches(line, queryRe).map((p, j) => p.hit
                                ? <mark key={j} style={MARK_STYLE}>{p.text}</mark>
                                : <span key={j}>{p.text}</span>)
                            : (line || '\u00A0')}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ padding: '10px 14px', color: 'var(--fl-text)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    {content.truncated && (
                      <div style={{ fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-gold)', marginBottom: 8 }}>
                        {t('collectionFiles.truncatedNote', 'Aperçu limité — téléchargez le fichier pour le contenu complet.')}
                      </div>
                    )}
                    {content.text}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
