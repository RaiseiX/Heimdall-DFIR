import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  Clock, Search, ChevronLeft, ChevronRight, Download, Loader2,
  FolderOpen, Star, Eye, EyeOff, SortAsc, SortDesc, X, Filter, Tag, LayoutTemplate, ArrowLeft,
  Copy, CheckSquare, Square, Layers, Palette, Columns, ChevronDown, Pin, ChevronUp,
  MessageSquare, Send, Trash2, Pencil,
} from 'lucide-react';
import { useNavigate, useParams, useLocation, useSearchParams, useOutletContext } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { collectionAPI, casesAPI, evidenceAPI, timelineRulesAPI, artifactsAPI } from '../utils/api';
import { useSocket } from '../hooks/useSocket';
import { useTheme } from '../utils/theme';
import SuperTimelineWorkbench from '../components/timeline/SuperTimelineWorkbench';
import CaseChatPanel from '../components/chat/CaseChatPanel';
import ColorRulesManager from '../components/timeline/ColorRulesManager';
import { evaluateColorRules, sortRules } from '../utils/colorRulesEngine';
import ColumnManager from '../components/timeline/ColumnManager';
import { ARTIFACT_PROFILES, getProfileForArtifact } from '../utils/artifactProfiles';
import { getEffectiveVirtual, getColumnPref } from '../utils/columnPreferences';
import ArtifactColumnEditor from '../components/timeline/ArtifactColumnEditor';
import { artifactColor, HAY_SEVERITY_BG } from '../constants/artifactColors';
import { fmtTs as fmtTsUtil, fmtLocal } from '../utils/formatters';

function includeParam(excluded, available) {
  if (!(excluded instanceof Set) || excluded.size === 0) return '';
  const incl = available.filter(t => !excluded.has(t));
  return incl.length ? incl.join(',') : '__none__';
}

function getColFieldValue(r, key) {
  if (key === 'timestamp')        return String(r.timestamp ?? '');
  if (key === 'artifact_type')    return r.artifact_type   || '';
  if (key === 'description')      return r.description     || '';
  if (key === 'source')           return r.source          || '';
  if (key === 'host_name')        return r.host_name       || '';
  if (key === 'user_name')        return r.user_name       || '';
  if (key === 'process_name')     return r.process_name    || '';
  if (key === 'timestamp_column') return r.timestamp_column|| '';
  if (key.startsWith('raw.'))     return String(r.raw?.[key.slice(4)] ?? '');
  return String(r[key] ?? '');
}

function applyColFilter(fieldValue, { op, value }) {
  const fv = String(fieldValue ?? '').toLowerCase();
  const v  = (value ?? '').toLowerCase();
  switch (op) {
    case 'not_contains': return !fv.includes(v);
    case 'equals':       return fv === v;
    case 'not_equals':   return fv !== v;
    case 'starts_with':  return fv.startsWith(v);
    case 'ends_with':    return fv.endsWith(v);
    case 'empty':        return !fieldValue || String(fieldValue).trim() === '';
    case 'not_empty':    return !!(fieldValue && String(fieldValue).trim());
    case 'regex':
      try { return new RegExp(value, 'i').test(String(fieldValue ?? '')); } catch { return true; }
    default:             return fv.includes(v); // 'contains'
  }
}

// Hex colors for artifact tabs (CSS variables can't be used with ${col}18 opacity trick in inline styles)
const ARTIFACT_TAB_HEX = {
  evtx:      '#4d82c0',
  prefetch:  '#22c55e',
  mft:       '#8b72d6',
  lnk:       '#d97c20',
  registry:  '#c96898',
  amcache:   '#c89d1d',
  shellbags: '#06b6d4',
  jumplist:  '#8b5cf6',
  srum:      '#f43f5e',
  recycle:   '#84cc16',
  wxtcmd:    '#d946ef',
  sqle:      '#0ea5e9',
  sum:       '#0ea5e9',
  appcompat: '#f59e0b',
  bits:      '#64748b',
  hayabusa:  '#da3633',
};
function tabColor(type) {
  return ARTIFACT_TAB_HEX[type] || '#8b9ab4';
}

// Per-artifact description formatter — reads from raw CSV columns for cleaner display
function fmtDesc(r) {
  const raw = r.raw || {};
  switch (r.artifact_type) {
    case 'evtx': {
      const md = raw.MapDescription || r.description || '';
      // EvtxECmd fallback: "EventID | RecordID | Timestamp" when no map exists
      if (/^\d+\s*\|\s*\d+\s*\|/.test(md)) {
        const eid = String(raw.EventId || raw.EventID || md.split('|')[0]).trim();
        const pd = raw.PayloadData1 || '';
        return pd ? `[EID:${eid}] ${pd}` : `EventID ${eid}`;
      }
      return md || raw.PayloadData1 || r.description || '';
    }
    case 'appcompat': {
      const p = raw.Path || r.description || '';
      // ShimCache sometimes stores binary-encoded paths with hex prefix
      const cleaned = p.replace(/^([0-9a-f]{6,}\s+)+/i, '').trim();
      return cleaned || p;
    }
    case 'registry':
      return raw.Description || raw.ValueName || raw.KeyPath || r.description || '';
    case 'prefetch': {
      const name = raw.ExecutableName || r.description || '';
      // PECmd sometimes includes RunCount/Hash: "EXE.EXE | 4 | HASH" — keep only the exe name
      return name.split('|')[0].trim() || name;
    }
    case 'mft':
      return raw.FileName || r.description || '';
    case 'amcache':
      return raw.FileDescription || raw.FullPath || raw.ProgramName || r.description || '';
    case 'srum':
      return raw.ExeInfo || raw.AppId || r.description || '';
    case 'shellbags':
      return raw.AbsolutePath || r.description || '';
    case 'sqle':
      return raw.Title || raw.URL || r.description || '';
    case 'wxtcmd':
      return raw.DisplayText || raw.Description || raw.AppId || r.description || '';
    default:
      return r.description || '';
  }
}

// Per-artifact source formatter — shows the most meaningful "source" field for each type
function fmtSrc(r) {
  const raw = r.raw || {};
  switch (r.artifact_type) {
    case 'evtx':
      return raw.Channel || r.source || '';
    case 'appcompat':
      // SourceFile = the SYSTEM registry hive, much more meaningful than Path
      return raw.SourceFile || r.source || '';
    case 'mft':
      return raw.ParentPath || r.source || '';
    case 'prefetch':
      return raw.SourceFilename || r.source || '';
    case 'lnk':
      return raw.SourceFile || r.source || '';
    case 'registry':
      return raw.HivePath || r.source || '';
    case 'amcache':
      return raw.SourceFile || raw.ProgramName || r.source || '';
    case 'shellbags':
      return raw.HivePath || raw.SourceFile || r.source || '';
    case 'jumplist':
      return raw.SourceFile || r.source || '';
    case 'srum':
      return raw.AppId || raw.UserId || r.source || '';
    case 'recycle':
      return raw.SourceName || raw.FileName || r.source || '';
    case 'bits':
      return raw.TargetDirectory || raw.Url || r.source || '';
    case 'sum':
      return raw.Address || r.source || '';
    case 'sqle':
      return raw.SourceFile || r.source || '';
    case 'wxtcmd':
      return raw.SourceFile || raw.AppId || r.source || '';
    default:
      return r.source || '';
  }
}

const COLUMNS_BASE = [
  { key: 'timestamp',        label: 'Timestamp (UTC)', width: 186, mono: true },
  { key: 'artifact_type',    label: 'Type',            width: 96             },
  { key: 'description',      label: 'Description',     flex: true            },
  { key: 'source',           label: 'Source',          width: 170, mono: true },
  { key: 'timestamp_column', label: 'TS Field',        width: 100, mono: true },
];
const PAGE_SIZES = [200, 500, 1000];

const fmtTs = fmtTsUtil;

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
  const { t } = useTranslation();
  const confidenceLevels = useMemo(() => [
    { key: 'critical', label: t('timeline.confidence.malicious'),  color: 'var(--fl-danger)', bg: '#ef444418', dot: '●' },
    { key: 'high',     label: t('timeline.confidence.suspect'),    color: 'var(--fl-warn)', bg: '#d97c2012', dot: '●' },
    { key: 'medium',   label: t('timeline.confidence.to_analyze'), color: 'var(--fl-gold)', bg: '#c89d1d10', dot: '●' },
    { key: 'low',      label: t('timeline.confidence.benign'),     color: '#22c55e', bg: '#22c55e08', dot: '●' },
  ], [t]);
  const forensicTags = useMemo(() => [
    { key: 'exec',            label: t('timeline.tags.exec'),            color: 'var(--fl-warn)' },
    { key: 'persist',         label: t('timeline.tags.persist'),         color: 'var(--fl-purple)' },
    { key: 'lateral',         label: t('timeline.tags.lateral'),         color: '#22c55e' },
    { key: 'exfil',           label: t('timeline.tags.exfil'),           color: 'var(--fl-danger)' },
    { key: 'c2',              label: t('timeline.tags.c2'),              color: '#f43f5e' },
    { key: 'recon',           label: t('timeline.tags.recon'),           color: '#06b6d4' },
    { key: 'privesc',         label: t('timeline.tags.privesc'),         color: '#f59e0b' },
    { key: 'defense_evasion', label: t('timeline.tags.defense_evasion'), color: '#64748b' },
    { key: 'credential',      label: t('timeline.tags.credential'),      color: 'var(--fl-pink)' },
    { key: 'discovery',       label: t('timeline.tags.discovery'),       color: '#0ea5e9' },
    { key: 'collection',      label: t('timeline.tags.collection'),      color: '#84cc16' },
    { key: 'impact',          label: t('timeline.tags.impact'),          color: '#dc2626' },
    { key: 'initial_access',  label: t('timeline.tags.initial_access'),  color: '#7c3aed' },
    { key: 'weaponization',   label: t('timeline.tags.weaponization'),   color: '#9333ea' },
    { key: 'delivery',        label: t('timeline.tags.delivery'),        color: '#2563eb' },
    { key: 'exploitation',    label: t('timeline.tags.exploitation'),    color: '#b45309' },
    { key: 'installation',    label: t('timeline.tags.installation'),    color: '#059669' },
  ], [t]);

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
      ? current.tags.filter(k => k !== key)
      : [...current.tags, key];
    onChange(globalIdx, { ...current, tags });
  }
  function clearAll() {
    onChange(globalIdx, { level: null, tags: [] });
    onClose();
  }

  return (
    <div ref={ref} style={{
      position: 'fixed', zIndex: 1000, width: 310,
      background: isDark ? 'var(--fl-panel)' : '#ffffff',
      border: `1px solid ${isDark ? 'var(--fl-border)' : '#c8d8ea'}`,
      borderRadius: 8,
      boxShadow: isDark
        ? '0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04)'
        : '0 8px 32px rgba(0,0,0,0.15)',
      padding: 14,
    }}>

      <div style={{ marginBottom: 12 }}>
        <div style={{ fontFamily: 'monospace', fontSize: 9,
          color: isDark ? 'var(--fl-muted)' : '#0969da',
          textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 7, fontWeight: 700 }}>
          {t('timeline.confidence_label')}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 5 }}>
          {confidenceLevels.map(l => {
            const active = current.level === l.key;
            return (
              <button key={l.key} onClick={() => setLevel(l.key)}
                style={{
                  padding: '6px 4px', borderRadius: 6, fontSize: 10,
                  fontFamily: 'monospace', cursor: 'pointer', fontWeight: 700,
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 3,
                  background: active ? l.bg : (isDark ? 'rgba(255,255,255,0.05)' : '#f0f6ff'),
                  color: active ? l.color : (isDark ? 'var(--fl-dim)' : '#1f2328'),
                  border: `1px solid ${active ? l.color + '80' : (isDark ? 'var(--fl-border)' : '#c8d8ea')}`,
                  transition: 'all 0.12s',
                  whiteSpace: 'normal', textAlign: 'center', lineHeight: 1.3,
                  minHeight: 42,
                }}>
                <span style={{ fontSize: 8, color: l.color }}>●</span>
                {l.label}
              </button>
            );
          })}
        </div>
      </div>

      <div>
        <div style={{ fontFamily: 'monospace', fontSize: 9,
          color: isDark ? 'var(--fl-muted)' : '#0969da',
          textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 7, fontWeight: 700 }}>
          {t('timeline.category_label')}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {forensicTags.map(tag => {
            const active = current.tags.includes(tag.key);
            return (
              <button key={tag.key} onClick={() => toggleTag(tag.key)}
                style={{
                  padding: '3px 9px', borderRadius: 10, fontSize: 10,
                  fontFamily: 'monospace', cursor: 'pointer', fontWeight: 600,
                  background: active ? `${tag.color}25` : (isDark ? 'rgba(255,255,255,0.05)' : '#f0f6ff'),
                  color: active ? tag.color : (isDark ? 'var(--fl-dim)' : '#1f2328'),
                  border: `1px solid ${active ? tag.color + '60' : (isDark ? 'var(--fl-border)' : '#c8d8ea')}`,
                  transition: 'all 0.12s',
                }}>
                {tag.label}
              </button>
            );
          })}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginTop: 12, paddingTop: 10,
        borderTop: `1px solid ${isDark ? 'var(--fl-border)' : '#e0eaf4'}` }}>
        <button onClick={clearAll}
          style={{ fontSize: 10, fontFamily: 'monospace',
            color: isDark ? 'var(--fl-muted)' : '#57606a',
            background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0' }}>
          {t('timeline.clear_tags')}
        </button>
        <button onClick={onClose}
          style={{ padding: '5px 14px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
            background: isDark ? 'rgba(255,255,255,0.08)' : '#0969da',
            border: `1px solid ${isDark ? 'var(--fl-border)' : '#0969da'}`,
            color: isDark ? 'var(--fl-text)' : '#ffffff', cursor: 'pointer', fontWeight: 600 }}>
          {t('common.close')}
        </button>
      </div>
    </div>
  );
}

export default function SuperTimelinePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { t } = useTranslation();
  const { socket } = useSocket();
  const [aiTabActive, setAiTabActive] = useState(false);

  const CONFIDENCE_LEVELS_T = useMemo(() => [
    { key: 'critical', label: t('timeline.confidence.malicious'),  color: 'var(--fl-danger)', bg: '#ef444418', dot: '●' },
    { key: 'high',     label: t('timeline.confidence.suspect'),    color: 'var(--fl-warn)', bg: '#d97c2012', dot: '●' },
    { key: 'medium',   label: t('timeline.confidence.to_analyze'), color: 'var(--fl-gold)', bg: '#c89d1d10', dot: '●' },
    { key: 'low',      label: t('timeline.confidence.benign'),     color: '#22c55e', bg: '#22c55e08', dot: '●' },
  ], [t]);
  const CONFIDENCE_MAP_T = useMemo(() => Object.fromEntries(CONFIDENCE_LEVELS_T.map(l => [l.key, l])), [CONFIDENCE_LEVELS_T]);

  const FORENSIC_TAGS_T = useMemo(() => [
    { key: 'exec',       label: t('timeline.tags.exec'),            color: 'var(--fl-warn)' },
    { key: 'persist',    label: t('timeline.tags.persist'),         color: 'var(--fl-pink)' },
    { key: 'lateral',    label: t('timeline.tags.lateral'),         color: 'var(--fl-purple)' },
    { key: 'exfil',      label: t('timeline.tags.exfil'),           color: '#f43f5e' },
    { key: 'privesc',    label: t('timeline.tags.privesc'),         color: 'var(--fl-gold)' },
    { key: 'credential', label: t('timeline.tags.credential'),      color: '#06b6d4' },
    { key: 'network',    label: t('timeline.tags.network'),         color: 'var(--fl-accent)' },
    { key: 'file',       label: t('timeline.tags.file'),            color: '#22c55e' },
    { key: 'logon',      label: t('timeline.tags.logon'),           color: '#8b5cf6' },
    { key: 'defense',    label: t('timeline.tags.defense_evasion'), color: '#64748b' },
    { key: 'registry',   label: t('timeline.tags.registry'),        color: '#d946ef' },
    { key: 'ioc',        label: t('timeline.tags.ioc'),             color: '#00ff88' },
    { key: 'recon',      label: t('timeline.tags.recon'),           color: '#7dd3fc' },
    { key: 'ransom',     label: t('timeline.tags.ransom'),          color: '#ff6b6b' },
  ], [t]);
  const FORENSIC_TAG_MAP_T = useMemo(() => Object.fromEntries(FORENSIC_TAGS_T.map(tg => [tg.key, tg])), [FORENSIC_TAGS_T]);

  const COLUMNS = useMemo(() => COLUMNS_BASE.map(c =>
    c.key === 'timestamp_column' ? { ...c, label: t('workbench.col_ts_field') } : c
  ), [t]);

  const { id: routeId, caseId: routeCaseId_, collectionId: routeEvidenceId } = useParams();
  const shellCtx = useOutletContext() || {};

  const routeCaseId = shellCtx.caseId || routeId || routeCaseId_;
  const location = useLocation();
  const isIsolated = Boolean(routeEvidenceId);

  const [isolatedEvidenceName, setIsolatedEvidenceName] = useState(
    location.state?.evidenceName || ''
  );
  const [isolatedCaseLabel, setIsolatedCaseLabel] = useState(
    location.state?.caseTitle
      ? `${location.state.caseNumber || ''} — ${location.state.caseTitle}`
      : ''
  );

  const [cases, setCases]           = useState([]);
  const [caseId, setCaseId]         = useState(routeCaseId || searchParams.get('caseId') || '');
  const [loadingCases, setLoadingCases] = useState(!isIsolated);

  const [records, setRecords]       = useState([]);
  const [total, setTotal]           = useState(0);
  const [page, setPage]             = useState(1);
  const [pageSize, setPageSize]     = useState(500);
  const [totalPages, setTotalPages] = useState(0);
  const [availTypes, setAvailTypes] = useState([]);
  const [typeCounts, setTypeCounts] = useState({});
  const [loading, setLoading]       = useState(false);

  const [search, setSearch]         = useState(searchParams.get('search') || '');
  const [searchOp, setSearchOp]     = useState('contains');

  const [groupByFields, setGroupByFields] = useState([]);
  const [showGroupByMenu, setShowGroupByMenu] = useState(false);
  const groupByMenuRef = useRef(null);

  const [showColumnManager, setShowColumnManager] = useState(false);
  const [showColumnEditor, setShowColumnEditor]   = useState(false);

  const [columnPrefVersion, setColumnPrefVersion] = useState(0);

  const [colWidths, setColWidths]   = useState(new Map());

  const [colOrder, setColOrder]     = useState([]);
  const [excludedTypes, setExcludedTypes] = useState(new Set());
  const [startTime, setStartTime]   = useState('');
  const [endTime, setEndTime]       = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [resultIdFilter, setResultIdFilter] = useState(searchParams.get('resultId') || '');
  const [hostsAvail, setHostsAvail] = useState([]);
  const [usersAvail, setUsersAvail] = useState([]);

  const [evidenceList, setEvidenceList]   = useState([]);
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState(new Set());
  const [showEvidenceFilter, setShowEvidenceFilter]   = useState(false);
  const evidenceFilterRef = useRef(null);

  const [selectedRow, setSelectedRow]   = useState(null);
  const [detailTab, setDetailTab]       = useState('details');
  const [rowNotes, setRowNotes]         = useState([]);
  const [noteText, setNoteText]         = useState('');
  const [noteSaving, setNoteSaving]     = useState(false);
  const [noteEditId, setNoteEditId]     = useState(null);
  const [noteEditText, setNoteEditText] = useState('');
  const [bookmarks, setBookmarks]       = useState(new Set());
  const [showBookmarksOnly, setShowBookmarks] = useState(false);

  const [pinnedRows, setPinnedRows]     = useState(new Map());
  const [showPinned, setShowPinned]     = useState(true);
  const [sortCol, setSortCol]           = useState('timestamp');
  const [sortDir, setSortDir]           = useState('desc');

  const [serverSortCol, setServerSortCol] = useState('timestamp');
  const [serverSortDir, setServerSortDir] = useState('desc');

  const [multiSort, setMultiSort]         = useState([]);
  const [hiddenCols, setHiddenCols]     = useState(new Set());
  const [showColMenu, setShowColMenu]   = useState(false);
  const [jumpPage, setJumpPage]         = useState('');
  const [workbench, setWorkbench]       = useState(false);
  const [workbenchEnteredAt, setWorkbenchEnteredAt] = useState(null);
  const [toolbarCollapsed, setToolbarCollapsed] = useState(false);
  const [csvSep, setCsvSep]             = useState(',');
  const [csvLoading, setCsvLoading]     = useState(false);

  const [tagData, setTagData]           = useState(new Map());
  const [tagPickerIdx, setTagPickerIdx] = useState(null);
  const [tagPickerPos, setTagPickerPos] = useState({ top: 0, left: 0 });
  const [confidenceFilter, setConfidenceFilter] = useState(null);
  const [forensicTagFilter, setForensicTagFilter] = useState(null);
  const tagAnchorRef = useRef(null);

  const [selectedRows, setSelectedRows]     = useState(new Set());
  const lastClickedRowRef                   = useRef(null);
  const [copyFeedback, setCopyFeedback]     = useState(false);

  const [colFilters, setColFilters]             = useState({});
  const [showColFilters, setShowColFilters]     = useState(false);
  const [colFilterCombinator, setColFilterCombinator] = useState('AND');
  const [cellCtxMenu, setCellCtxMenu]           = useState(null);
  const [jumpTs, setJumpTs]                     = useState('');
  const [showPresetMenu, setShowPresetMenu]     = useState(false);
  const [presetName, setPresetName]             = useState('');
  const presetMenuRef                           = useRef(null);

  const [dateError, setDateError]           = useState(null);

  const colorRulesRef    = useRef([]);
  const [showColorRules, setShowColorRules] = useState(false);

  const handleRulesChange = useCallback((rules) => {
    colorRulesRef.current = sortRules(rules);
  }, []);

  const tableContainerRef = useRef(null);

  const colMenuRef = useRef(null);

  useEffect(() => {
    function h(e) {
      if (colMenuRef.current && !colMenuRef.current.contains(e.target)) setShowColMenu(false);
      if (groupByMenuRef.current && !groupByMenuRef.current.contains(e.target)) setShowGroupByMenu(false);
      if (presetMenuRef.current && !presetMenuRef.current.contains(e.target)) setShowPresetMenu(false);
      if (cellCtxMenu) setCellCtxMenu(null);
    }
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [cellCtxMenu]);

  useEffect(() => {
    if (!isIsolated || !routeCaseId || (isolatedEvidenceName && isolatedCaseLabel)) return;
    Promise.all([
      casesAPI.get(routeCaseId).catch(() => null),
      evidenceAPI.list(routeCaseId).catch(() => null),
    ]).then(([caseRes, evRes]) => {
      if (caseRes?.data) {
        const d = caseRes.data;
        setIsolatedCaseLabel(`${d.case_number || ''} — ${d.title || ''}`.trim().replace(/^—\s*/, ''));
      }
      if (evRes?.data && routeEvidenceId) {
        const evList = Array.isArray(evRes.data) ? evRes.data : (evRes.data.evidence || []);
        const ev = evList.find(e => e.id === routeEvidenceId);
        if (ev) setIsolatedEvidenceName(ev.name || '');
      }
    });
  }, [isIsolated, routeCaseId, routeEvidenceId]);

  useEffect(() => {
    if (isIsolated) return;
    casesAPI.list({}).then(({ data }) => {
      const list = data.cases || (Array.isArray(data) ? data : []);
      setCases(list);

      if (list.length > 0 && !searchParams.get('caseId')) setCaseId(String(list[0].id));
      setLoadingCases(false);
    }).catch(() => setLoadingCases(false));
  }, []);

  const loadTimeline = useCallback(async (pg, tf, srch, st, et, ps, sd = 'desc', sc = 'timestamp', hf = '', uf = '', rf = '', evIds = null, msort = null) => {
    if (!caseId) return;
    setLoading(true);
    setSelectedRow(null);
    setTagPickerIdx(null);
    try {
      const params = { page: pg, limit: ps, sort_dir: sd, sort_col: sc };

      if (msort && msort.length > 0) {
        params.sort_multi = msort.map(s => `${s.col}:${s.dir}`).join(',');
      }
      if (tf) params.artifact_types = tf;
      if (srch) { params.search = srch; params.search_op = searchOp; }
      if (st) params.start_time = new Date(st).toISOString();
      if (et) params.end_time   = new Date(et).toISOString();
      if (hf) params.host_name = hf;
      if (uf) params.user_name = uf;
      if (rf) params.result_id = rf;

      if (routeEvidenceId) {
        params.evidence_id = routeEvidenceId;
      } else if (evIds && evIds.size > 0) {

        params.evidence_ids = [...evIds].join(',');
      }
      const res = await collectionAPI.timeline(caseId, params);
      if (res.data) {
        setRecords(res.data.records || []);
        setTotal(res.data.total || 0);
        setTotalPages(res.data.total_pages || 0);

        if (!tf) {
          setAvailTypes(res.data.artifact_types_available || []);
          setTypeCounts(res.data.artifact_types_counts || {});
        } else {

          setTypeCounts(prev => ({ ...prev, ...(res.data.artifact_types_counts || {}) }));
        }
        if (res.data.hosts_available?.length) setHostsAvail(res.data.hosts_available);
        if (res.data.users_available?.length) setUsersAvail(res.data.users_available);
      }
    } catch { setRecords([]); setTotal(0); }
    setLoading(false);
  }, [caseId, routeEvidenceId, searchOp]);

  useEffect(() => {
    if (!caseId || isIsolated) return;
    evidenceAPI.list(caseId)
      .then(r => {
        const list = Array.isArray(r.data) ? r.data : (r.data?.evidence || []);
        setEvidenceList(list);
      })
      .catch(() => setEvidenceList([]));
  }, [caseId, isIsolated]);

  useEffect(() => {
    function h(e) {
      if (evidenceFilterRef.current && !evidenceFilterRef.current.contains(e.target)) {
        setShowEvidenceFilter(false);
      }
    }
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const initSearchRef = useRef(searchParams.get('search') || '');

  useEffect(() => {
    if (caseId) {
      const srch = initSearchRef.current;
      initSearchRef.current = '';
      setPage(1); setExcludedTypes(new Set()); setSearch(srch);
      setStartTime(''); setEndTime(''); setSelectedRow(null);
      setSelectedEvidenceIds(new Set());
      loadTimeline(1, '', srch, '', '', pageSize, 'desc', 'timestamp', '', '', resultIdFilter, null);
    }
  }, [caseId]);

  useEffect(() => {
    if (!caseId) return;
    try {
      const raw = localStorage.getItem(`heimdall_pins_${caseId}`);
      if (raw) {
        const parsed = JSON.parse(raw);
        setPinnedRows(new Map(Object.entries(parsed)));
      } else {
        setPinnedRows(new Map());
      }
    } catch { setPinnedRows(new Map()); }
  }, [caseId]);

  function getPinKey(r) {
    return `${r.artifact_type}_${r.timestamp}_${r.source || ''}`.substring(0, 120);
  }

  function togglePin(e, r) {
    e.stopPropagation();
    const key = getPinKey(r);
    setPinnedRows(prev => {
      const n = new Map(prev);
      n.has(key) ? n.delete(key) : n.set(key, r);
      try {
        localStorage.setItem(`heimdall_pins_${caseId}`, JSON.stringify(Object.fromEntries(n)));
      } catch (_e) {}
      return n;
    });
  }

  useEffect(() => {
    if (!caseId) return;
    try {
      const raw = localStorage.getItem(`heimdall_col_prefs_${caseId}`);
      if (raw) {
        const saved = JSON.parse(raw);
        if (saved.hidden)   setHiddenCols(new Set(saved.hidden));
        if (saved.widths)   setColWidths(new Map(Object.entries(saved.widths)));
        if (saved.order)    setColOrder(saved.order);
      }
    } catch (_e) {}
  }, [caseId]);

  useEffect(() => {
    if (!caseId) return;
    timelineRulesAPI.list(caseId)
      .then(r => {
        const rules = r.data?.rules || r.data || [];
        colorRulesRef.current = sortRules(Array.isArray(rules) ? rules : []);
      })
      .catch(() => { colorRulesRef.current = []; });
  }, [caseId]);

  const prevResultIdRef = useRef(resultIdFilter);
  useEffect(() => {
    if (prevResultIdRef.current !== resultIdFilter && caseId) {
      prevResultIdRef.current = resultIdFilter;
      setPage(1);
      loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter);
    }
  }, [resultIdFilter]);

  function handlePivotFilter(value) {
    setSearch(value);
    setPage(1);
    loadTimeline(1, includeParam(excludedTypes, availTypes), value, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds);
  }

  function applyFilter() {
    if (dateError) return;
    setPage(1); loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds);
  }
  function clearFilters() {
    setSearch(''); setExcludedTypes(new Set()); setStartTime(''); setEndTime('');
    setHostFilter(''); setUserFilter(''); setResultIdFilter('');
    setSortCol('timestamp'); setSortDir('desc');
    setServerSortCol('timestamp'); setServerSortDir('desc');
    setMultiSort([]); setGroupByFields([]);
    setSelectedEvidenceIds(new Set());

    setShowBookmarks(false);
    setConfidenceFilter(null);
    setForensicTagFilter(null);
    setColFilters({});
    setColFilterCombinator('AND');
    setJumpTs('');
    setDateError(null);
    setPage(1); loadTimeline(1, '', '', '', '', pageSize, 'desc', 'timestamp', '', '', '', null, []);
  }

  function saveColPrefs(hidden, widths, order) {
    if (!caseId) return;
    const prefs = {
      hidden: [...hidden],
      widths: Object.fromEntries(widths),
      order,
    };
    try { localStorage.setItem(`heimdall_col_prefs_${caseId}`, JSON.stringify(prefs)); } catch (_e) {}
  }
  function handleColHiddenChange(newSet) {
    setHiddenCols(newSet); saveColPrefs(newSet, colWidths, colOrder);
  }
  function handleColWidthChange(newMap) {
    setColWidths(newMap); saveColPrefs(hiddenCols, newMap, colOrder);
  }
  function handleColOrderChange(newArr) {
    setColOrder(newArr); saveColPrefs(hiddenCols, colWidths, newArr);
  }
  function changePage(p) { setPage(p); loadTimeline(p, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds); }
  function changePageSize(s) { setPageSize(s); setPage(1); loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, s, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds); }

  const prevPageSizeRef = useRef(pageSize);
  useEffect(() => {
    if (workbench && caseId) {
      prevPageSizeRef.current = pageSize;
      setWorkbenchEnteredAt(Date.now());
      setToolbarCollapsed(true);
      if (pageSize < 2000) {
        changePageSize(2000);
      }
    } else if (!workbench) {
      setWorkbenchEnteredAt(null);
      setToolbarCollapsed(false);

      changePageSize(prevPageSizeRef.current < 2000 ? prevPageSizeRef.current : 500);
    }
  }, [workbench]);

  const SERVER_SORTABLE = new Set(['timestamp', 'artifact_type', 'description', 'source']);

  const MULTI_SORT_MAX = 3;

  function handleSort(colKey, e) {
    if (!SERVER_SORTABLE.has(colKey)) {

      if (sortCol === colKey) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
      else { setSortCol(colKey); setSortDir('asc'); }
      return;
    }

    if (e?.shiftKey && multiSort.length > 0) {

      const existing = multiSort.findIndex(s => s.col === colKey);
      let newMs;
      if (existing !== -1) {

        newMs = multiSort.map((s, idx) =>
          idx === existing ? { col: s.col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : s
        );
      } else {

        const appended = [...multiSort, { col: colKey, dir: 'desc' }];
        newMs = appended.slice(0, MULTI_SORT_MAX);
      }
      setMultiSort(newMs);

      setSortCol(newMs[0].col); setSortDir(newMs[0].dir);
      setServerSortCol(newMs[0].col); setServerSortDir(newMs[0].dir);
      setPage(1);
      loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize,
        newMs[0].dir, newMs[0].col, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds, newMs);
    } else {

      const newDir = (serverSortCol === colKey && serverSortDir === 'desc') ? 'asc' : 'desc';
      const newMs = [{ col: colKey, dir: newDir }];
      setMultiSort(newMs);
      setSortCol(colKey); setSortDir(newDir);
      setServerSortCol(colKey); setServerSortDir(newDir);
      setPage(1);
      loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize,
        newDir, colKey, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds, newMs);
    }
  }

  const sortedRecords = useMemo(() => {

    if (SERVER_SORTABLE.has(sortCol) || !sortCol) return records;
    return [...records].sort((a, b) => {
      const va = String(a[sortCol] ?? ''), vb = String(b[sortCol] ?? '');
      return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  }, [records, sortCol, sortDir]);

  const displayedRecords = useMemo(() => {
    let r = sortedRecords;
    if (showBookmarksOnly) r = r.filter((_, i) => bookmarks.has((page - 1) * pageSize + i));
    if (confidenceFilter) r = r.filter((_, i) => {
      const g = (page - 1) * pageSize + i;
      return tagData.get(g)?.level === confidenceFilter;
    });
    if (forensicTagFilter) r = r.filter((_, i) => {
      const g = (page - 1) * pageSize + i;
      return tagData.get(g)?.tags?.includes(forensicTagFilter);
    });
    return r;
  }, [sortedRecords, showBookmarksOnly, bookmarks, confidenceFilter, forensicTagFilter, tagData, page, pageSize]);

  const colFilteredRecords = useMemo(() => {
    const active = Object.entries(colFilters).filter(([, f]) =>
      f && (f.op === 'empty' || f.op === 'not_empty' || (f.value ?? '').trim())
    );
    if (!active.length) return displayedRecords;
    const method = colFilterCombinator === 'OR' ? 'some' : 'every';
    return displayedRecords.filter(r =>
      active[method](([key, filter]) => applyColFilter(getColFieldValue(r, key), filter))
    );
  }, [displayedRecords, colFilters, colFilterCombinator]);

  const flatRows = useMemo(() => {
    if (groupByFields.length === 0) {
      return colFilteredRecords.map((record, localIndex) => ({ type: 'row', record, localIndex }));
    }
    const result = [];
    const prevValues = new Array(groupByFields.length).fill(null);

    colFilteredRecords.forEach((r, localIndex) => {

      for (let lvl = 0; lvl < groupByFields.length; lvl++) {
        const field = groupByFields[lvl];
        const val   = r[field] ?? '—';
        if (val !== prevValues[lvl]) {

          for (let deeper = lvl; deeper < groupByFields.length; deeper++) prevValues[deeper] = null;
          prevValues[lvl] = val;
          const color = field === 'artifact_type' ? artifactColor(val) : 'var(--fl-dim)';
          result.push({ type: 'group', level: lvl, field, value: val, color });
        }
      }
      result.push({ type: 'row', record: r, localIndex });
    });
    return result;
  }, [colFilteredRecords, groupByFields]);

  const rowVirtualizer = useVirtualizer({
    count:           flatRows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize:    (i) => {
      if (flatRows[i]?.type !== 'group') return 26;
      const lvl = flatRows[i].level ?? 0;
      return lvl === 0 ? 28 : 24;
    },
    overscan:        15,
  });

  function handleRowClick(e, localIndex) {
    if (e.shiftKey && lastClickedRowRef.current !== null) {
      const start = Math.min(lastClickedRowRef.current, localIndex);
      const end   = Math.max(lastClickedRowRef.current, localIndex);
      setSelectedRows(prev => {
        const n = new Set(prev);
        for (let i = start; i <= end; i++) n.add(i);
        return n;
      });
    } else if (e.ctrlKey || e.metaKey) {
      setSelectedRows(prev => {
        const n = new Set(prev);
        n.has(localIndex) ? n.delete(localIndex) : n.add(localIndex);
        return n;
      });
      lastClickedRowRef.current = localIndex;
    } else {

      setSelectedRows(new Set());
      const next = selectedRow === localIndex ? null : localIndex;
      setSelectedRow(next);
      if (next !== selectedRow) { setDetailTab('details'); setRowNotes([]); setNoteText(''); setNoteEditId(null); }
      lastClickedRowRef.current = localIndex;
    }
  }

  function computeRowRef(r) {
    if (!r) return null;
    const str = `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`;
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = (((h << 5) + h) ^ str.charCodeAt(i)) >>> 0;
    return h.toString(16).padStart(8, '0');
  }

  useEffect(() => {
    if (detailTab !== 'notes' || selectedRow === null || !caseId) return;
    const r = displayedRecords[selectedRow];
    if (!r) return;
    const ref = computeRowRef(r);
    const controller = new AbortController();
    artifactsAPI.getNotes(caseId, ref, { signal: controller.signal })
      .then(res => setRowNotes(res.data?.notes ?? []))
      .catch(err => { if (err.name !== 'CanceledError' && err.name !== 'AbortError') setRowNotes([]); });
    return () => controller.abort();
  }, [detailTab, selectedRow, caseId]);

  async function submitRowNote() {
    const r = selectedRow !== null ? displayedRecords[selectedRow] : null;
    if (!noteText.trim() || !r || !caseId) return;
    setNoteSaving(true);
    try {
      const ref = computeRowRef(r);
      await artifactsAPI.createNote(caseId, ref, noteText.trim());
      setNoteText('');
      const res = await artifactsAPI.getNotes(caseId, ref);
      setRowNotes(res.data?.notes ?? []);
    } catch {}
    setNoteSaving(false);
  }

  async function saveEditRowNote(noteId) {
    const r = selectedRow !== null ? displayedRecords[selectedRow] : null;
    if (!noteEditText.trim() || !r || !caseId) return;
    try {
      const ref = computeRowRef(r);
      await artifactsAPI.updateNote(caseId, ref, noteId, noteEditText.trim());
      const res = await artifactsAPI.getNotes(caseId, ref);
      setRowNotes(res.data?.notes ?? []);
      setNoteEditId(null);
    } catch {}
  }

  async function deleteRowNote(noteId) {
    const r = selectedRow !== null ? displayedRecords[selectedRow] : null;
    if (!r || !caseId) return;
    try {
      const ref = computeRowRef(r);
      await artifactsAPI.deleteNote(caseId, ref, noteId);
      const res = await artifactsAPI.getNotes(caseId, ref);
      setRowNotes(res.data?.notes ?? []);
    } catch {}
  }

  function toggleRowCheckbox(e, localIndex) {
    e.stopPropagation();
    setSelectedRows(prev => {
      const n = new Set(prev);
      n.has(localIndex) ? n.delete(localIndex) : n.add(localIndex);
      return n;
    });
    lastClickedRowRef.current = localIndex;
  }

  function selectAllVisible() {
    if (selectedRows.size === colFilteredRecords.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(colFilteredRecords.map((_, i) => i)));
    }
  }

  function copySelectedToClipboard() {
    const SEP = csvSep;
    const cols = ['timestamp', 'artifact_type', 'description', 'source', 'host_name', 'user_name', 'process_name', 'mitre_tactic'];
    const rows  = [...selectedRows].sort((a, b) => a - b).map(i => colFilteredRecords[i]).filter(Boolean);
    const lines = [
      cols.join(SEP),
      ...rows.map(r => cols.map(c => {
        const v = c === 'timestamp' ? fmtTs(r[c]) : String(r[c] ?? '');
        return v.includes(SEP) || v.includes('"') || v.includes('\n')
          ? `"${v.replace(/"/g, '""')}"`
          : v;
      }).join(SEP)),
    ];
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 1500);
    });
  }

  useEffect(() => {
    function onKeyDown(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'c' && selectedRows.size > 0 && !workbench) {
        e.preventDefault();
        copySelectedToClipboard();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [selectedRows, colFilteredRecords, csvSep, workbench]);

  useEffect(() => { setSelectedRows(new Set()); }, [records, page]);

  function toggleBookmark(e, globalIdx) {
    e.stopPropagation();
    setBookmarks(prev => { const n = new Set(prev); n.has(globalIdx) ? n.delete(globalIdx) : n.add(globalIdx); return n; });
  }

  function openTagPicker(e, globalIdx) {
    e.stopPropagation();
    if (tagPickerIdx === globalIdx) { setTagPickerIdx(null); return; }
    const rect = e.currentTarget.getBoundingClientRect();
    const top  = Math.min(rect.bottom + 4, window.innerHeight - 320);
    const left = Math.min(rect.left, window.innerWidth - 296);
    setTagPickerPos({ top, left });
    setTagPickerIdx(globalIdx);
  }

  function handleTagChange(globalIdx, data) {
    setTagData(prev => { const n = new Map(prev); n.set(globalIdx, data); return n; });
  }

  const taggedCount     = useMemo(() => [...tagData.values()].filter(d => d.level || d.tags?.length).length, [tagData]);
  const confidenceCounts = useMemo(() => {
    const c = {};
    for (const d of tagData.values()) if (d.level) c[d.level] = (c[d.level] || 0) + 1;
    return c;
  }, [tagData]);

  // ── Filter presets (localStorage) ───────────────────────────────────────────
  const PRESET_KEY = `heimdall_col_filter_presets_${caseId || 'global'}`;
  function loadPresets() {
    try { return JSON.parse(localStorage.getItem(PRESET_KEY) || '{}'); } catch { return {}; }
  }
  function savePreset(name) {
    if (!name.trim()) return;
    const presets = loadPresets();
    presets[name.trim()] = { filters: colFilters, combinator: colFilterCombinator };
    try { localStorage.setItem(PRESET_KEY, JSON.stringify(presets)); } catch (_e) {}
  }
  function deletePreset(name) {
    const presets = loadPresets();
    delete presets[name];
    try { localStorage.setItem(PRESET_KEY, JSON.stringify(presets)); } catch (_e) {}
  }
  function applyPreset(preset) {
    setColFilters(preset.filters || {});
    setColFilterCombinator(preset.combinator || 'AND');
    setShowColFilters(true);
    setShowPresetMenu(false);
  }

  // ── Client-side filtered CSV export ─────────────────────────────────────────
  function exportFilteredCSV() {
    if (!colFilteredRecords.length) return;
    const SEP = csvSep;
    const cols = visibleCols.map(c => c.key);
    const headers = visibleCols.map(c => c.label);
    function esc(v) {
      const s = String(v ?? '');
      return (s.includes(SEP) || s.includes('"') || s.includes('\n'))
        ? `"${s.replace(/"/g, '""')}"`
        : s;
    }
    const lines = [
      headers.map(esc).join(SEP),
      ...colFilteredRecords.map(r =>
        cols.map(k => esc(k === 'timestamp' ? fmtTs(r.timestamp) : getColFieldValue(r, k))).join(SEP)
      ),
    ];
    const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `timeline-filtered-${caseId}-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function exportCSV() {
    if (!caseId || csvLoading) return;
    setCsvLoading(true);
    try {
      const params = { sep: csvSep };
      if (excludedTypes.size > 0) params.artifact_types = includeParam(excludedTypes, availTypes);
      if (search)          params.search      = search;
      if (startTime)       params.start_time  = startTime;
      if (endTime)         params.end_time    = endTime;
      if (hostFilter)      params.host_name   = hostFilter;
      if (userFilter)      params.user_name   = userFilter;
      if (routeEvidenceId) params.evidence_id = routeEvidenceId;
      const resp = await collectionAPI.exportCsv(caseId, params);
      const blob = new Blob([resp.data], { type: 'text/csv;charset=utf-8' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url;
      a.download = `timeline-${caseId}-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {

    } finally {
      setCsvLoading(false);
    }
  }

  const activeArtifactType = useMemo(() => {
    if (!availTypes.length) return null;
    const visible = availTypes.filter(t => !excludedTypes.has(t));
    return visible.length === 1 ? visible[0] : null;
  }, [availTypes, excludedTypes]);

  const virtualCols = useMemo(() => {
    if (!activeArtifactType) return [];

    const virtual = getEffectiveVirtual(activeArtifactType, ARTIFACT_PROFILES);
    if (!virtual?.length) return [];
    return virtual.map(v => ({
      key:     v.key,
      label:   v.label,
      width:   120,
      mono:    true,
      virtual: true,
    }));

  }, [activeArtifactType, columnPrefVersion]);

  const visibleCols = useMemo(() => {

    let base = [...COLUMNS];
    if (colOrder.length > 0) {
      const orderMap = Object.fromEntries(colOrder.map((k, i) => [k, i]));
      base = [...base].sort((a, b) => {
        const ai = orderMap[a.key] ?? 999;
        const bi = orderMap[b.key] ?? 999;
        return ai - bi;
      });
    }

    base = base.filter(c => !hiddenCols.has(c.key));

    base = base.map(c => colWidths.has(c.key) ? { ...c, width: colWidths.get(c.key) } : c);

    return [...base, ...virtualCols];
  }, [COLUMNS, hiddenCols, colOrder, colWidths, virtualCols]);
  const hasFilters      = search || excludedTypes.size > 0 || startTime || endTime || hostFilter || userFilter || selectedEvidenceIds.size > 0;
  const activeFilterCount = [search, startTime, endTime, hostFilter, userFilter].filter(Boolean).length
    + (excludedTypes.size > 0 ? 1 : 0)
    + (selectedEvidenceIds.size > 0 ? 1 : 0);
  const hasResultFilter = Boolean(resultIdFilter);
  const selectedCase = cases.find(c => String(c.id) === String(caseId));

  return (
    <div style={{ height: '100%', background: 'var(--fl-bg)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {cellCtxMenu && (
        <div
          onMouseDown={e => e.stopPropagation()}
          style={{
            position: 'fixed', top: cellCtxMenu.y, left: cellCtxMenu.x, zIndex: 2000,
            background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 8,
            padding: '4px 0', minWidth: 240, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
            fontFamily: 'monospace', fontSize: 11,
          }}>
          <div style={{ padding: '3px 12px 5px', fontSize: 9, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid var(--fl-sep)' }}>
            {cellCtxMenu.colLabel} — <span style={{ color: 'var(--fl-dim)' }}>{String(cellCtxMenu.value).substring(0, 40)}</span>
          </div>
          {[
            { label: '⊃  Filtrer contient',  op: 'contains',     title: 'Ajouter un filtre "contient" sur cette colonne' },
            { label: '＝  Filtrer égal',      op: 'equals',       title: 'Ajouter un filtre "égal" sur cette colonne' },
            { label: '⊄  Exclure valeur',    op: 'not_contains', title: 'Ajouter un filtre "ne contient pas" sur cette colonne' },
            { label: '≠  Exclure exact',     op: 'not_equals',   title: 'Ajouter un filtre "différent" sur cette colonne' },
          ].map(item => (
            <button
              key={item.op}
              title={item.title}
              onClick={() => {
                setColFilters(prev => ({ ...prev, [cellCtxMenu.colKey]: { op: item.op, value: cellCtxMenu.value } }));
                setShowColFilters(true);
                setCellCtxMenu(null);
              }}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '5px 14px',
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-on-dark)', fontSize: 11,
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-card)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}

      {tagPickerIdx !== null && (
        <div style={{ position: 'fixed', top: tagPickerPos.top, left: tagPickerPos.left, zIndex: 1000 }}>
          <TagPicker
            globalIdx={tagPickerIdx}
            tagData={tagData}
            onChange={handleTagChange}
            onClose={() => setTagPickerIdx(null)}
            anchorRef={tagAnchorRef}
          />
        </div>
      )}

      {workbench && toolbarCollapsed && (
        <div style={{
          flexShrink: 0, height: 32,
          display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px',
          background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-accent)',
        }}>
          <LayoutTemplate size={12} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
          <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: 'var(--fl-accent)', letterSpacing: '0.06em' }}>
            WORKBENCH
          </span>
          {total > 0 && (
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-subtle)', background: '#4d82c010', border: '1px solid #4d82c020', borderRadius: 3, padding: '1px 6px' }}>
              {total.toLocaleString()} events
            </span>
          )}
          {activeArtifactType && (
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-purple)', background: '#8b72d610', border: '1px solid #8b72d620', borderRadius: 3, padding: '1px 6px' }}>
              {activeArtifactType}
            </span>
          )}
          {hasFilters && (
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-warn)', background: '#d97c2010', border: '1px solid #d97c2020', borderRadius: 3, padding: '1px 6px' }}>
              {activeFilterCount} filtre{activeFilterCount > 1 ? 's' : ''}
            </span>
          )}
          <div style={{ flex: 1 }} />
          <button
            onClick={() => setToolbarCollapsed(false)}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
              background: 'rgba(77,130,192,0.08)', border: '1px solid var(--fl-accent)',
              color: 'var(--fl-accent)', cursor: 'pointer',
            }}
            title="Afficher la barre d'outils"
          >
            <ChevronDown size={10} /> Déplier
          </button>
        </div>
      )}

      <div className="fl-header" style={{
        padding: '8px 16px 6px', marginBottom: 0, flexShrink: 0,
        background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-sep)',
        flexDirection: 'column', alignItems: 'flex-start', gap: 6,
        display: workbench && toolbarCollapsed ? 'none' : 'flex',
      }}>
        {/* ── Ligne 1 : titre + count ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Clock size={15} style={{ color: 'var(--fl-accent)' }} />
          <span className="fl-header-title" style={{ marginBottom: 0, fontSize: 14 }}>Super Timeline</span>
          {total > 0 && (
            <span className="fl-badge" style={{ background: '#4d82c012', color: 'var(--fl-accent)', border: '1px solid #4d82c025' }}>
              {total.toLocaleString()} {t('timeline.records_badge')}
            </span>
          )}
          {bookmarks.size > 0 && (
            <button onClick={() => setShowBookmarks(v => !v)}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              style={{
                background: showBookmarksOnly ? '#f59e0b18' : 'transparent',
                color: showBookmarksOnly ? '#f59e0b' : 'var(--fl-dim)',
                border: `1px solid ${showBookmarksOnly ? '#f59e0b40' : 'var(--fl-border)'}`,
              }}>
              <Star size={11} fill={showBookmarksOnly ? '#f59e0b' : 'none'} />
              {bookmarks.size} {bookmarks.size > 1 ? t('timeline.bookmarks_count_pl') : t('timeline.bookmarks_count')}
            </button>
          )}
        </div>
        {/* ── Ligne 2 : actions groupées ── */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>

          {selectedRows.size > 0 && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '3px 10px',
              background: '#0e1e33', border: '1px solid #4d82c040', borderRadius: 6,
            }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-accent)', fontWeight: 700 }}>
                {selectedRows.size} sélectionné{selectedRows.size > 1 ? 's' : ''}
              </span>
              <div style={{ width: 1, height: 12, background: 'var(--fl-border)' }} />
              <button
                onClick={copySelectedToClipboard}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                title="Copier en CSV (Ctrl+C)"
                style={{ color: copyFeedback ? '#22c55e' : 'var(--fl-on-dark)', gap: 4 }}>
                <Copy size={11} />
                {copyFeedback ? 'Copié !' : 'Copier CSV'}
              </button>
              <button
                onClick={() => {
                  const rows = [...selectedRows].sort((a, b) => a - b).map(i => colFilteredRecords[i]).filter(Boolean);
                  const globalIdxs = rows.map((_, i) => {
                    const localI = [...selectedRows].sort((a, b) => a - b)[i];
                    return (page - 1) * pageSize + localI;
                  });
                  setBookmarks(prev => {
                    const n = new Set(prev);
                    globalIdxs.forEach(g => n.add(g));
                    return n;
                  });
                }}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                style={{ color: '#f59e0b', gap: 4 }}
                title="Bookmarker les lignes sélectionnées">
                <Star size={11} /> Bookmarker
              </button>
              <button
                onClick={() => setSelectedRows(new Set())}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                style={{ color: 'var(--fl-muted)' }}>
                <X size={10} />
              </button>
            </div>
          )}

          {/* ─ Export ──────────────────────────────────── */}
          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 3, padding: '2px 6px', borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)' }}>
            <select
              value={csvSep}
              onChange={e => setCsvSep(e.target.value)}
              disabled={!records.length}
              title="Délimiteur CSV"
              style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: records.length ? 'var(--fl-dim)' : 'var(--fl-muted)', fontSize: 11, padding: '2px 4px', height: 26 }}
            >
              <option value=",">, (CSV)</option>
              <option value=";">; (Excel FR)</option>
              <option value={'\t'}>Tab</option>
            </select>
            <button onClick={exportCSV} disabled={!records.length || csvLoading} className="fl-btn fl-btn-ghost fl-btn-sm"
              style={{ color: records.length ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>
              {csvLoading ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Download size={12} />} Export CSV
            </button>
            {colFilteredRecords.length !== records.length && (
              <button
                onClick={exportFilteredCSV}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                title={`Exporter uniquement les ${colFilteredRecords.length.toLocaleString('fr-FR')} lignes après filtres colonne`}
                style={{ color: '#22c55e', border: '1px solid #22c55e30', background: '#22c55e08' }}>
                <Download size={12} /> Export filtré ({colFilteredRecords.length.toLocaleString('fr-FR')})
              </button>
            )}
          </div>

          {/* ─ Filtres col. / Presets ──────────────── */}
          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />
          {/* groupe visuel filtres */}
          {records.length > 0 && !workbench && (
            <button
              onClick={() => { setShowColFilters(v => !v); if (showColFilters) setColFilters({}); }}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title="Filtres rapides par colonne"
              style={{
                color: showColFilters ? '#22c55e' : 'var(--fl-dim)',
                background: showColFilters ? 'rgba(34,197,94,0.08)' : 'transparent',
                border: `1px solid ${showColFilters ? '#22c55e30' : 'var(--fl-border)'}`,
              }}>
              <Layers size={12} />
              Filtres col.
              {Object.values(colFilters).some(f => f && (f.op === 'empty' || f.op === 'not_empty' || (f.value ?? '').trim())) && (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'inline-block', marginLeft: 2 }} />
              )}
            </button>
          )}

          {records.length > 0 && !workbench && (
            <div ref={presetMenuRef} style={{ position: 'relative' }}>
              <button
                onClick={() => setShowPresetMenu(v => !v)}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                title="Sauvegarder / charger un preset de filtres colonne"
                style={{
                  color: showPresetMenu ? '#22c55e' : 'var(--fl-dim)',
                  background: showPresetMenu ? 'rgba(34,197,94,0.08)' : 'transparent',
                  border: `1px solid ${showPresetMenu ? '#22c55e30' : 'var(--fl-border)'}`,
                }}>
                <Star size={12} /> Presets
                {Object.keys(loadPresets()).length > 0 && (
                  <span style={{ fontSize: 9, color: '#22c55e', marginLeft: 2 }}>({Object.keys(loadPresets()).length})</span>
                )}
              </button>
              {showPresetMenu && (() => {
                const presets = loadPresets();
                const names = Object.keys(presets);
                return (
                  <div style={{
                    position: 'absolute', top: '100%', left: 0, zIndex: 400, marginTop: 4,
                    background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 8,
                    padding: '6px 0', minWidth: 240, boxShadow: '0 8px 24px rgba(0,0,0,0.7)',
                  }}>
                    <div style={{ padding: '3px 12px 6px', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      Presets de filtres colonne
                    </div>
                    {names.length === 0 && (
                      <div style={{ padding: '4px 14px 6px', fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'monospace' }}>Aucun preset sauvegardé</div>
                    )}
                    {names.map(name => (
                      <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 8px 2px 12px' }}>
                        <button
                          onClick={() => applyPreset(presets[name])}
                          style={{
                            flex: 1, textAlign: 'left', padding: '4px 4px', fontSize: 11,
                            fontFamily: 'monospace', background: 'none', border: 'none',
                            cursor: 'pointer', color: 'var(--fl-on-dark)',
                          }}
                          onMouseEnter={e => { e.currentTarget.style.color = '#22c55e'; }}
                          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-on-dark)'; }}
                        >
                          {name}
                          <span style={{ marginLeft: 6, fontSize: 9, color: 'var(--fl-subtle)' }}>
                            ({Object.keys(presets[name].filters || {}).length} col. · {presets[name].combinator || 'AND'})
                          </span>
                        </button>
                        <button
                          onClick={() => { deletePreset(name); setShowPresetMenu(false); setTimeout(() => setShowPresetMenu(true), 0); }}
                          title="Supprimer ce preset"
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: '2px 4px', borderRadius: 3 }}
                          onMouseEnter={e => { e.currentTarget.style.color = '#f87171'; }}
                          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                        >
                          <X size={10} />
                        </button>
                      </div>
                    ))}
                    {names.length > 0 && <div style={{ height: 1, background: 'var(--fl-sep)', margin: '4px 0' }} />}
                    <div style={{ display: 'flex', gap: 4, padding: '4px 10px' }}>
                      <input
                        value={presetName}
                        onChange={e => setPresetName(e.target.value)}
                        onKeyDown={e => {
                          if (e.key === 'Enter' && presetName.trim()) {
                            savePreset(presetName);
                            setPresetName('');
                            setShowPresetMenu(false);
                            setTimeout(() => setShowPresetMenu(true), 0);
                          }
                        }}
                        placeholder="Nom du preset…"
                        style={{
                          flex: 1, padding: '3px 7px', fontSize: 10, fontFamily: 'monospace',
                          background: 'var(--fl-card)', border: '1px solid var(--fl-border)',
                          borderRadius: 4, color: 'var(--fl-text)', outline: 'none',
                        }}
                      />
                      <button
                        onClick={() => {
                          if (!presetName.trim()) return;
                          savePreset(presetName);
                          setPresetName('');
                          setShowPresetMenu(false);
                          setTimeout(() => setShowPresetMenu(true), 0);
                        }}
                        style={{
                          padding: '3px 9px', fontSize: 10, fontFamily: 'monospace',
                          background: '#22c55e18', border: '1px solid #22c55e40',
                          borderRadius: 4, color: '#22c55e', cursor: 'pointer',
                        }}>
                        Sauvegarder
                      </button>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}

          {/* ─ Colonnes ──────────────────────────────── */}
          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />
          <div style={{ position: 'relative' }} ref={colMenuRef}>
            <button onClick={() => setShowColMenu(v => !v)} className="fl-btn fl-btn-ghost fl-btn-sm" title={t('timeline.columns')}>
              <Eye size={12} />
            </button>
            {showColMenu && (
              <div style={{
                position: 'absolute', right: 0, top: '100%', marginTop: 4, zIndex: 50,
                background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: 8, minWidth: 170,
                boxShadow: '0 8px 24px #00000060',
              }}>
                {COLUMNS.map(c => (
                  <label key={c.key} style={{
                    display: 'flex', alignItems: 'center', gap: 7, padding: '4px 8px',
                    fontFamily: 'JetBrains Mono, monospace', fontSize: 11, cursor: 'pointer',
                    color: hiddenCols.has(c.key) ? 'var(--fl-muted)' : 'var(--fl-on-dark)',
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
          {records.length > 0 && !workbench && (
            <button
              onClick={() => setShowColumnManager(v => !v)}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title="Gérer les colonnes (show/hide, order, width)"
              style={{
                color: showColumnManager ? '#22c55e' : 'var(--fl-dim)',
                background: showColumnManager ? 'rgba(34,197,94,0.08)' : 'transparent',
                border: `1px solid ${showColumnManager ? '#22c55e30' : 'var(--fl-border)'}`,
              }}>
              <Columns size={12} />
              Colonnes
              {(hiddenCols.size > 0 || colOrder.length > 0 || colWidths.size > 0) && (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'inline-block', marginLeft: 2 }} />
              )}
            </button>
          )}

          {activeArtifactType && (
            <button
              onClick={() => setShowColumnEditor(v => !v)}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title={`Personnaliser les colonnes pour ${activeArtifactType}`}
              style={{
                color: showColumnEditor ? '#a371f7' : 'var(--fl-dim)',
                background: showColumnEditor ? 'rgba(163,113,247,0.08)' : 'transparent',
                border: `1px solid ${showColumnEditor ? '#a371f740' : 'var(--fl-border)'}`,
              }}
            >
              <Eye size={12} />
              Champs
              {getColumnPref(activeArtifactType) && (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#a371f7', display: 'inline-block', marginLeft: 2 }} />
              )}
            </button>
          )}

          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />
          {records.length > 0 && (
            <button
              onClick={() => setShowColorRules(v => !v)}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title="Moteur de règles couleur — surlignage forensique"
              style={{
                color: showColorRules ? 'var(--fl-warn)' : 'var(--fl-dim)',
                background: showColorRules ? 'rgba(217,124,32,0.1)' : 'transparent',
                border: `1px solid ${showColorRules ? '#d97c2030' : 'var(--fl-border)'}`,
              }}>
              <Palette size={12} />
              Règles couleur
              {colorRulesRef.current.filter(r => r.is_active).length > 0 && (
                <span style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: 'var(--fl-warn)', display: 'inline-block', marginLeft: 2,
                }} />
              )}
            </button>
          )}
          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />
          <button
            onClick={() => setWorkbench(v => !v)}
            disabled={!records.length}
            className="fl-btn fl-btn-ghost fl-btn-sm"
            style={{
              color: workbench ? 'var(--fl-accent)' : (records.length ? 'var(--fl-dim)' : 'var(--fl-muted)'),
              background: workbench ? 'rgba(77,130,192,0.1)' : 'transparent',
              border: `1px solid ${workbench ? '#4d82c030' : 'var(--fl-border)'}`,
            }}
          >
            <LayoutTemplate size={12} /> Workbench
          </button>
          
          {workbench && (
            <button
              onClick={() => setToolbarCollapsed(true)}
              className="fl-btn fl-btn-ghost fl-btn-sm"
              title="Réduire la barre d'outils pour agrandir le Workbench"
              style={{ color: 'var(--fl-subtle)', border: '1px solid var(--fl-card)' }}
            >
              <ChevronUp size={12} /> Replier
            </button>
          )}
        </div>
      </div>

      <div style={{ display: workbench && toolbarCollapsed ? 'none' : undefined }}>

        {total > 0 && (
          <div style={{ padding: '5px 16px 6px', background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-sep)',
            display: 'flex', flexDirection: 'column', gap: 5, flexShrink: 0 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center', minHeight: 30 }}>

            <div style={{ display: 'flex', gap: 3, alignItems: 'center' }}>
              <div style={{ position: 'relative' }}>
                <Search size={11} style={{ position: 'absolute', left: 7, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)' }} />
                <input value={search} onChange={e => setSearch(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && applyFilter()}
                  placeholder={t('timeline.search_ph')}
                  style={{ paddingLeft: 22, paddingRight: 8, paddingTop: 4, paddingBottom: 4,
                    borderRadius: 5, fontSize: 11, fontFamily: 'monospace', width: 185,
                    background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', outline: 'none' }} />
              </div>
              <select value={searchOp} onChange={e => { setSearchOp(e.target.value); applyFilter(); }}
                title="Opérateur de recherche"
                style={{ padding: '3px 5px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
                  background: 'var(--fl-bg)', border: `1px solid ${searchOp !== 'contains' ? 'var(--fl-purple)' : 'var(--fl-border)'}`,
                  color: searchOp !== 'contains' ? 'var(--fl-purple)' : 'var(--fl-dim)', outline: 'none', cursor: 'pointer' }}>
                <option value="contains">{t('timeline.op_contains')}</option>
                <option value="equals">{t('timeline.op_equals')}</option>
                <option value="starts_with">{t('timeline.op_starts')}</option>
                <option value="regex">{t('timeline.op_regex')}</option>
              </select>
            </div>

            <div style={{ width: 1, height: 16, background: 'var(--fl-sep)', flexShrink: 0 }} />
            <div ref={groupByMenuRef} style={{ position: 'relative' }}>
              <button onClick={() => setShowGroupByMenu(v => !v)}
                title="Grouper les lignes par champ(s)"
                style={{ padding: '3px 8px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                  background: groupByFields.length > 0 ? '#8b72d618' : 'transparent',
                  color: groupByFields.length > 0 ? 'var(--fl-purple)' : 'var(--fl-dim)',
                  border: `1px solid ${groupByFields.length > 0 ? '#8b72d635' : 'var(--fl-border)'}` }}>
                <LayoutTemplate size={10} />
                {groupByFields.length > 0
                  ? `Group: ${groupByFields.join(' › ')}`
                  : t('timeline.group_by_type')}
                <ChevronDown size={9} />
              </button>
              {showGroupByMenu && (
                <div style={{
                  position: 'absolute', top: '100%', left: 0, zIndex: 300, marginTop: 4,
                  background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 8,
                  padding: '6px 0', minWidth: 190, boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                }}>
                  <div style={{ padding: '3px 12px 6px', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Grouper par (max 3 niveaux)
                  </div>
                  {[
                    { key: 'artifact_type', label: 'Type d\'artefact' },
                    { key: 'host_name',     label: 'Machine' },
                    { key: 'user_name',     label: 'Utilisateur' },
                  ].map(opt => {
                    const idx = groupByFields.indexOf(opt.key);
                    const active = idx !== -1;
                    return (
                      <button key={opt.key}
                        onClick={() => {
                          setGroupByFields(prev => {
                            if (active) return prev.filter(k => k !== opt.key);
                            if (prev.length >= 3) return prev;
                            return [...prev, opt.key];
                          });
                        }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                          padding: '5px 12px', fontSize: 11, fontFamily: 'monospace', textAlign: 'left',
                          background: active ? '#8b72d618' : 'none', border: 'none', cursor: 'pointer',
                          color: active ? 'var(--fl-purple)' : 'var(--fl-on-dark)',
                        }}>
                        <span style={{ width: 12, height: 12, borderRadius: 2, border: `1px solid ${active ? 'var(--fl-purple)' : 'var(--fl-subtle)'}`, background: active ? 'var(--fl-purple)' : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#000', flexShrink: 0 }}>
                          {active ? '✓' : ''}
                        </span>
                        {active && <span style={{ fontSize: 9, color: 'var(--fl-purple)', marginRight: 2 }}>{idx + 1}</span>}
                        {opt.label}
                      </button>
                    );
                  })}
                  {groupByFields.length > 0 && (
                    <>
                      <div style={{ height: 1, background: 'var(--fl-sep)', margin: '4px 0' }} />
                      <button onClick={() => { setGroupByFields([]); setShowGroupByMenu(false); }}
                        style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 12px', fontSize: 10, fontFamily: 'monospace', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)' }}>
                        <X size={9} /> Désactiver le groupement
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>

            <div style={{ width: 1, height: 16, background: 'var(--fl-sep)', flexShrink: 0 }} />
            <input type="datetime-local" value={startTime}
              onChange={e => {
                const newStart = e.target.value;
                if (endTime && newStart && endTime < newStart) setDateError('La date de fin doit être après la date de début');
                else setDateError(null);
                setStartTime(newStart);
              }}
              style={{ padding: '3px 6px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                background: 'var(--fl-bg)', border: `1px solid ${dateError ? '#f87171' : 'var(--fl-border)'}`, color: '#8899bb', colorScheme: 'dark', outline: 'none' }} />
            <span style={{ fontSize: 11, color: dateError ? '#f87171' : 'var(--fl-card)' }}>→</span>
            <input type="datetime-local" value={endTime}
              onChange={e => {
                const newEnd = e.target.value;
                if (startTime && newEnd && newEnd < startTime) setDateError('La date de fin doit être après la date de début');
                else setDateError(null);
                setEndTime(newEnd);
              }}
              title={dateError || undefined}
              style={{ padding: '3px 6px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                background: 'var(--fl-bg)', border: `1px solid ${dateError ? '#f87171' : 'var(--fl-border)'}`, color: '#8899bb', colorScheme: 'dark', outline: 'none' }} />
            {dateError && <span style={{ fontSize: 10, color: '#f87171', whiteSpace: 'nowrap' }}>{dateError}</span>}

            <div style={{ display: 'flex', gap: 3, alignItems: 'center', marginLeft: 2 }}>
              <span style={{ fontSize: 9, color: 'var(--fl-subtle)', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>⏩</span>
              <input
                value={jumpTs}
                onChange={e => setJumpTs(e.target.value)}
                onKeyDown={e => {
                  if (e.key !== 'Enter') return;
                  const trimmed = jumpTs.trim();
                  if (!trimmed) return;
                  const dt = new Date(trimmed);
                  if (isNaN(dt.getTime())) return;
                  const iso = dt.toISOString().slice(0, 16);
                  setStartTime(iso);
                  setPage(1);
                  loadTimeline(1, includeParam(excludedTypes, availTypes), search, iso, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds.size > 0 ? selectedEvidenceIds : null);
                  setJumpTs('');
                }}
                placeholder="Aller à… (YYYY-MM-DD HH:MM)"
                title="Saisir un timestamp pour positionner la vue (Entrée pour valider)"
                style={{
                  padding: '3px 6px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace', width: 195,
                  background: 'var(--fl-bg)', border: `1px solid ${jumpTs.trim() ? '#f59e0b60' : 'var(--fl-border)'}`,
                  color: jumpTs.trim() ? '#f59e0b' : '#8899bb', outline: 'none',
                }}
              />
            </div>

            {hostsAvail.length > 0 && (
              <select value={hostFilter} onChange={e => setHostFilter(e.target.value)}
                style={{ padding: '3px 6px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                  background: 'var(--fl-bg)', border: `1px solid ${hostFilter ? 'var(--fl-accent)' : 'var(--fl-border)'}`,
                  color: hostFilter ? 'var(--fl-accent)' : '#8899bb', outline: 'none' }}>
                <option value="">{t('timeline.machine_all')}</option>
                {hostsAvail.map(h => <option key={h} value={h}>{h}</option>)}
              </select>
            )}
            {usersAvail.length > 0 && (
              <select value={userFilter} onChange={e => setUserFilter(e.target.value)}
                style={{ padding: '3px 6px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                  background: 'var(--fl-bg)', border: `1px solid ${userFilter ? 'var(--fl-purple)' : 'var(--fl-border)'}`,
                  color: userFilter ? 'var(--fl-purple)' : '#8899bb', outline: 'none' }}>
                <option value="">{t('timeline.user_all')}</option>
                {usersAvail.map(u => <option key={u} value={u}>{u}</option>)}
              </select>
            )}

            {!isIsolated && evidenceList.length > 0 && (
              <div ref={evidenceFilterRef} style={{ position: 'relative' }}>
                <button
                  onClick={() => setShowEvidenceFilter(v => !v)}
                  style={{
                    padding: '3px 8px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    background: selectedEvidenceIds.size > 0 ? '#06b6d418' : 'transparent',
                    color: selectedEvidenceIds.size > 0 ? '#06b6d4' : 'var(--fl-dim)',
                    border: `1px solid ${selectedEvidenceIds.size > 0 ? '#06b6d435' : 'var(--fl-border)'}`,
                  }}
                  title={t('timeline.filter_by_source')}
                >
                  <FolderOpen size={10} />
                  {t('timeline.sources')} {selectedEvidenceIds.size > 0 ? `(${selectedEvidenceIds.size})` : ''}
                </button>
                {showEvidenceFilter && (
                  <div style={{
                    position: 'absolute', top: '100%', left: 0, zIndex: 200, marginTop: 4,
                    background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 8,
                    padding: '6px 0', minWidth: 240, maxWidth: 340,
                    boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                  }}>
                    <div style={{ padding: '3px 10px 6px', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      {t('timeline.filter_by_collection')}
                    </div>
                    
                    <button
                      onClick={() => {
                        setSelectedEvidenceIds(new Set());
                        setPage(1);
                        loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, null);
                        setShowEvidenceFilter(false);
                      }}
                      style={{
                        display: 'block', width: '100%', textAlign: 'left', padding: '5px 12px',
                        fontSize: 11, fontFamily: 'monospace', background: selectedEvidenceIds.size === 0 ? '#06b6d412' : 'none',
                        border: 'none', cursor: 'pointer',
                        color: selectedEvidenceIds.size === 0 ? '#06b6d4' : 'var(--fl-dim)',
                      }}
                      onMouseEnter={e => { if (selectedEvidenceIds.size !== 0) e.currentTarget.style.background = 'var(--fl-card)'; }}
                      onMouseLeave={e => { if (selectedEvidenceIds.size !== 0) e.currentTarget.style.background = 'none'; }}
                    >
                      {t('timeline.all_collections')}
                    </button>
                    <div style={{ height: 1, background: 'var(--fl-sep)', margin: '3px 0' }} />
                    {evidenceList.map(ev => {
                      const sel = selectedEvidenceIds.has(ev.id);
                      return (
                        <button
                          key={ev.id}
                          onClick={() => {
                            const ns = new Set(selectedEvidenceIds);
                            sel ? ns.delete(ev.id) : ns.add(ev.id);
                            setSelectedEvidenceIds(ns);
                            setPage(1);
                            loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, ns.size > 0 ? ns : null);
                          }}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 7, width: '100%', textAlign: 'left',
                            padding: '5px 12px', fontSize: 11, fontFamily: 'monospace',
                            background: sel ? '#06b6d412' : 'none', border: 'none', cursor: 'pointer',
                            color: sel ? '#06b6d4' : 'var(--fl-on-dark)',
                          }}
                          onMouseEnter={e => { if (!sel) e.currentTarget.style.background = 'var(--fl-card)'; }}
                          onMouseLeave={e => { if (!sel) e.currentTarget.style.background = 'none'; }}
                        >
                          <span style={{ width: 10, height: 10, borderRadius: 2, border: `1px solid ${sel ? '#06b6d4' : 'var(--fl-subtle)'}`, background: sel ? '#06b6d4' : 'transparent', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, color: '#000' }}>
                            {sel ? '✓' : ''}
                          </span>
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
                            {ev.name}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Filtrer + Reset — right-aligned end of Row A */}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
              {hasResultFilter && (
                <button
                  onClick={() => { setResultIdFilter(''); setPage(1); loadTimeline(1, includeParam(excludedTypes, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, ''); }}
                  style={{ padding: '3px 8px', borderRadius: 10, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
                    background: '#8b72d618', border: '1px solid #8b72d640', color: 'var(--fl-purple)',
                    display: 'flex', alignItems: 'center', gap: 5 }}
                  title={t('timeline.remove_collection_filter')}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fl-purple)', display: 'inline-block', flexShrink: 0 }} />
                  {t('timeline.collection_label')} : {resultIdFilter.slice(0, 8)}…
                  <X size={9} />
                </button>
              )}
              <button onClick={applyFilter}
                style={{ padding: '3px 10px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
                  background: '#4d82c018', border: '1px solid #4d82c030', color: 'var(--fl-accent)',
                  display: 'flex', alignItems: 'center', gap: 4 }}>
                <Filter size={10} /> {t('timeline.apply_filter')}
              </button>
              {hasFilters && (
                <button onClick={clearFilters}
                  style={{ padding: '3px 8px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
                    background: 'transparent', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)',
                    display: 'flex', alignItems: 'center', gap: 4 }}>
                  <X size={10} /> Reset
                  {activeFilterCount > 0 && (
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                      width: 16, height: 16, borderRadius: '50%', fontSize: 9, fontWeight: 700,
                      background: 'var(--fl-accent)', color: '#fff',
                    }}>{activeFilterCount}</span>
                  )}
                </button>
              )}
            </div>
          </div>{/* end Row A */}

          {/* Row B — artefacts colorés + lignes */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, alignItems: 'center' }}>
            <button
              onClick={() => { setExcludedTypes(new Set()); setPage(1); loadTimeline(1, '', search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds); }}
              style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
                cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                background: excludedTypes.size === 0 ? '#4d82c018' : 'transparent',
                color: excludedTypes.size === 0 ? 'var(--fl-accent)' : 'var(--fl-dim)',
                border: `1px solid ${excludedTypes.size === 0 ? '#4d82c035' : 'var(--fl-border)'}` }}>
              {t('common.all')}
            </button>
            {availTypes.map(t => {
              const col      = tabColor(t);
              const excluded = excludedTypes.has(t);
              const count    = typeCounts[t];
              return (
                <button key={t}
                  title={excluded ? `Afficher ${t}` : `Masquer ${t}`}
                  onClick={() => {
                    const ns = new Set(excludedTypes);
                    excluded ? ns.delete(t) : ns.add(t);
                    setExcludedTypes(ns);
                    setPage(1);
                    loadTimeline(1, includeParam(ns, availTypes), search, startTime, endTime, pageSize, serverSortDir, serverSortCol, hostFilter, userFilter, resultIdFilter, selectedEvidenceIds);
                  }}
                  style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    background: excluded ? `${col}14` : `${col}22`,
                    color: excluded ? `${col}80` : col,
                    border: `1px ${excluded ? 'dashed' : 'solid'} ${excluded ? col + '50' : col + '90'}`,
                    transition: 'all 0.15s',
                    textDecoration: excluded ? 'line-through' : 'none' }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: excluded ? `${col}55` : col, display: 'inline-block', flexShrink: 0 }} />
                  {t}
                  {count != null && (
                    <span style={{ fontSize: 9, opacity: excluded ? 0.5 : 0.75 }}>({count.toLocaleString('fr-FR')})</span>
                  )}
                  {excluded && <EyeOff size={8} style={{ marginLeft: 1, flexShrink: 0 }} />}
                </button>
              );
            })}

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>{t('timeline.rows_per_page')} :</span>
              {PAGE_SIZES.map(s => (
                <button key={s} onClick={() => changePageSize(s)}
                  style={{ padding: '2px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                    background: pageSize === s ? '#4d82c018' : 'transparent', color: pageSize === s ? 'var(--fl-accent)' : 'var(--fl-dim)',
                    border: `1px solid ${pageSize === s ? '#4d82c030' : 'var(--fl-border)'}` }}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          </div>
        )}

        {taggedCount > 0 && (
          <div style={{ padding: '7px 10px', background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
            borderRadius: 8, marginBottom: 8, display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
            <Tag size={11} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)', marginRight: 4 }}>
              {t('timeline.filter_by_tag')}
            </span>

            {CONFIDENCE_LEVELS_T.map(l => {
              if (!confidenceCounts[l.key]) return null;
              const active = confidenceFilter === l.key;
              return (
                <button key={l.key} onClick={() => setConfidenceFilter(active ? null : l.key)}
                  style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    background: active ? l.bg : 'transparent', color: active ? l.color : 'var(--fl-dim)',
                    border: `1px solid ${active ? l.color + '40' : 'var(--fl-border)'}` }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: l.color, display: 'inline-block', flexShrink: 0 }} />
                  {l.label}
                  <span style={{ opacity: 0.55 }}>({confidenceCounts[l.key]})</span>
                </button>
              );
            })}

            {FORENSIC_TAGS_T.map(t => {
              const count = [...tagData.values()].filter(d => d.tags?.includes(t.key)).length;
              if (!count) return null;
              const active = forensicTagFilter === t.key;
              return (
                <button key={t.key} onClick={() => setForensicTagFilter(active ? null : t.key)}
                  style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    background: active ? `${t.color}20` : 'transparent', color: active ? t.color : 'var(--fl-dim)',
                    border: `1px solid ${active ? t.color + '40' : 'var(--fl-border)'}` }}>
                  {t.label}
                  <span style={{ opacity: 0.55 }}>({count})</span>
                </button>
              );
            })}

            {(confidenceFilter || forensicTagFilter) && (
              <button onClick={() => { setConfidenceFilter(null); setForensicTagFilter(null); }}
                style={{ padding: '2px 6px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                  cursor: 'pointer', background: 'transparent', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)',
                  display: 'flex', alignItems: 'center', gap: 3 }}>
                <X size={9} /> Reset tags
              </button>
            )}
          </div>
        )}
      </div>

      {!loading && total === 0 && caseId && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
          <Clock size={44} style={{ color: 'var(--fl-border)', marginBottom: 12 }} />
          {isIsolated ? (
            <>
              <p style={{ fontFamily: 'monospace', fontSize: 14, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 6 }}>
                {t('timeline.no_isolated_data')}
              </p>
              <p style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', marginBottom: 6, textAlign: 'center', maxWidth: 400 }}>
                {t('timeline.reparse_hint')}
              </p>
              <p style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', marginBottom: 20, fontStyle: 'italic' }}>
                {isolatedEvidenceName || routeEvidenceId}
              </p>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={() => navigate(`/cases/${routeCaseId}`, { state: { tab: 'evidence' } })}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 18px', borderRadius: 6, fontSize: 11,
                    fontFamily: 'monospace', fontWeight: 600, background: 'var(--fl-accent)', color: '#ffffff', border: 'none', cursor: 'pointer' }}>
                  <ArrowLeft size={13} /> {t('timeline.go_to_evidence')}
                </button>
                <button
                  onClick={() => navigate(`/cases/${routeCaseId}`, { state: { tab: 'timeline' } })}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 6, fontSize: 11,
                    fontFamily: 'monospace', fontWeight: 600, background: 'var(--fl-panel)', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)', cursor: 'pointer' }}>
                  <ChevronLeft size={13} /> {t('timeline.back_to_case')}
                </button>
              </div>
            </>
          ) : (
            <>
              <p style={{ fontFamily: 'monospace', fontSize: 14, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 6 }}>
                {t('timeline.no_parsed_data')}
              </p>
              <p style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', marginBottom: 20 }}>
                {selectedCase?.case_number} — {t('timeline.parse_hint')}
              </p>
              <button onClick={() => navigate('/collection')}
                style={{ padding: '8px 20px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
                  fontWeight: 600, background: 'var(--fl-accent)', color: '#ffffff', border: 'none', cursor: 'pointer' }}>
                {t('timeline.import_collection')}
              </button>
            </>
          )}
        </div>
      )}

      {total > 0 && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 0, minHeight: 0 }}>
          {loading ? (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Loader2 size={20} className="animate-spin" style={{ color: 'var(--fl-accent)' }} />
            </div>
          ) : workbench ? (
            <SuperTimelineWorkbench
              records={displayedRecords}
              availTypes={availTypes}
              caseId={caseId}
              onFilterTimeline={handlePivotFilter}
              socket={socket}
              total={total}
              page={page}
              totalPages={totalPages}
              onPageChange={changePage}
              onExitWorkbench={() => { setWorkbench(false); setAiTabActive(false); }}
              enteredAt={workbenchEnteredAt}
              onAITabChange={setAiTabActive}
            />
          ) : (
            <>
              
              <div style={{ display: 'flex', flex: '1 1 auto', minHeight: 0, overflow: 'hidden' }}>
              <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              
              {pinnedRows.size > 0 && (
                <div style={{ marginBottom: 4, border: '1px solid #d97c2030', borderRadius: 8, overflow: 'hidden', flexShrink: 0 }}>
                  
                  <div
                    onClick={() => setShowPinned(v => !v)}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', cursor: 'pointer',
                      background: 'var(--fl-bg)', borderBottom: showPinned ? '1px solid #d97c2020' : 'none' }}>
                    <Pin size={10} style={{ color: 'var(--fl-warn)' }} />
                    <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: 'var(--fl-warn)' }}>
                      Épinglés ({pinnedRows.size})
                    </span>
                    <button onClick={e => { e.stopPropagation(); setPinnedRows(new Map()); try { localStorage.removeItem(`heimdall_pins_${caseId}`); } catch {} }}
                      style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', fontSize: 9, fontFamily: 'monospace' }}>
                      Tout désépingler
                    </button>
                  </div>
                  
                  {showPinned && (
                    <div style={{ maxHeight: 140, overflowY: 'auto' }}>
                      {[...pinnedRows.entries()].map(([key, pr]) => {
                        const pac = artifactColor(pr.artifact_type);
                        return (
                          <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 6,
                            padding: '3px 10px', borderBottom: '1px solid var(--fl-bg)',
                            background: 'transparent', fontSize: 10, fontFamily: 'monospace' }}>
                            <button onClick={e => togglePin(e, pr)}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                              <Pin size={9} fill="var(--fl-warn)" style={{ color: 'var(--fl-warn)' }} />
                            </button>
                            <span style={{ color: 'var(--fl-accent)', flexShrink: 0 }}>{fmtTs(pr.timestamp).substring(0, 19)}</span>
                            <span style={{ padding: '0px 5px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                              background: `${pac}18`, color: pac, border: `1px solid ${pac}30`, flexShrink: 0 }}>
                              {pr.artifact_type}
                            </span>
                            <span style={{ color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {(pr.description || pr.source || '').substring(0, 100)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              <div
                ref={tableContainerRef}
                style={{ overflow: 'auto', border: '1px solid var(--fl-sep)', borderRadius: 4, flex: '1 1 auto', position: 'relative', background: 'var(--fl-bg)' }}
              >
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, tableLayout: 'fixed' }}>
                  <colgroup>
                    <col style={{ width: 24 }} />
                    <col style={{ width: 20 }} />
                    <col style={{ width: 18 }} />
                    <col style={{ width: 32 }} />
                    {visibleCols.map(c => <col key={c.key} style={{ width: c.flex ? undefined : (colWidths.get(c.key) ?? c.width) }} />)}
                  </colgroup>

                  <thead style={{ position: 'sticky', top: 0, zIndex: 10, background: 'var(--fl-bg)' }}>
                    
                    <tr>
                      
                      <th style={{ padding: '6px 4px', borderBottom: '2px solid #20293a', textAlign: 'center' }}
                          onClick={selectAllVisible} title="Tout sélectionner / désélectionner">
                        {colFilteredRecords.length > 0 && selectedRows.size === colFilteredRecords.length
                          ? <CheckSquare size={11} style={{ color: 'var(--fl-accent)', cursor: 'pointer' }} />
                          : <Square size={11} style={{ color: selectedRows.size > 0 ? '#4d82c060' : 'var(--fl-border)', cursor: 'pointer' }} />
                        }
                      </th>
                      
                      <th style={{ padding: '6px 4px', borderBottom: '2px solid #20293a', textAlign: 'center' }}
                        title="Signets">
                        <Star size={9} style={{ color: 'var(--fl-border)' }} />
                      </th>
                      
                      <th style={{ padding: '6px 4px', borderBottom: '2px solid #20293a', textAlign: 'center' }}
                        title="Épingles">
                        <Pin size={9} style={{ color: 'var(--fl-border)' }} />
                      </th>
                      
                      <th style={{ padding: '6px 4px', borderBottom: '2px solid #20293a',
                        fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-subtle)', textAlign: 'center' }}>
                        <Tag size={9} />
                      </th>
                      {visibleCols.map(col => {

                        const sortIdx   = multiSort.findIndex(s => s.col === col.key);
                        const isMulti   = sortIdx !== -1;
                        const sortEntry = isMulti ? multiSort[sortIdx] : null;

                        const isSingle  = !isMulti && sortCol === col.key;
                        const isActive  = isMulti || isSingle;
                        const direction = isMulti ? sortEntry.dir : sortDir;

                        const rankLabel = isMulti && multiSort.length > 1 ? String(sortIdx + 1) : '';
                        return (
                          <th key={col.key} onClick={e => handleSort(col.key, e)}
                            title={SERVER_SORTABLE.has(col.key) ? 'Clic — tri / Shift+Clic — tri secondaire' : undefined}
                            style={{ padding: '6px 8px', textAlign: 'left', cursor: 'pointer', userSelect: 'none',
                              fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
                              letterSpacing: '0.07em', textTransform: 'uppercase',
                              color: isActive ? 'var(--fl-accent)' : 'var(--fl-subtle)',
                              borderBottom: showColFilters ? 'none' : '2px solid #20293a', whiteSpace: 'nowrap' }}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                              {col.label}
                              {isActive && (
                                <span style={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  {direction === 'asc' ? <SortAsc size={10} /> : <SortDesc size={10} />}
                                  {rankLabel && (
                                    <sup style={{ fontSize: 8, lineHeight: 1, color: 'var(--fl-accent)', fontWeight: 700 }}>
                                      {rankLabel}
                                    </sup>
                                  )}
                                </span>
                              )}
                            </span>
                          </th>
                        );
                      })}
                    </tr>
                    
                    {showColFilters && (
                      <tr style={{ background: 'var(--fl-card)' }}>
                        <th style={{ padding: '2px 4px', borderBottom: '1px solid var(--fl-sep)' }} />
                        <th style={{ padding: '2px 4px', borderBottom: '1px solid var(--fl-sep)' }} />
                        <th style={{ padding: '2px 4px', borderBottom: '1px solid var(--fl-sep)' }} />
                        <th style={{ padding: '2px 4px', borderBottom: '1px solid var(--fl-sep)', textAlign: 'center', verticalAlign: 'middle' }}>
                          <button
                            onClick={() => setColFilterCombinator(v => v === 'AND' ? 'OR' : 'AND')}
                            title={colFilterCombinator === 'AND' ? 'Mode: toutes les colonnes doivent correspondre (ET) — cliquer pour passer en OU' : 'Mode: au moins une colonne doit correspondre (OU) — cliquer pour passer en ET'}
                            style={{
                              fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                              padding: '1px 5px', borderRadius: 3, cursor: 'pointer',
                              background: colFilterCombinator === 'OR' ? '#f59e0b18' : '#22c55e18',
                              color: colFilterCombinator === 'OR' ? '#f59e0b' : '#22c55e',
                              border: `1px solid ${colFilterCombinator === 'OR' ? '#f59e0b40' : '#22c55e40'}`,
                            }}>
                            {colFilterCombinator}
                          </button>
                        </th>
                        {visibleCols.map(col => {
                          const f   = colFilters[col.key] || { op: 'contains', value: '' };
                          const op  = f.op  ?? 'contains';
                          const val = f.value ?? '';
                          const isActive = op === 'empty' || op === 'not_empty' || val.trim();
                          return (
                            <th key={`cf-${col.key}`} style={{ padding: '2px 4px', borderBottom: '1px solid var(--fl-sep)' }}>
                              <div style={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                                <select
                                  value={op}
                                  onChange={e => setColFilters(prev => ({ ...prev, [col.key]: { op: e.target.value, value: prev[col.key]?.value ?? '' } }))}
                                  title="Opérateur de filtre"
                                  style={{
                                    flexShrink: 0, width: 26, fontSize: 10, padding: '1px 1px',
                                    background: isActive ? '#0e1e10' : 'var(--fl-bg)',
                                    border: `1px solid ${isActive ? '#22c55e60' : 'var(--fl-border)'}`,
                                    borderRadius: 3, color: isActive ? '#22c55e' : 'var(--fl-dim)',
                                    outline: 'none', cursor: 'pointer', appearance: 'none', textAlign: 'center',
                                  }}>
                                  <option value="contains"   title="Contient">⊃</option>
                                  <option value="not_contains" title="Ne contient pas">⊄</option>
                                  <option value="equals"     title="Égal">＝</option>
                                  <option value="not_equals" title="Différent">≠</option>
                                  <option value="starts_with" title="Commence par">▷</option>
                                  <option value="ends_with"  title="Finit par">◁</option>
                                  <option value="regex"      title="Regex">~</option>
                                  <option value="empty"      title="Vide">∅</option>
                                  <option value="not_empty"  title="Non vide">•</option>
                                </select>
                                {op !== 'empty' && op !== 'not_empty' && (
                                  <input
                                    value={val}
                                    onChange={e => setColFilters(prev => ({ ...prev, [col.key]: { op: prev[col.key]?.op ?? 'contains', value: e.target.value } }))}
                                    placeholder="…"
                                    title={`Filtrer ${col.label}`}
                                    style={{
                                      flex: 1, minWidth: 0, background: val.trim() ? '#0e1e10' : 'var(--fl-bg)',
                                      border: `1px solid ${val.trim() ? '#22c55e60' : 'var(--fl-border)'}`,
                                      borderRadius: 3, color: val.trim() ? '#22c55e' : 'var(--fl-dim)',
                                      fontSize: 9, padding: '2px 4px', fontFamily: 'monospace', outline: 'none',
                                    }}
                                  />
                                )}
                              </div>
                            </th>
                          );
                        })}
                      </tr>
                    )}
                  </thead>

                  <tbody>
                    
                    {rowVirtualizer.getVirtualItems().length > 0 && rowVirtualizer.getVirtualItems()[0].start > 0 && (
                      <tr><td colSpan={visibleCols.length + 4} style={{ height: rowVirtualizer.getVirtualItems()[0].start, padding: 0, border: 'none' }} /></tr>
                    )}

                    {rowVirtualizer.getVirtualItems().map(virtualItem => {
                      const item = flatRows[virtualItem.index];
                      if (!item) return null;

                      if (item.type === 'group') {
                        const gc    = item.color;
                        const lvl   = item.level ?? 0;
                        const indent = lvl * 14;
                        const fontSize = lvl === 0 ? 10 : 9;
                        const fontWeight = lvl === 0 ? 700 : 600;

                        const countVal = item.field === 'artifact_type' ? typeCounts[item.value] : null;
                        return (
                          <tr key={virtualItem.key} style={{ height: virtualItem.size, background: `${gc}${lvl === 0 ? '12' : '08'}`, userSelect: 'none' }}>
                            <td colSpan={visibleCols.length + 4} style={{
                              paddingLeft: 8 + indent, paddingRight: 8, paddingTop: 2, paddingBottom: 2,
                              fontFamily: 'monospace', fontSize, fontWeight,
                              color: gc, borderBottom: `1px solid ${gc}30`,
                              borderLeft: `${lvl === 0 ? 3 : 2}px solid ${gc}`,
                            }}>
                              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                {lvl === 0
                                  ? <span style={{ width: 7, height: 7, borderRadius: '50%', background: gc, display: 'inline-block' }} />
                                  : <span style={{ fontSize: 8, opacity: 0.7 }}>└</span>
                                }
                                <span style={{ opacity: 0.6, marginRight: 2, textTransform: 'uppercase', fontSize: fontSize - 1 }}>
                                  {item.field}:
                                </span>
                                {item.value}
                                {countVal != null && (
                                  <span style={{ opacity: 0.5 }}>({countVal.toLocaleString('fr-FR')})</span>
                                )}
                              </span>
                            </td>
                          </tr>
                        );
                      }

                      const { record: r, localIndex: i } = item;
                      const globalIdx  = (page - 1) * pageSize + i;
                      const acol       = artifactColor(r.artifact_type);
                      const isSel      = selectedRow === i;
                      const isChecked  = selectedRows.has(i);
                      const isBkm      = bookmarks.has(globalIdx);
                      const td         = tagData.get(globalIdx) || {};
                      const lvl        = td.level ? CONFIDENCE_MAP_T[td.level] : null;
                      const hayLevel   = !lvl && r.artifact_type === 'hayabusa' ? (r.raw?.level || null) : null;

                      const colorMatch = colorRulesRef.current.length > 0
                        ? evaluateColorRules(r, colorRulesRef.current)
                        : null;
                      const rowBg      = isChecked
                        ? '#0e1e33'
                        : isSel
                          ? '#11203a'
                          : lvl
                            ? lvl.bg
                            : colorMatch
                              ? `${colorMatch.color}1a`
                              : (HAY_SEVERITY_BG[hayLevel] ?? (i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'));

                      const rowAccent  = colorMatch ? colorMatch.color : (lvl ? lvl.color : (isSel ? acol : `${acol}60`));

                      return (
                        <tr
                          key={virtualItem.key}
                          onClick={e => handleRowClick(e, i)}
                          style={{
                            height: virtualItem.size,
                            background: rowBg,
                            borderLeft: `3px solid ${isChecked ? 'var(--fl-accent)' : rowAccent}`,
                            borderBottom: '1px solid var(--fl-bg)',
                            cursor: 'pointer',
                            transition: 'background 0.08s',
                          }}
                        >
                          
                          <td onClick={e => toggleRowCheckbox(e, i)}
                            style={{ padding: '2px 0', textAlign: 'center', width: 24 }}>
                            {isChecked
                              ? <CheckSquare size={10} style={{ color: 'var(--fl-accent)' }} />
                              : <Square size={10} style={{ color: 'var(--fl-border)' }} />
                            }
                          </td>

                          <td onClick={e => toggleBookmark(e, globalIdx)}
                            style={{ padding: '2px 0', textAlign: 'center', width: 20 }}>
                            <Star size={9} fill={isBkm ? '#f59e0b' : 'none'}
                              style={{ color: isBkm ? '#f59e0b' : 'var(--fl-border)' }} />
                          </td>

                          {(() => {
                            const pinKey = getPinKey(r);
                            const isPinned = pinnedRows.has(pinKey);
                            return (
                              <td onClick={e => togglePin(e, r)}
                                title={isPinned ? 'Désépingler cette ligne' : 'Épingler cette ligne en haut'}
                                style={{ padding: '2px 0', textAlign: 'center', width: 18 }}>
                                <Pin size={9} fill={isPinned ? 'var(--fl-warn)' : 'none'}
                                  style={{ color: isPinned ? 'var(--fl-warn)' : 'var(--fl-border)' }} />
                              </td>
                            );
                          })()}

                          <td ref={tagPickerIdx === globalIdx ? tagAnchorRef : null}
                            onClick={e => openTagPicker(e, globalIdx)}
                            style={{ padding: '2px 0', textAlign: 'center', width: 32 }}>
                            {lvl ? (
                              <span style={{ fontSize: 12, color: lvl.color }} title={lvl.label}>{lvl.dot}</span>
                            ) : td.tags?.length > 0 ? (
                              <Tag size={9} style={{ color: 'var(--fl-subtle)' }} />
                            ) : (
                              <span style={{ fontSize: 9, color: 'var(--fl-border)' }}>○</span>
                            )}
                          </td>

                          {visibleCols.map(col2 => {
                            let content;
                            if (col2.key === 'timestamp') {
                              content = <span style={{ color: 'var(--fl-accent)' }}>{fmtTs(r.timestamp)}</span>;
                            } else if (col2.key === 'artifact_type') {
                              content = (
                                <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 10,
                                  fontWeight: 700, fontFamily: 'monospace',
                                  background: `${acol}18`, color: acol, border: `1px solid ${acol}30` }}>
                                  {r.artifact_type}
                                </span>
                              );
                            } else if (col2.key === 'description') {
                              content = (
                                <span style={{ color: '#d0daf0' }}>
                                  <Highlight text={fmtDesc(r) || '-'} term={search} />
                                  {td.tags?.length > 0 && (
                                    <span style={{ marginLeft: 6 }}>
                                      {td.tags.map(key => {
                                        const ft = FORENSIC_TAG_MAP_T[key];
                                        return ft ? (
                                          <span key={key} style={{ marginLeft: 3, padding: '0px 5px', borderRadius: 8,
                                            fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
                                            background: `${ft.color}20`, color: ft.color, border: `1px solid ${ft.color}30` }}>
                                            {ft.label}
                                          </span>
                                        ) : null;
                                      })}
                                    </span>
                                  )}
                                </span>
                              );
                            } else if (col2.key === 'source') {
                              content = <span style={{ color: 'var(--fl-dim)' }}><Highlight text={fmtSrc(r).substring(0, 90)} term={search} /></span>;
                            } else if (col2.virtual && col2.key.startsWith('raw.')) {

                              const rawKey = col2.key.slice(4);
                              const rawVal = r.raw?.[rawKey];
                              content = rawVal != null
                                ? <span style={{ color: '#b8c8e8', fontSize: 10 }}>{String(rawVal).substring(0, 80)}</span>
                                : <span style={{ color: 'var(--fl-border)' }}>—</span>;
                            } else {
                              content = <span style={{ color: 'var(--fl-dim)' }}>{r[col2.key] || '-'}</span>;
                            }
                            return (
                              <td key={col2.key}
                                onContextMenu={e => {
                                  e.preventDefault();
                                  e.stopPropagation();
                                  const rawVal = getColFieldValue(r, col2.key);
                                  setCellCtxMenu({ x: e.clientX, y: e.clientY, colKey: col2.key, colLabel: col2.label, value: rawVal });
                                }}
                                style={{ padding: '3px 8px',
                                  fontFamily: col2.mono ? 'monospace' : undefined,
                                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                  maxWidth: col2.flex ? 0 : undefined }}>
                                {content}
                              </td>
                            );
                          })}
                        </tr>
                      );
                    })}

                    {(() => {
                      const items = rowVirtualizer.getVirtualItems();
                      if (!items.length) return null;
                      const bottom = rowVirtualizer.getTotalSize() - items[items.length - 1].end;
                      return bottom > 0 ? <tr><td colSpan={visibleCols.length + 4} style={{ height: bottom, padding: 0, border: 'none' }} /></tr> : null;
                    })()}
                  </tbody>
                </table>
              </div>
              </div>

              {(() => {
                const r    = selectedRow !== null ? displayedRecords[selectedRow] : null;
                if (!r) return null;
                const acol = artifactColor(r.artifact_type);
                const gIdx = selectedRow !== null ? (page - 1) * pageSize + selectedRow : -1;
                const td   = tagData.get(gIdx) || {};
                const lvl  = td.level ? CONFIDENCE_MAP_T[td.level] : null;
                const profile  = getProfileForArtifact(r.artifact_type);
                const labelMap = Object.fromEntries(
                  (profile?.virtual || []).map(col => [col.key.slice(4), col.label])
                );
                return (
                  <div style={{
                    width: 340,
                    flexShrink: 0,
                    display: 'flex',
                    flexDirection: 'column',
                    borderLeft: `3px solid ${acol}`,
                    boxShadow: `-4px 0 20px rgba(0,0,0,0.5)`,
                    background: '#0a0f1a',
                    overflow: 'hidden',
                  }}>
                    
                    {/* ── Header ── */}
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '6px 12px',
                      borderBottom: `1px solid ${acol}25`,
                      background: `linear-gradient(90deg, ${acol}14 0%, #0b101a 100%)`,
                      flexShrink: 0,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: acol, flexShrink: 0, boxShadow: `0 0 8px ${acol}90` }} />
                        <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.artifact_name}
                        </span>
                      </div>
                      <button onClick={() => setSelectedRow(null)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', display: 'flex', padding: 3, borderRadius: 4, flexShrink: 0 }}>
                        <X size={13} />
                      </button>
                    </div>

                    {/* ── Tab bar ── */}
                    <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', borderBottom: `1px solid ${acol}20`, background: '#07090f' }}>
                      {[
                        { id: 'details', label: 'Details', icon: null },
                        { id: 'notes',   label: 'Notes',   icon: MessageSquare, badge: rowNotes.length },
                      ].map(tb => (
                        <button key={tb.id} onClick={() => setDetailTab(tb.id)}
                          style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            padding: '6px 12px', fontSize: 10, fontFamily: 'monospace',
                            fontWeight: detailTab === tb.id ? 700 : 400,
                            color: detailTab === tb.id ? acol : 'var(--fl-muted)',
                            borderBottom: detailTab === tb.id ? `2px solid ${acol}` : '2px solid transparent',
                            display: 'flex', alignItems: 'center', gap: 4,
                          }}>
                          {tb.icon && <tb.icon size={9} />}
                          {tb.label}
                          {tb.badge > 0 && (
                            <span style={{ fontSize: 8, background: acol, color: '#000', borderRadius: 8, padding: '0 4px', fontWeight: 700 }}>
                              {tb.badge}
                            </span>
                          )}
                        </button>
                      ))}
                    </div>

                    {/* ── Details tab ── */}
                    {detailTab === 'details' && (
                    <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '10px 12px' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-accent)', width: '100%' }}>
                          {fmtTs(r.timestamp)}
                        </span>
                        {r.timestamp_column && (
                          <span style={{ fontFamily: 'monospace', fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--fl-sep)', color: 'var(--fl-dim)' }}>
                            {r.timestamp_column}
                          </span>
                        )}
                        <span style={{ fontFamily: 'monospace', fontSize: 9, padding: '1px 5px', borderRadius: 3, background: `${acol}18`, color: acol, border: `1px solid ${acol}35` }}>
                          {r.artifact_type}
                        </span>
                        {lvl && (
                          <span style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9, fontFamily: 'monospace', fontWeight: 700, background: lvl.bg, color: lvl.color, border: `1px solid ${lvl.color}40` }}>
                            {lvl.label}
                          </span>
                        )}
                        {td.tags?.map(key => {
                          const ft = FORENSIC_TAG_MAP_T[key];
                          return ft ? (
                            <span key={key} style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9, fontFamily: 'monospace', background: `${ft.color}18`, color: ft.color, border: `1px solid ${ft.color}30` }}>
                              {ft.label}
                            </span>
                          ) : null;
                        })}
                      </div>
                      {(fmtDesc(r) || r.description) && (
                        <div style={{ padding: '7px 9px', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-on-dark)', background: `${acol}0c`, borderRadius: 5, border: `1px solid ${acol}35`, marginBottom: 10, lineHeight: 1.6, wordBreak: 'break-word' }}>
                          {fmtDesc(r) || r.description}
                        </div>
                      )}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                        {Object.entries(r.raw || {})
                          .filter(([, v]) => v !== '' && v !== null && v !== undefined)
                          .map(([k, v]) => (
                            <div key={k} style={{ borderRadius: 4, overflow: 'hidden', border: `1px solid ${acol}28` }}>
                              <div style={{ fontFamily: 'monospace', fontSize: 9, color: acol, padding: '3px 7px', background: `${acol}18`, textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>
                                {labelMap[k] || k}
                              </div>
                              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#c0cfe0', padding: '5px 7px', wordBreak: 'break-all', lineHeight: 1.5, background: '#0b101a', borderTop: `1px solid ${acol}18` }}>
                                {String(v).substring(0, 500)}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                    )}

                    {/* ── Notes tab ── */}
                    {detailTab === 'notes' && (
                    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                      <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {rowNotes.length === 0 ? (
                          <div style={{ color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 11, textAlign: 'center', marginTop: 24 }}>
                            No notes yet — add one below
                          </div>
                        ) : rowNotes.map(n => (
                          <div key={n.id} style={{ borderRadius: 6, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', padding: '8px 10px' }}>
                            {noteEditId === n.id ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                <textarea value={noteEditText} onChange={e => setNoteEditText(e.target.value)}
                                  style={{ width: '100%', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px', resize: 'vertical', minHeight: 60, outline: 'none', boxSizing: 'border-box' }} />
                                <div style={{ display: 'flex', gap: 6 }}>
                                  <button onClick={() => saveEditRowNote(n.id)}
                                    style={{ padding: '3px 10px', borderRadius: 4, background: `${acol}18`, border: `1px solid ${acol}50`, color: acol, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                                    Save
                                  </button>
                                  <button onClick={() => setNoteEditId(null)}
                                    style={{ padding: '3px 10px', borderRadius: 4, background: 'none', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                                    Cancel
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <>
                                <div style={{ fontSize: 11, color: 'var(--fl-text)', lineHeight: 1.5, wordBreak: 'break-word', marginBottom: 6 }}>
                                  {n.note}
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                  <span style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'monospace' }}>
                                    {n.author_name || n.author_username} · {fmtLocal(n.created_at)}
                                    {n.updated_at !== n.created_at && ' (edited)'}
                                  </span>
                                  <div style={{ display: 'flex', gap: 6 }}>
                                    <button onClick={() => { setNoteEditId(n.id); setNoteEditText(n.note); }}
                                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', display: 'flex' }}>
                                      <Pencil size={10} />
                                    </button>
                                    <button onClick={() => deleteRowNote(n.id)}
                                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-danger)', display: 'flex' }}>
                                      <Trash2 size={10} />
                                    </button>
                                  </div>
                                </div>
                              </>
                            )}
                          </div>
                        ))}
                      </div>
                      <div style={{ flexShrink: 0, padding: '8px 12px', borderTop: '1px solid var(--fl-border2)', display: 'flex', gap: 8 }}>
                        <textarea
                          value={noteText}
                          onChange={e => setNoteText(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) submitRowNote(); }}
                          placeholder="Add a note… (Ctrl+Enter to send)"
                          style={{ flex: 1, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px', resize: 'none', height: 52, outline: 'none' }}
                        />
                        <button onClick={submitRowNote} disabled={noteSaving || !noteText.trim()}
                          style={{ padding: '0 12px', borderRadius: 4, background: noteText.trim() ? `${acol}18` : 'var(--fl-bg)', border: `1px solid ${noteText.trim() ? acol + '50' : 'var(--fl-border2)'}`, color: noteText.trim() ? acol : 'var(--fl-muted)', cursor: noteText.trim() ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace' }}>
                          <Send size={11} /> Send
                        </button>
                      </div>
                    </div>
                    )}
                  </div>
                );
              })()}
              </div>

              <ColumnManager
                open={showColumnManager}
                onClose={() => setShowColumnManager(false)}
                caseId={caseId}
                columns={COLUMNS}
                hiddenCols={hiddenCols}
                colWidths={colWidths}
                colOrder={colOrder}
                onHiddenChange={handleColHiddenChange}
                onWidthChange={handleColWidthChange}
                onOrderChange={handleColOrderChange}
              />

              <ColorRulesManager
                open={showColorRules}
                onClose={() => setShowColorRules(false)}
                caseId={caseId}
                onRulesChange={handleRulesChange}
              />

              <ArtifactColumnEditor
                artifactType={activeArtifactType}
                open={showColumnEditor && !!activeArtifactType}
                onClose={() => setShowColumnEditor(false)}
                onApply={() => setColumnPrefVersion(v => v + 1)}
              />

              {totalPages > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0, padding: '6px 8px 2px', borderTop: '1px solid var(--fl-sep)', marginTop: 6, position: 'relative' }}>
                  {/* count — left */}
                  <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', position: 'absolute', left: 8 }}>
                    {((page - 1) * pageSize + 1).toLocaleString()}–{Math.min(page * pageSize, total).toLocaleString()} / {total.toLocaleString()}
                  </span>
                  {/* navigation — centered */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, margin: '0 auto' }}>
                    {[['«', 1], null, [null, page - 1], null, [null, page + 1], null, ['»', totalPages]].map((item, idx) => {
                      if (item === null) {
                        if (idx === 1) return (
                          <button key="prev" disabled={page <= 1} onClick={() => changePage(page - 1)}
                            style={{ padding: '3px 6px', borderRadius: 4, display: 'flex', alignItems: 'center',
                              background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                              color: page <= 1 ? 'var(--fl-border)' : 'var(--fl-dim)', cursor: page <= 1 ? 'default' : 'pointer' }}>
                            <ChevronLeft size={12} />
                          </button>
                        );
                        if (idx === 3) return (
                          <span key="cur" style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', padding: '0 6px' }}>
                            {page} / {totalPages}
                          </span>
                        );
                        if (idx === 5) return (
                          <button key="next" disabled={page >= totalPages} onClick={() => changePage(page + 1)}
                            style={{ padding: '3px 6px', borderRadius: 4, display: 'flex', alignItems: 'center',
                              background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                              color: page >= totalPages ? 'var(--fl-border)' : 'var(--fl-dim)', cursor: page >= totalPages ? 'default' : 'pointer' }}>
                            <ChevronRight size={12} />
                          </button>
                        );
                        return null;
                      }
                      const [label, target] = item;
                      const disabled = target < 1 || target > totalPages || target === page;
                      return (
                        <button key={label} disabled={disabled} onClick={() => !disabled && changePage(target)}
                          style={{ padding: '3px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                            background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                            color: disabled ? 'var(--fl-border)' : 'var(--fl-dim)', cursor: disabled ? 'default' : 'pointer' }}>
                          {label}
                        </button>
                      );
                    })}
                    <input value={jumpPage} onChange={e => setJumpPage(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter') {
                          const p = parseInt(jumpPage);
                          if (p >= 1 && p <= totalPages) { changePage(p); setJumpPage(''); }
                        }
                      }}
                      placeholder={t('timeline.goto_page_ph')}
                      style={{ width: 70, padding: '3px 6px', borderRadius: 4, textAlign: 'center',
                        fontFamily: 'monospace', fontSize: 10, outline: 'none',
                        background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)' }} />
                  </div>
                  {/* tagged count — right */}
                  {taggedCount > 0 && (
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)',
                      display: 'flex', alignItems: 'center', gap: 4, position: 'absolute', right: 8 }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--fl-accent)',
                        display: 'inline-block', flexShrink: 0 }} />
                      {taggedCount} {taggedCount > 1 ? t('timeline.tagged_pl') : t('timeline.tagged_s')}
                    </span>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}

      <CaseChatPanel
        caseId={caseId}
        socket={socket}
        hidden={aiTabActive}
      />
    </div>
  );
}
