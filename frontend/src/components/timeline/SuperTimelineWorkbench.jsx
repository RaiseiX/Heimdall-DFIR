
import { useState, useRef, useEffect, useMemo, useCallback, Fragment } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table';
import { SortAsc, SortDesc, Copy, CheckCheck, Clock, FileText, HardDrive, Tag, MessageSquare, Send, Trash2, Pencil, ShieldAlert, Eye, AlertTriangle, ChevronDown, ChevronRight, Share2, Pin, PinOff, Globe2, X, Bot, Star, CheckSquare, Square, Cpu, GitBranch, Layers, Network, Target, Download, Users, TrendingUp, Search, Zap, Activity } from 'lucide-react';
import TimelinePlayback from './TimelinePlayback';
import TimelineHeatmap from './TimelineHeatmap';
import GanttView from './GanttView';
import MitreMatrixLive from './MitreMatrixLive';
import VerdictBadge from './VerdictBadge';
import CommandPalette from './CommandPalette';
import ContextMenu from './ContextMenu';
import AiAnalystPanel from './AiAnalystPanel';
import { artifactsAPI, detectionsAPI, pinsAPI, collectionAPI, iocsAPI } from '../../utils/api';
import { ARTIFACT_PROFILES } from '../../utils/artifactProfiles';

import { artifactColor as ac, HAY_SEVERITY_BG as HAYABUSA_SEV_BG } from '../../constants/artifactColors';
import { fmtTs, fmtLocal } from '../../utils/formatters';

function computeRef(r) {
  const str = `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`;
  let h = 5381;
  for (let i = 0; i < str.length; i++) {
    h = (((h << 5) + h) ^ str.charCodeAt(i)) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

const RAW_FIELD_PRIORITY = [

  'process_name','ProcessName','Image','process_path','command_line','CommandLine','CommandLine_full',
  'ParentImage','ParentCommandLine','ParentProcessName',

  'username','user_name','UserName','user','SubjectUserName','TargetUserName','account','AccountName',

  'file_path','FileName','TargetFilename','full_path','path','OriginalFileName',

  'key_path','TargetObject','value_name','Details','registry_path',

  'dst_ip','DestinationIp','SourceIp','src_ip','ip','hostname','remote_host',
  'DestinationHostname','dst_port','DestinationPort','src_port','SourcePort','Protocol',
  'url','domain','QueryName','Initiated',

  'md5','Hashes','sha1','sha256','hash','Imphash','MD5','SHA1','SHA256',

  'pid','ProcessId','ppid','ParentProcessId','EventID','event_id',
  'channel','Channel','computer','Computer','LogonId',

  'RuleName','Techniques','level','Level','Channel','RecordID',
];

function sortRawByPriority(entries) {
  return [...entries].sort(([a], [b]) => {
    const ia = RAW_FIELD_PRIORITY.indexOf(a);
    const ib = RAW_FIELD_PRIORITY.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });
}

const DESC_CHIP_RULES = [

  { test: s => /\.(exe|dll|bat|ps1|sh|py|cmd|vbs|js)(\s|$|:)/i.test(s) || /^(Image|Process|CommandLine|ParentImage):/i.test(s), color: '#c792ea', bg: '#c792ea28' },

  { test: s => /[A-Za-z]:\\|\/home\/|\/etc\/|\/var\/|\/tmp\/|%\w+%/i.test(s) || /^(Path|File|Dir|TargetFilename|ObjectName):/i.test(s), color: '#6ab0f5', bg: '#4d82c028' },

  { test: s => /^(User|Username|SubjectUserName|TargetUserName|Account):/i.test(s), color: '#d4a44c', bg: '#d4a44c28' },

  { test: s => /^(PID|ProcessId|ParentProcessId|ppid):/i.test(s) || /\bpid\s*[:=]\s*\d+/i.test(s), color: '#a98ee8', bg: '#8b72d628' },

  { test: s => /\b\d{1,3}(\.\d{1,3}){3}\b/.test(s) || /^(IP|DestinationIp|SourceIp|dst|src):/i.test(s), color: '#4ade80', bg: '#3fb95028' },

  { test: s => /^(MD5|SHA1|SHA256|Hash|Hashes):/i.test(s) || /\b[0-9a-f]{32,64}\b/i.test(s), color: '#58a6ff', bg: '#58a6ff28' },

  { test: s => /^(Key|Registry|TargetObject|HKLM|HKCU|HKU)/i.test(s), color: '#f0883e', bg: '#d97c2028' },

  { test: s => /^(Port|DestinationPort|SourcePort|dst_port|src_port):/i.test(s), color: '#79c0ff', bg: '#79c0ff28' },
];

function chipColor(segment) {
  for (const rule of DESC_CHIP_RULES) {
    if (rule.test(segment)) return { color: rule.color, bg: rule.bg };
  }
  return { color: '#7a9ab8', bg: '#7a9ab822' };
}

function shortenPath(p) {
  const norm = p.replace(/\\/g, '/');
  const parts = norm.split('/').filter(Boolean);
  if (parts.length <= 2) return p;
  return '…/' + parts.slice(-2).join('/');
}

function shortenHash(h) {
  if (h.length >= 32) return h.slice(0, 8) + '…';
  return h;
}

function extractChipDisplay(raw) {
  const s = raw.trim();
  const colonIdx = s.indexOf(':');
  if (colonIdx < 1 || colonIdx > 30) return s;
  const key = s.slice(0, colonIdx).trim();
  const val = s.slice(colonIdx + 1).trim();
  if (!val) return key;

  if (/^(MD5|SHA1|SHA256|Hash|Hashes|Imphash)$/i.test(key)) {
    return shortenHash(val);
  }
  if (/^(Image|ParentImage|TargetFilename|file_path|full_path|path|ObjectName|TargetObject)$/i.test(key)) {
    return shortenPath(val);
  }
  if (/^(CommandLine|CommandLine_full|command_line)$/i.test(key)) {
    const trimmed = val.length > 55 ? val.slice(0, 55) + '…' : val;
    return trimmed;
  }
  if (/^(PID|ProcessId|ParentProcessId|ppid|pid)$/i.test(key)) {
    return `PID ${val}`;
  }
  if (/^(Port|DestinationPort|SourcePort|dst_port|src_port)$/i.test(key)) {
    return `:${val}`;
  }
  if (val.length > 40) return val.slice(0, 40) + '…';
  return val;
}

function DescriptionCell({ value }) {
  if (!value || value === '-') return <span style={{ color: 'var(--fl-muted)' }}>—</span>;

  const parts = value.split(/\s*\|\s*/);
  if (parts.length === 1) {
    const display = value.length > 120 ? value.slice(0, 120) + '…' : value;
    return (
      <span title={value} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--fl-on-dark)' }}>
        {display}
      </span>
    );
  }

  const [main, ...chips] = parts;
  const tooltip = parts.join('\n');
  const mainTrim = main.trim();
  const mainDisplay = mainTrim.length > 60
    ? (mainTrim.includes('/') || mainTrim.includes('\\') ? shortenPath(mainTrim) : mainTrim.slice(0, 60) + '…')
    : mainTrim;

  return (
    <span title={tooltip} style={{ display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', minWidth: 0, width: '100%' }}>
      <span style={{
        color: '#e2eaf5', fontWeight: 600, flexShrink: 1,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        minWidth: 40, maxWidth: '50%',
      }}>
        {mainDisplay}
      </span>
      {chips.slice(0, 4).map((chip, i) => {
        const { color, bg } = chipColor(chip.trim());
        const label = extractChipDisplay(chip.trim());
        return (
          <span key={i} style={{
            flexShrink: 0, display: 'inline-block',
            padding: '0px 5px', borderRadius: 3,
            fontSize: 10, fontFamily: 'monospace',
            background: bg, color, border: `1px solid ${color}30`,
            whiteSpace: 'nowrap', maxWidth: 180,
            overflow: 'hidden', textOverflow: 'ellipsis',
          }}>
            {label}
          </span>
        );
      })}
      {chips.length > 4 && (
        <span style={{ fontSize: 9, color: 'var(--fl-subtle)', flexShrink: 0 }}>+{chips.length - 4}</span>
      )}
    </span>
  );
}

/* ─── IoA Pattern Library ─────────────────────────────────────────────────── */
const IOA_PATTERNS = [
  {
    id: 'pth', name: 'Pass-the-Hash', tactic: 'lateral-movement',
    color: '#f43f5e',
    match: r => {
      const eid = r.raw?.EventID || r.raw?.EventId;
      const logon = r.raw?.LogonType || r.raw?.logon_type;
      const ntlm = (r.raw?.AuthenticationPackageName || '').toLowerCase().includes('ntlm');
      return String(eid) === '4624' && String(logon) === '3' && ntlm;
    },
  },
  {
    id: 'dcsync', name: 'DCSync', tactic: 'credential-access',
    color: '#dc2626',
    match: r => {
      const eid = String(r.raw?.EventID || r.raw?.EventId || '');
      const props = r.raw?.Properties || r.raw?.properties || r.description || '';
      return eid === '4662' && /1131f6aa|1131f6ad|89e95b76/i.test(props);
    },
  },
  {
    id: 'kerberoast', name: 'Kerberoasting', tactic: 'credential-access',
    color: '#f59e0b',
    match: r => {
      const eid = String(r.raw?.EventID || r.raw?.EventId || '');
      const ticket = r.raw?.TicketEncryptionType || '';
      return eid === '4769' && (ticket === '0x17' || ticket === '0x18');
    },
  },
  {
    id: 'lolbins', name: 'LOLBins', tactic: 'defense-evasion',
    color: '#a855f7',
    match: r => {
      const img = (r.raw?.Image || r.raw?.process_name || r.process_name || '').toLowerCase();
      const lol = ['certutil','mshta','wscript','cscript','regsvr32','rundll32','msiexec','installutil','regasm','regsvcs','wmic','bitsadmin','forfiles','msbuild'];
      return lol.some(l => img.includes(l));
    },
  },
  {
    id: 'mimikatz', name: 'Credential Dumping', tactic: 'credential-access',
    color: '#ef4444',
    match: r => {
      const desc = (r.description || '').toLowerCase();
      const cmd = (r.raw?.CommandLine || r.raw?.command_line || '').toLowerCase();
      return /lsass|sekurlsa|logonpasswords|mimikatz|wce\.exe|pwdump/.test(desc + cmd);
    },
  },
  {
    id: 'psexec', name: 'Lateral Tool Transfer', tactic: 'lateral-movement',
    color: '#22c55e',
    match: r => {
      const img = (r.raw?.Image || r.raw?.ParentImage || r.process_name || '').toLowerCase();
      const svc = (r.raw?.ServiceName || '').toLowerCase();
      return /psexec|psexesvc/.test(img + svc);
    },
  },
  {
    id: 'scheduled_task', name: 'Scheduled Task Persist.', tactic: 'persistence',
    color: '#ec4899',
    match: r => {
      const eid = String(r.raw?.EventID || r.raw?.EventId || '');
      return ['4698','4702'].includes(eid) || r.artifact_type === 'task';
    },
  },
  {
    id: 'powershell_enc', name: 'PowerShell Encoded', tactic: 'execution',
    color: '#818cf8',
    match: r => {
      const cmd = (r.raw?.CommandLine || r.raw?.command_line || r.description || '').toLowerCase();
      return /powershell.*-enc|-encodedcommand|iex\s*\(|invoke-expression/i.test(cmd);
    },
  },
];

function computeAnomalyScore(r, allRecords) {
  let score = 0;
  const h = new Date(r.timestamp).getHours();
  if (h < 6 || h > 22) score += 2; // unusual hours
  const img = (r.raw?.Image || r.raw?.process_name || r.process_name || '').toLowerCase().split(/[\\/]/).pop();
  if (img) {
    const exeCount = allRecords.filter(x =>
      (x.raw?.Image || x.raw?.process_name || x.process_name || '').toLowerCase().split(/[\\/]/).pop() === img
    ).length;
    if (exeCount === 1) score += 3; // unique exe
    else if (exeCount <= 3) score += 1;
  }
  const eid = String(r.raw?.EventID || r.raw?.EventId || '');
  if (['4698','4702','4720','4728','4732','4756','4768','4769'].includes(eid)) score += 2;
  const patterns = IOA_PATTERNS.filter(p => { try { return p.match(r); } catch { return false; } });
  score += patterns.length * 3;
  return Math.min(score, 10);
}

/* ─── end IoA ──────────────────────────────────────────────────────────────── */

const ROW_H    = 42;
const GAP_H    = 22;
const OVERSCAN = 12;

const ch = createColumnHelper();

const GRID_COLUMNS = [
  ch.accessor('timestamp', {
    header: 'Timestamp (UTC)',
    size: 190,
    meta: { mono: true, pinned: true },
    cell: info => fmtTs(info.getValue()),
  }),
  ch.accessor('artifact_type', {
    header: 'Type',
    size: 100,
    cell: info => {
      const v = info.getValue() || '-';
      const color = ac(v);
      return (
        <span style={{
          padding: '1px 6px', borderRadius: 3, fontSize: 10,
          fontWeight: 700, fontFamily: 'monospace',
          background: `${color}18`, color, border: `1px solid ${color}30`,
          whiteSpace: 'nowrap', display: 'inline-block',
        }}>
          {v}
        </span>
      );
    },
  }),
  ch.accessor('description', {
    header: 'Description',
    cell: info => <DescriptionCell value={info.getValue()} />,
  }),
  ch.accessor('source', {
    header: 'Source',
    size: 200,
    meta: { mono: true },
    cell: info => {
      const v = String(info.getValue() || '');
      return <span title={v} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>;
    },
  }),
  ch.accessor('timestamp_column', {
    header: 'Champ TS',
    size: 110,
    meta: { mono: true },
    cell: info => info.getValue() || '-',
  }),
];

const WB_LEVELS = [
  { key: 'critical', label: 'Malveillant', color: 'var(--fl-danger)', dot: '●' },
  { key: 'high',     label: 'Suspect',     color: 'var(--fl-warn)', dot: '●' },
  { key: 'medium',   label: 'Ambigu',      color: 'var(--fl-gold)', dot: '●' },
  { key: 'low',      label: 'Bénin',       color: '#22c55e', dot: '●' },
];
const WB_TAGS = [
  { key: 'exec',            label: 'Exécution',       color: 'var(--fl-warn)' },
  { key: 'persist',         label: 'Persistance',     color: 'var(--fl-purple)' },
  { key: 'lateral',         label: 'Mvt latéral',     color: '#22c55e' },
  { key: 'exfil',           label: 'Exfiltration',    color: 'var(--fl-danger)' },
  { key: 'c2',              label: 'C2',               color: '#f43f5e' },
  { key: 'recon',           label: 'Reconnaissance',  color: '#06b6d4' },
  { key: 'privesc',         label: 'Privesc',          color: '#f59e0b' },
  { key: 'defense_evasion', label: 'Évasion défense', color: '#64748b' },
  { key: 'credential',      label: 'Credentials',     color: 'var(--fl-pink)' },
  { key: 'discovery',       label: 'Découverte',      color: '#0ea5e9' },
  { key: 'collection',      label: 'Collection',      color: '#84cc16' },
  { key: 'impact',          label: 'Impact',           color: '#dc2626' },
];

function WbTagPicker({ rowId, current = {}, onChange, onClose, anchorRef }) {
  const ref = useRef(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (anchorRef?.current) {
      const r = anchorRef.current.getBoundingClientRect();
      setPos({ x: Math.min(r.left, window.innerWidth - 220), y: Math.min(r.bottom + 4, window.innerHeight - 260) });
    }
  }, [anchorRef]);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener('mousedown', h, true);
    return () => document.removeEventListener('mousedown', h, true);
  }, [onClose]);

  const lvl = current.level || null;
  const tags = current.tags || [];

  return (
    <div
      ref={ref}
      style={{
        position: 'fixed', left: pos.x, top: pos.y, zIndex: 9999,
        background: 'var(--fl-bg)', border: '1px solid #1a2a40', borderRadius: 6,
        boxShadow: '0 8px 32px #00000080', padding: '8px 10px', width: 210,
        fontFamily: 'monospace',
      }}
      onClick={e => e.stopPropagation()}
    >
      
      <div style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Niveau</div>
      <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        {WB_LEVELS.map(l => (
          <button key={l.key} onClick={() => onChange({ ...current, level: lvl === l.key ? null : l.key })}
            title={l.label}
            style={{
              flex: 1, padding: '3px 0', borderRadius: 4, cursor: 'pointer', fontSize: 13,
              background: lvl === l.key ? `${l.color}30` : 'transparent',
              border: `1px solid ${lvl === l.key ? l.color + '80' : '#1a2a40'}`,
              color: l.color,
            }}>
            {l.dot}
          </button>
        ))}
      </div>
      
      <div style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Tags</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {WB_TAGS.map(t => {
          const active = tags.includes(t.key);
          return (
            <button key={t.key} onClick={() => onChange({ ...current, tags: active ? tags.filter(k => k !== t.key) : [...tags, t.key] })}
              style={{
                padding: '2px 6px', borderRadius: 8, fontSize: 9, cursor: 'pointer', fontWeight: 600,
                background: active ? `${t.color}30` : 'rgba(255,255,255,0.05)',
                color: active ? t.color : 'var(--fl-dim)',
                border: `1px solid ${active ? t.color + '60' : 'rgba(255,255,255,0.1)'}`,
              }}>
              {t.label}
            </button>
          );
        })}
      </div>
      
      <button onClick={() => { onChange({ level: null, tags: [] }); onClose(); }}
        style={{ marginTop: 7, background: 'none', border: 'none', cursor: 'pointer', fontSize: 9, color: 'var(--fl-subtle)', padding: 0 }}>
        Effacer
      </button>
    </div>
  );
}

function ArtifactGrid({ records, selectedRecord, onSelect, notedRefs, gapThresholdMs, onPin, isPinned, artifactType, pinnedRows, verdictMap, caseId, onVerdictChange, onFollowProcess, onFilterRow }) {
  const [sorting, setSorting]         = useState([{ id: 'timestamp', desc: false }]);
  const [hoveredRow, setHoveredRow]   = useState(null);
  const [ctxMenu, setCtxMenu]         = useState(null);
  const [bookmarkedRows, setBookmarkedRows] = useState(() => new Set());
  const [tagData, setTagData]         = useState(() => new Map());
  const [selectedRows, setSelectedRows]     = useState(() => new Set());
  const [tagPickerRowId, setTagPickerRowId] = useState(null);
  const tagAnchorRef = useRef(null);
  const { t } = useTranslation();

  const anomalyScores = useMemo(() => {
    const m = new Map();
    (records || []).forEach(r => m.set(r, computeAnomalyScore(r, records)));
    return m;
  }, [records]);

  const toggleBookmark = useCallback((rowId) => {
    setBookmarkedRows(prev => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId); else next.add(rowId);
      return next;
    });
  }, []);

  const toggleSelect = useCallback((rowId) => {
    setSelectedRows(prev => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId); else next.add(rowId);
      return next;
    });
  }, []);

  const openTagPicker = useCallback((e, rowId) => {
    e.stopPropagation();
    setTagPickerRowId(prev => prev === rowId ? null : rowId);
  }, []);

  const updateTag = useCallback((rowId, value) => {
    setTagData(prev => { const next = new Map(prev); next.set(rowId, value); return next; });
  }, []);

  const columns = useMemo(() => {
    const profile = artifactType ? ARTIFACT_PROFILES[artifactType] : null;
    const virtualDefs = profile?.virtual ?? [];

    const baseCols = GRID_COLUMNS.map(col =>
      col.accessorKey === 'timestamp_column'
        ? { ...col, header: t('workbench.col_ts_field') }
        : col
    );

    if (!virtualDefs.length) return baseCols;

    const pinned = baseCols.filter(c => c.accessorKey === 'timestamp' || c.accessorKey === 'artifact_type');
    const virtCols = virtualDefs.map(v => {
      const rawKey = v.key.startsWith('raw.') ? v.key.slice(4) : v.key;
      return ch.accessor(row => row.raw?.[rawKey] ?? null, {
        id: v.key,
        header: v.label,
        size: 150,
        cell: info => {
          const val = info.getValue();
          if (val === null || val === undefined || val === '') return <span style={{ color: 'var(--fl-muted)' }}>—</span>;
          const str = String(val);
          return <span title={str} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{str}</span>;
        },
      });
    });

    return [...pinned, ...virtCols];
  }, [artifactType, t]);

  const table = useReactTable({
    data: records,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const containerRef = useRef(null);
  const tableRows = table.getRowModel().rows;

  const displayRows = useMemo(() => {
    if (!gapThresholdMs) return tableRows.map(r => ({ type: 'row', row: r }));
    const result = [];
    for (let i = 0; i < tableRows.length; i++) {
      if (i > 0) {
        const prev = tableRows[i - 1].original.timestamp;
        const curr = tableRows[i].original.timestamp;
        if (prev && curr) {
          const diffMs = new Date(curr) - new Date(prev);
          if (diffMs >= gapThresholdMs) {
            const h = Math.round(diffMs / 3600000);
            const m = Math.round((diffMs % 3600000) / 60000);
            result.push({ type: 'gap', label: h >= 1 ? `${h}h${m > 0 ? m + 'm' : ''}` : `${m}m`, diffMs });
          }
        }
      }
      result.push({ type: 'row', row: tableRows[i] });
    }
    return result;
  }, [tableRows, gapThresholdMs]);

  const rowVirtualizer = useVirtualizer({
    count: displayRows.length,
    getScrollElement: () => containerRef.current,
    estimateSize: (i) => displayRows[i]?.type === 'gap' ? GAP_H : ROW_H,
    overscan: OVERSCAN,
  });

  const virtualItems   = rowVirtualizer.getVirtualItems();
  const totalSize      = rowVirtualizer.getTotalSize();
  const colCount = columns.length + 4;

  const handleShareToChat = useCallback((evt) => {
    window.dispatchEvent(new CustomEvent('forensic:shareToChat', {
      detail: {
        type: 'timeline_event',
        timestamp: evt.timestamp || evt.ts,
        artifact_type: evt.artifact_type,
        description: evt.description || evt.desc,
        source: evt.source,
      },
    }));
  }, []);

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: 'var(--fl-bg)' }}>
      
      {ctxMenu && (
        <div style={{ position: 'fixed', zIndex: 9500 }}>
          <ContextMenu
            record={ctxMenu.record}
            pos={{ x: ctxMenu.x, y: ctxMenu.y }}
            onClose={() => setCtxMenu(null)}
            onFollowProcess={p => { onFollowProcess?.(p); setCtxMenu(null); }}
            onFilter={(field, val) => { onFilterRow?.(field, val); setCtxMenu(null); }}
          />
        </div>
      )}

      {tagPickerRowId !== null && (
        <WbTagPicker
          rowId={tagPickerRowId}
          current={tagData.get(tagPickerRowId) || {}}
          onChange={(val) => updateTag(tagPickerRowId, val)}
          onClose={() => setTagPickerRowId(null)}
          anchorRef={tagAnchorRef}
        />
      )}

      <div
        ref={containerRef}
        style={{ flex: 1, overflow: 'auto' }}
      >
        <table style={{
          width: '100%',
          minWidth: 800,
          borderCollapse: 'collapse',
          tableLayout: 'fixed',
          fontSize: 11,
        }}>
          
          <colgroup>
            <col style={{ width: 24 }} />  
            <col style={{ width: 22 }} />  
            <col style={{ width: 20 }} />  
            <col style={{ width: 30 }} />  
            {artifactType && ARTIFACT_PROFILES[artifactType]?.virtual?.length
              ? <>
                  <col style={{ width: 190 }} />  
                  <col style={{ width: 100 }} />  
                  {(ARTIFACT_PROFILES[artifactType]?.virtual ?? []).map((v, i) => (
                    <col key={i} style={{ width: 150 }} />
                  ))}
                </>
              : <>
                  <col style={{ width: 190 }} />  
                  <col style={{ width: 100 }} />  
                  <col />               
                  <col style={{ width: 200 }} />  
                  <col style={{ width: 110 }} />  
                </>
            }
          </colgroup>

          <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id} style={{ background: 'var(--fl-bg)' }}>
                
                <th
                  onClick={() => {
                    const allIds = new Set(tableRows.map(r => r.id));
                    setSelectedRows(prev => prev.size === tableRows.length ? new Set() : allIds);
                  }}
                  style={{ width: 24, padding: '6px 4px', borderBottom: '2px solid var(--fl-sep)', background: 'var(--fl-bg)', textAlign: 'center', cursor: 'pointer' }}
                  title="Tout sélectionner"
                >
                  {selectedRows.size > 0 && selectedRows.size === tableRows.length
                    ? <CheckSquare size={11} style={{ color: 'var(--fl-accent)' }} />
                    : <Square size={11} style={{ color: selectedRows.size > 0 ? '#4d82c060' : 'var(--fl-border)' }} />
                  }
                </th>
                
                <th style={{ width: 22, padding: '6px 4px', borderBottom: '2px solid var(--fl-sep)', background: 'var(--fl-bg)', textAlign: 'center' }} title="Signets">
                  <Star size={10} style={{ color: 'var(--fl-border)' }} />
                </th>
                
                <th style={{ width: 20, padding: '6px 4px', borderBottom: '2px solid var(--fl-sep)', background: 'var(--fl-bg)', textAlign: 'center' }} title="Épingles">
                  <Pin size={10} style={{ color: 'var(--fl-border)' }} />
                </th>
                
                <th style={{ width: 30, padding: '6px 4px', borderBottom: '2px solid var(--fl-sep)', background: 'var(--fl-bg)', textAlign: 'center' }} title="Tags forensiques">
                  <Tag size={10} style={{ color: 'var(--fl-border)' }} />
                </th>
                {hg.headers.map((h) => {
                  const pinned  = h.column.columnDef.meta?.pinned;
                  const isSorted = h.column.getIsSorted();
                  return (
                    <th
                      key={h.id}
                      onClick={h.column.getToggleSortingHandler()}
                      style={{
                        padding: '7px 8px',
                        textAlign: 'left',
                        cursor: 'pointer',
                        userSelect: 'none',
                        fontFamily: 'monospace',
                        fontSize: 10,
                        fontWeight: 700,
                        letterSpacing: '0.07em',
                        textTransform: 'uppercase',
                        color: isSorted ? 'var(--fl-accent)' : 'var(--fl-muted)',
                        borderBottom: '2px solid var(--fl-border2)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        position: pinned ? 'sticky' : undefined,
                        left:     pinned ? 0 : undefined,
                        zIndex:   pinned ? 20 : undefined,
                        background: 'var(--fl-bg)',
                        borderRight: pinned ? '1px solid var(--fl-sep)' : undefined,
                      }}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {isSorted === 'asc'  && <SortAsc  size={9} />}
                        {isSorted === 'desc' && <SortDesc size={9} />}
                      </span>
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>

          <tbody>
            
            {virtualItems.length > 0 && virtualItems[0].start > 0 && (
              <tr><td colSpan={colCount} style={{ height: virtualItems[0].start, padding: 0, border: 'none' }} /></tr>
            )}

            {virtualItems.map(vItem => {
              const item = displayRows[vItem.index];
              if (!item) return null;

              if (item.type === 'gap') {
                return (
                  <tr key={`gap-${vItem.index}`} style={{ height: GAP_H }}>
                    <td colSpan={colCount} style={{ padding: 0, border: 'none' }}>
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 6,
                        padding: '0 12px', height: GAP_H,
                        background: 'var(--fl-bg)',
                      }}>
                        <div style={{ flex: 1, height: 1, borderStyle: 'dashed', borderWidth: '1px 0 0 0', borderColor: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' }} />
                        <span style={{
                          fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                          color: 'var(--fl-danger)',
                          background: 'color-mix(in srgb, var(--fl-danger) 8%, var(--fl-bg))',
                          border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)',
                          padding: '1px 6px', borderRadius: 4, whiteSpace: 'nowrap',
                        }}>
                          GAP {item.label}
                        </span>
                        <div style={{ flex: 1, height: 1, borderStyle: 'dashed', borderWidth: '1px 0 0 0', borderColor: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' }} />
                      </div>
                    </td>
                  </tr>
                );
              }

              const { row } = item;
              const isSelected = selectedRecord === row.original;
              const color      = ac(row.original.artifact_type);
              const isEven     = vItem.index % 2 === 0;
              const hayLevel   = !isSelected && row.original.artifact_type === 'hayabusa'
                ? (row.original.raw?.level || null) : null;
              const rowBg      = isSelected
                ? '#11203a'
                : (HAYABUSA_SEV_BG[hayLevel] ?? (isEven ? 'transparent' : 'rgba(255,255,255,0.04)'));

              const isHovered = hoveredRow === row.id;
              return (
                <tr
                  key={row.id}
                  onClick={() => onSelect(row.original)}
                  onMouseEnter={() => setHoveredRow(row.id)}
                  onMouseLeave={() => setHoveredRow(null)}
                  onContextMenu={e => { e.preventDefault(); setCtxMenu({ record: row.original, x: e.clientX, y: e.clientY }); }}
                  style={{
                    height: ROW_H,
                    background: rowBg,
                    borderLeft: `3px solid ${isSelected ? color : color + '55'}`,
                    borderBottom: '1px solid var(--fl-border2)',
                    cursor: 'pointer',
                    transition: 'background 0.08s',
                    position: 'relative',
                  }}
                >
                  
                  <td
                    onClick={e => { e.stopPropagation(); toggleSelect(row.id); }}
                    style={{ padding: '2px 0', textAlign: 'center', width: 24, cursor: 'pointer' }}
                  >
                    {selectedRows.has(row.id)
                      ? <CheckSquare size={11} style={{ color: 'var(--fl-accent)' }} />
                      : <Square size={11} style={{ color: isHovered ? 'var(--fl-subtle)' : 'var(--fl-sep)' }} />
                    }
                  </td>

                  <td
                    onClick={e => { e.stopPropagation(); toggleBookmark(row.id); }}
                    style={{ padding: '2px 0', textAlign: 'center', width: 22, cursor: 'pointer' }}
                    title={bookmarkedRows.has(row.id) ? 'Retirer le signet' : 'Ajouter un signet'}
                  >
                    <Star
                      size={11}
                      fill={bookmarkedRows.has(row.id) ? '#f59e0b' : 'none'}
                      style={{ color: bookmarkedRows.has(row.id) ? '#f59e0b' : (isHovered ? 'var(--fl-subtle)' : 'var(--fl-sep)') }}
                    />
                  </td>

                  <td
                    onClick={e => { e.stopPropagation(); onPin?.(row.original); }}
                    style={{ padding: '2px 0', textAlign: 'center', width: 20, cursor: onPin ? 'pointer' : 'default' }}
                    title={isPinned?.(row.original) ? 'Désépingler' : 'Épingler en haut'}
                  >
                    {(() => {
                      const pinEntry = pinnedRows
                        ? [...pinnedRows.values()].find(p => p.event_ts === row.original.timestamp && p.source === row.original.source)
                        : null;
                      if (pinEntry) {
                        return pinEntry.is_global
                          ? <Globe2 size={11} style={{ color: '#f0b040' }} />
                          : <Pin size={11} fill="var(--fl-warn)" style={{ color: 'var(--fl-warn)' }} />;
                      }
                      return (
                        <Pin
                          size={11}
                          fill="none"
                          style={{ color: isHovered ? 'var(--fl-subtle)' : 'var(--fl-sep)' }}
                        />
                      );
                    })()}
                  </td>

                  <td
                    ref={tagPickerRowId === row.id ? tagAnchorRef : null}
                    onClick={e => openTagPicker(e, row.id)}
                    style={{ padding: '2px 0', textAlign: 'center', width: 30, cursor: 'pointer' }}
                    title="Tag forensique"
                  >
                    {(() => {
                      const td = tagData.get(row.id) || {};
                      const lvl = WB_LEVELS.find(l => l.key === td.level);
                      if (lvl) return <span style={{ fontSize: 13, color: lvl.color, lineHeight: 1 }}>{lvl.dot}</span>;
                      if (td.tags?.length > 0) return <Tag size={11} style={{ color: 'var(--fl-subtle)' }} />;
                      const score = anomalyScores.get(row.original) || 0;
                      if (score >= 7) return <span style={{ fontSize: 10, color: 'var(--fl-danger)', lineHeight: 1 }} title={`Score anomalie: ${score}/10`}>⚡</span>;
                      if (score >= 4) return <span style={{ fontSize: 10, color: 'var(--fl-warn)', lineHeight: 1 }} title={`Score anomalie: ${score}/10`}>△</span>;
                      return <span style={{ fontSize: 11, color: isHovered ? 'var(--fl-card)' : 'var(--fl-bg)' }}>○</span>;
                    })()}
                  </td>

                  {row.getVisibleCells().map((cell) => {
                    const pinned = cell.column.columnDef.meta?.pinned;
                    const mono   = cell.column.columnDef.meta?.mono;
                    const isDesc = cell.column.id === 'description';
                    return (
                      <td
                        key={cell.id}
                        style={{
                          padding: '0 8px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          minWidth: isDesc ? 0 : undefined,
                          fontFamily: mono ? 'monospace' : undefined,
                          color: mono ? 'var(--fl-accent)' : 'var(--fl-on-dark)',
                          position:   pinned ? 'sticky' : undefined,
                          left:       pinned ? 0 : undefined,
                          zIndex:     pinned ? 5 : undefined,
                          background: pinned ? rowBg : undefined,
                          borderRight: pinned ? '1px solid var(--fl-sep)' : undefined,
                        }}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    );
                  })}
                </tr>
              );
            })}

            {virtualItems.length > 0 && (() => {
              const lastItem = virtualItems[virtualItems.length - 1];
              const bottomPad = totalSize - lastItem.end;
              return bottomPad > 0
                ? <tr><td colSpan={colCount} style={{ height: bottomPad, padding: 0, border: 'none' }} /></tr>
                : null;
            })()}
          </tbody>
        </table>
      </div>

      <div style={{
        flexShrink: 0,
        padding: '3px 12px',
        background: 'var(--fl-bg)',
        borderTop: '1px solid var(--fl-sep)',
        fontFamily: 'monospace',
        fontSize: 10,
        color: 'var(--fl-muted)',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
      }}>
        <span>{tableRows.length.toLocaleString()} ligne{tableRows.length !== 1 ? 's' : ''}{gapThresholdMs ? ` · ${displayRows.filter(r => r.type === 'gap').length} gap(s)` : ''}</span>
        {artifactType && ARTIFACT_PROFILES[artifactType]?.virtual?.length > 0 && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 3,
            padding: '1px 6px', borderRadius: 3,
            background: `${ac(artifactType)}12`,
            border: `1px solid ${ac(artifactType)}30`,
            color: ac(artifactType),
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
          }}>
            <FileText size={8} /> Mode investigation · {artifactType}
          </span>
        )}
        {selectedRecord && (
          <span style={{ color: 'var(--fl-subtle)', marginLeft: 'auto' }}>
            <span style={{ color: ac(selectedRecord.artifact_type) }}>{selectedRecord.artifact_type}</span>
            {' '}{fmtTs(selectedRecord.timestamp)}
          </span>
        )}
      </div>
    </div>
  );
}

function PivotButton({ value, isIP, caseId, onFilterTimeline }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const { t } = useTranslation();

  useEffect(() => {
    if (!open) return;
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-flex', flexShrink: 0 }}>
      <button
        onClick={() => setOpen(v => !v)}
        title="Pivot"
        style={{
          background: 'none', border: '1px solid var(--fl-card)', borderRadius: 3,
          cursor: 'pointer', padding: '1px 6px', fontSize: 9, fontFamily: 'monospace',
          color: 'var(--fl-accent)', display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0,
        }}
      >
        ⤢ Pivot
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', zIndex: 100, marginTop: 2,
          background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 6,
          padding: '4px 0', minWidth: 180, boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
        }}>
          {onFilterTimeline && (
            <button
              onClick={() => { onFilterTimeline(value); setOpen(false); }}
              style={{
                display: 'block', width: '100%', textAlign: 'left',
                padding: '5px 12px', fontSize: 10, fontFamily: 'monospace',
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-on-dark)',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-card)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
            >
              {t('timeline.filter_timeline')}
            </button>
          )}
          {isIP && caseId && (
            <button
              onClick={() => { window.location.href = `/cases/${caseId}/graph?view=network`; setOpen(false); }}
              style={{
                display: 'block', width: '100%', textAlign: 'left',
                padding: '5px 12px', fontSize: 10, fontFamily: 'monospace',
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-on-dark)',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-card)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
            >
              {t('timeline.see_in_network')}
            </button>
          )}
        </div>
      )}
    </span>
  );
}

function ArtifactInspector({ record, allRecords = [], caseId, onNotedRefsChange, onFilterTimeline }) {
  const { t } = useTranslation();
  const [copied, setCopied]         = useState(false);
  const [inspectorTab, setTab]      = useState('details');
  const [notes, setNotes]           = useState([]);
  const [noteText, setNoteText]     = useState('');
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteEditId, setNoteEditId] = useState(null);
  const [noteEditText, setNoteEditText] = useState('');
  const [contextWindow, setContextWindow] = useState(5); // ±N minutes
  const [verdictLocal, setVerdictLocal]   = useState(null);
  const [pivotQuery, setPivotQuery]       = useState('');

  const json = useMemo(() => {
    if (!record) return null;
    return JSON.stringify(record.raw ?? record, null, 2);
  }, [record]);

  function copyJson() {
    if (!json) return;
    navigator.clipboard.writeText(json).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  useEffect(() => {
    setTab('details');
    setNotes([]);
    setNoteText('');
    setNoteEditId(null);
  }, [record]);

  useEffect(() => {
    if (inspectorTab !== 'notes' || !record || !caseId) return;
    const controller = new AbortController();
    artifactsAPI.getNotes(caseId, computeRef(record), { signal: controller.signal })
      .then(res => setNotes(res.data?.notes ?? []))
      .catch(err => { if (err.name !== 'CanceledError' && err.name !== 'AbortError') setNotes([]); });
    return () => controller.abort();
  }, [inspectorTab, record, caseId]);

  async function submitNote() {
    if (!noteText.trim() || !record || !caseId) return;
    setNoteSaving(true);
    try {
      await artifactsAPI.createNote(caseId, computeRef(record), noteText.trim());
      setNoteText('');
      const res = await artifactsAPI.getNotes(caseId, computeRef(record));
      setNotes(res.data?.notes ?? []);
      if (onNotedRefsChange) onNotedRefsChange();
    } catch {}
    setNoteSaving(false);
  }

  async function saveEditNote(noteId) {
    if (!noteEditText.trim() || !record || !caseId) return;
    try {
      await artifactsAPI.updateNote(caseId, computeRef(record), noteId, noteEditText.trim());
      const res = await artifactsAPI.getNotes(caseId, computeRef(record));
      setNotes(res.data?.notes ?? []);
      setNoteEditId(null);
    } catch {}
  }

  async function deleteNote(noteId) {
    if (!record || !caseId) return;
    try {
      await artifactsAPI.deleteNote(caseId, computeRef(record), noteId);
      const res = await artifactsAPI.getNotes(caseId, computeRef(record));
      setNotes(res.data?.notes ?? []);
      if (onNotedRefsChange) onNotedRefsChange();
    } catch {}
  }

  if (!record) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        background: '#05080f', gap: 8,
      }}>
        <div style={{ fontSize: 22, opacity: 0.15 }}>⬛</div>
        <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-muted)' }}>
          {t('timeline.inspector_placeholder')}
        </div>
      </div>
    );
  }

  const color     = ac(record.artifact_type);
  const rawFields = record.raw && typeof record.raw === 'object'
    ? sortRawByPriority(
        Object.entries(record.raw).filter(([, v]) => v !== null && v !== undefined && v !== '')
      )
    : [];

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#05080f', overflow: 'hidden' }}>

      <div style={{
        flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '4px 12px',
        background: 'var(--fl-bg)',
        borderBottom: `1px solid color-mix(in srgb, ${color} 20%, var(--fl-border))`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
          
          {[
            { id: 'details', label: t('workbench.details'), icon: null },
            { id: 'context', label: '±ctx', icon: Activity },
            { id: 'pivot',   label: 'Pivot', icon: Target },
            { id: 'verdict', label: 'Verdict', icon: ShieldAlert },
            { id: 'notes',   label: t('notes.tab'), icon: MessageSquare, badge: notes.length },
          ].map(tab => {
            const Icon = tab.icon;
            return (
            <button key={tab.id} onClick={() => setTab(tab.id)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: '5px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
              fontWeight: inspectorTab === tab.id ? 600 : 400,
              color: inspectorTab === tab.id ? 'var(--fl-accent)' : 'var(--fl-muted)',
              borderBottom: inspectorTab === tab.id ? '2px solid var(--fl-accent)' : '2px solid transparent',
              display: 'flex', alignItems: 'center', gap: 3,
            }}>
              {Icon && <Icon size={9} />}
              {tab.label}
              {tab.badge > 0 && (
                <span style={{ fontSize: 8, background: 'var(--fl-accent)', color: '#000', borderRadius: 8, padding: '0 4px', fontWeight: 700 }}>{tab.badge}</span>
              )}
            </button>
            );
          })}
          
          <span style={{
            padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
            fontFamily: 'monospace', whiteSpace: 'nowrap',
            background: `${color}20`, color, border: `1px solid ${color}40`,
          }}>
            {record.artifact_type || '?'}
          </span>
          {record.artifact_name && (
            <span style={{
              fontSize: 11, fontFamily: 'monospace', color: '#a0b8d0',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {record.artifact_name}
            </span>
          )}
        </div>

        {(() => {
          const raw = record.raw || {};
          const isMemory = record.artifact_type === 'memory'
            || (record.source || '').toLowerCase().includes('volatility')
            || (record.source || '').toLowerCase().includes('volweb');
          const pid = raw.Pid || raw.pid || raw.PID || null;
          if (!isMemory) return null;
          const url = pid
            ? `http://localhost:8888/processes/${pid}`
            : 'http://localhost:8888';
          return (
            <button
              onClick={() => window.open(url, '_blank')}
              style={{
                flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
                marginLeft: 4, background: 'rgba(139,114,214,0.12)',
                border: '1px solid rgba(139,114,214,0.35)',
                borderRadius: 4, cursor: 'pointer', padding: '2px 8px',
                fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-purple)',
              }}
              title={pid ? `Ouvrir VolWeb — PID ${pid}` : 'Ouvrir VolWeb'}
            >
              ↗ VolWeb{pid ? ` (PID ${pid})` : ''}
            </button>
          );
        })()}
        
        <button onClick={copyJson} style={{
          flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
          marginLeft: 8, background: 'none', border: '1px solid var(--fl-sep)',
          borderRadius: 4, cursor: 'pointer', padding: '2px 8px',
          fontSize: 10, fontFamily: 'monospace',
          color: copied ? 'var(--fl-ok)' : 'var(--fl-subtle)', transition: 'color 0.15s',
        }}>
          {copied ? <CheckCheck size={11} /> : <Copy size={11} />}
          {copied ? t('timeline.copy_success') : t('workbench.copy')}
        </button>
      </div>

      
      {inspectorTab === 'context' && (() => {
        const ts = new Date(record.timestamp).getTime();
        const winMs = contextWindow * 60 * 1000;
        const nearby = allRecords.filter(x => {
          const d = Math.abs(new Date(x.timestamp).getTime() - ts);
          return d > 0 && d <= winMs;
        }).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        return (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ flexShrink: 0, padding: '6px 12px', borderBottom: '1px solid var(--fl-border2)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>Fenêtre ±</span>
              {[1, 5, 15, 30, 60].map(n => (
                <button key={n} onClick={() => setContextWindow(n)}
                  style={{
                    padding: '1px 7px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', cursor: 'pointer',
                    background: contextWindow === n ? 'rgba(77,130,192,0.2)' : 'transparent',
                    border: `1px solid ${contextWindow === n ? 'var(--fl-accent)' : 'var(--fl-sep)'}`,
                    color: contextWindow === n ? 'var(--fl-accent)' : 'var(--fl-muted)',
                  }}>
                  {n < 60 ? `${n}m` : '1h'}
                </button>
              ))}
              <span style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>{nearby.length} evt</span>
            </div>
            <div style={{ flex: 1, overflow: 'auto', padding: '6px 0' }}>
              {nearby.length === 0 ? (
                <div style={{ textAlign: 'center', marginTop: 24, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
                  Aucun événement dans la fenêtre ±{contextWindow} min
                </div>
              ) : nearby.map((x, i) => {
                const c = ac(x.artifact_type);
                const delta = ((new Date(x.timestamp).getTime() - ts) / 60000).toFixed(1);
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 8,
                    padding: '4px 12px',
                    background: x === record ? 'rgba(77,130,192,0.1)' : 'transparent',
                    borderLeft: `2px solid ${c}`,
                    marginBottom: 2,
                  }}>
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3a6a9a', flexShrink: 0, width: 46, textAlign: 'right' }}>
                      {delta > 0 ? `+${delta}` : delta}m
                    </span>
                    <span style={{ fontSize: 9, padding: '1px 4px', borderRadius: 2, background: `${c}18`, color: c, fontFamily: 'monospace', flexShrink: 0 }}>
                      {x.artifact_type}
                    </span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                      {x.description || x.source || ''}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {inspectorTab === 'pivot' && (() => {
        const raw = record.raw || {};
        const pivotFields = [];
        const PIVOT_KEYS = [
          'Image','ParentImage','CommandLine','ParentCommandLine',
          'DestinationIp','SourceIp','DestinationHostname','QueryName',
          'MD5','SHA256','SHA1','Hashes',
          'SubjectUserName','TargetUserName','UserName',
          'ProcessId','ParentProcessId',
          'TargetObject','Details',
          'SourceFile','Channel',
        ];
        for (const k of PIVOT_KEYS) {
          if (raw[k] && String(raw[k]).length > 1) {
            pivotFields.push({ key: k, value: String(raw[k]) });
          }
        }
        const filtered = pivotQuery
          ? pivotFields.filter(f => f.value.toLowerCase().includes(pivotQuery.toLowerCase()) || f.key.toLowerCase().includes(pivotQuery.toLowerCase()))
          : pivotFields;
        return (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ flexShrink: 0, padding: '6px 12px', borderBottom: '1px solid var(--fl-border2)' }}>
              <input
                value={pivotQuery}
                onChange={e => setPivotQuery(e.target.value)}
                placeholder="Filtrer les champs…"
                style={{
                  width: '100%', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)',
                  borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 10,
                  padding: '4px 8px', outline: 'none', boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ flex: 1, overflow: 'auto', padding: '6px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {filtered.length === 0 && (
                <div style={{ textAlign: 'center', marginTop: 20, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
                  Aucun champ IOC
                </div>
              )}
              {filtered.map(({ key, value }) => {
                const truncated = value.length > 80 ? value.slice(0, 80) + '…' : value;
                const matchCount = allRecords.filter(x => {
                  const v = x.raw?.[key];
                  return v && String(v) === value;
                }).length;
                return (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 6px', borderRadius: 4, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)' }}>
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#4d82c0', flexShrink: 0, width: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>{key}</span>
                    <span style={{ flex: 1, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={value}>{truncated}</span>
                    {matchCount > 1 && (
                      <span style={{ fontSize: 8, padding: '1px 5px', borderRadius: 8, background: 'rgba(77,130,192,0.15)', color: 'var(--fl-accent)', flexShrink: 0, fontFamily: 'monospace' }}>
                        ×{matchCount}
                      </span>
                    )}
                    <button
                      onClick={() => onFilterTimeline?.({ field: key, value })}
                      title={`Pivoter sur ${key}=${value}`}
                      style={{ flexShrink: 0, background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 3, cursor: 'pointer', padding: '1px 5px', fontSize: 8, color: 'var(--fl-accent)', fontFamily: 'monospace' }}>
                      Pivot
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {inspectorTab === 'verdict' && (() => {
        const ref = computeRef(record);
        const ioas = IOA_PATTERNS.filter(p => { try { return p.match(record); } catch { return false; } });
        const score = computeAnomalyScore(record, allRecords);
        return (
          <div style={{ flex: 1, overflow: 'auto', padding: '12px' }}>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Score d'anomalie</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ flex: 1, height: 6, background: 'var(--fl-sep)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 3, transition: 'width 0.3s',
                    width: `${score * 10}%`,
                    background: score >= 7 ? 'var(--fl-danger)' : score >= 4 ? 'var(--fl-warn)' : 'var(--fl-ok)',
                  }} />
                </div>
                <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, color: score >= 7 ? 'var(--fl-danger)' : score >= 4 ? 'var(--fl-warn)' : 'var(--fl-ok)', flexShrink: 0 }}>
                  {score}/10
                </span>
              </div>
            </div>


            {ioas.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Patterns IoA détectés</div>
                {ioas.map(p => (
                  <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 4, marginBottom: 4, background: `${p.color}12`, border: `1px solid ${p.color}40` }}>
                    <span style={{ fontSize: 9, fontWeight: 700, color: p.color, fontFamily: 'monospace' }}>⚡ {p.name}</span>
                    <span style={{ fontSize: 8, color: '#4d6080', fontFamily: 'monospace' }}>{p.tactic}</span>
                  </div>
                ))}
              </div>
            )}


            <div>
              <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Verdict</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {WB_LEVELS.map(l => (
                  <button key={l.key}
                    onClick={() => setVerdictLocal(verdictLocal === l.key ? null : l.key)}
                    style={{
                      padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                      fontWeight: 600, cursor: 'pointer',
                      background: verdictLocal === l.key ? `${l.color}25` : 'transparent',
                      border: `1px solid ${verdictLocal === l.key ? l.color : 'var(--fl-sep)'}`,
                      color: verdictLocal === l.key ? l.color : 'var(--fl-muted)',
                    }}>
                    {l.dot} {l.label}
                  </button>
                ))}
              </div>
              {verdictLocal && (
                <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 4, background: 'rgba(77,130,192,0.08)', border: '1px solid var(--fl-sep)', fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
                  Verdict «{WB_LEVELS.find(l => l.key === verdictLocal)?.label}» appliqué localement. Utilisez les annotations (onglet Notes) pour persister.
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {inspectorTab === 'notes' ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          
          <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {notes.length === 0 ? (
              <div style={{ color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 11, textAlign: 'center', marginTop: 24 }}>
                {t('notes.empty')}
              </div>
            ) : notes.map(n => (
              <div key={n.id} style={{ borderRadius: 6, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', padding: '8px 10px' }}>
                {noteEditId === n.id ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <textarea value={noteEditText} onChange={e => setNoteEditText(e.target.value)}
                      style={{ width: '100%', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4,
                        color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px',
                        resize: 'vertical', minHeight: 60, outline: 'none', boxSizing: 'border-box' }} />
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => saveEditNote(n.id)}
                        style={{ padding: '3px 10px', borderRadius: 4,
                          background: 'color-mix(in srgb, var(--fl-accent) 15%, var(--fl-card))',
                          border: '1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)',
                          color: 'var(--fl-accent)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                        {t('common.save')}
                      </button>
                      <button onClick={() => setNoteEditId(null)}
                        style={{ padding: '3px 10px', borderRadius: 4, background: 'none', border: '1px solid var(--fl-border)',
                          color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                        {t('common.cancel')}
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
                        {n.updated_at !== n.created_at && t('workbench.note_edited')}
                      </span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={() => { setNoteEditId(n.id); setNoteEditText(n.note); }}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', display: 'flex' }}>
                          <Pencil size={10} />
                        </button>
                        <button onClick={() => deleteNote(n.id)}
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
            <textarea value={noteText} onChange={e => setNoteText(e.target.value)}
              placeholder={t('notes.placeholder')}
              onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) submitNote(); }}
              style={{ flex: 1, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4,
                color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 11, padding: '6px 8px',
                resize: 'none', height: 52, outline: 'none' }} />
            <button onClick={submitNote} disabled={noteSaving || !noteText.trim()}
              style={{ padding: '0 12px', borderRadius: 4,
                background: noteText.trim() ? 'color-mix(in srgb, var(--fl-accent) 15%, var(--fl-card))' : 'var(--fl-bg)',
                border: `1px solid ${noteText.trim() ? 'color-mix(in srgb, var(--fl-accent) 40%, transparent)' : 'var(--fl-border2)'}`,
                color: noteText.trim() ? 'var(--fl-accent)' : 'var(--fl-muted)', cursor: noteText.trim() ? 'pointer' : 'default',
                display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace' }}>
              <Send size={11} /> {t('workbench.send')}
            </button>
          </div>
        </div>
      ) : (
        <>
        
        <div style={{
          flexShrink: 0,
          padding: '8px 12px',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
          display: 'flex', flexDirection: 'column', gap: 5,
        }}>
          
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
              <Clock size={10} /> {t('workbench.timestamp_label')}
            </span>
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#7abfff', fontWeight: 600, lineHeight: 1.4 }}>
              {fmtTs(record.timestamp)}
              {record.timestamp_column && (
                <span style={{ marginLeft: 8, fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--fl-sep)', color: '#4d6080', fontWeight: 400 }}>
                  {record.timestamp_column}
                </span>
              )}
            </span>
          </div>

          
          {(record.host_name || record.source_device) && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
                <HardDrive size={10} /> Hôte
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#22c55e', fontWeight: 600 }}>
                {record.host_name || record.source_device}
              </span>
            </div>
          )}

          
          {record.user_name && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
                <Eye size={10} /> Utilisateur
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-gold)', fontWeight: 600 }}>
                {record.user_name}
              </span>
            </div>
          )}

          
          {record.process_name && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
                <Cpu size={10} /> Processus
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-warn)', fontWeight: 600, wordBreak: 'break-all' }}>
                {record.process_name}
              </span>
            </div>
          )}

          
          {record.mitre_technique_id && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
                <ShieldAlert size={10} /> MITRE
              </span>
              <MitreBadge id={record.mitre_technique_id} name={record.mitre_technique_name} />
            </div>
          )}

          
          {record.description && (
            <div style={{
              padding: '6px 8px', borderRadius: 5,
              background: `${color}10`, border: `1px solid ${color}35`,
              fontSize: 11, lineHeight: 1.55, wordBreak: 'break-word',
              display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4,
            }}>
              {record.description.split(/\s*\|\s*/).map((part, i, arr) => {
                const { color: c, bg } = chipColor(part.trim());
                return (
                  <span key={i} style={{
                    padding: i === 0 ? '0' : '1px 6px',
                    borderRadius: i === 0 ? 0 : 4,
                    fontFamily: 'monospace',
                    fontSize: i === 0 ? 11 : 10,
                    fontWeight: i === 0 ? 600 : 400,
                    color: i === 0 ? 'var(--fl-on-dark)' : c,
                    background: i === 0 ? 'transparent' : bg,
                    border: i === 0 ? 'none' : `1px solid ${c}40`,
                    whiteSpace: 'nowrap',
                  }}>
                    {part.trim()}
                  </span>
                );
              })}
            </div>
          )}

          
          {record.source && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace', paddingTop: 1 }}>
                <FileText size={10} /> Source
              </span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4d6080', wordBreak: 'break-all', lineHeight: 1.4 }}>
                {record.source}
              </span>
            </div>
          )}
        </div>

        
        <div style={{ flex: 1, overflow: 'auto' }}>
          {rawFields.length > 0 ? (
            <>
              <div style={{
                position: 'sticky', top: 0,
                padding: '4px 12px',
                fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                color: 'var(--fl-muted)', letterSpacing: '0.08em', textTransform: 'uppercase',
                background: '#05080f', borderBottom: '1px solid rgba(255,255,255,0.07)',
                display: 'flex', alignItems: 'center', gap: 5,
              }}>
                <Tag size={9} />
                {t('workbench.raw_csv')} — {rawFields.length}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, padding: '8px 12px' }}>
                {rawFields.map(([key, val]) => {
                  const strVal = String(val);
                  const isIP   = /^\d{1,3}(\.\d{1,3}){3}$/.test(strVal);
                  const isHash = /^[0-9a-fA-F]{32,}$/.test(strVal);
                  const isURL  = /^https?:\/\//.test(strVal);
                  const isPivotable = isIP || isHash || isURL;
                  return (
                    <div key={key} style={{ borderRadius: 4, overflow: 'hidden', border: `1px solid ${color}28` }}>
                      <div style={{
                        fontFamily: 'monospace', fontSize: 9, color,
                        padding: '3px 8px', background: `${color}18`,
                        textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600,
                        userSelect: 'none',
                      }}>
                        {key}
                      </div>
                      <div style={{
                        padding: '5px 8px',
                        fontFamily: 'monospace', color: '#c0cfe0', fontSize: 10,
                        wordBreak: 'break-all', lineHeight: 1.5,
                        background: '#05080f', borderTop: `1px solid ${color}18`,
                        display: 'flex', alignItems: 'flex-start', gap: 6,
                      }}>
                        <span style={{ flex: 1 }}>{strVal}</span>
                        {isPivotable && (
                          <PivotButton value={strVal} isIP={isIP} caseId={caseId} onFilterTimeline={onFilterTimeline} />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div style={{ padding: '8px 12px' }}>
              <div style={{
                fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-muted)',
                letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6,
              }}>
                {t('workbench.json_raw')}
              </div>
              <pre style={{
                margin: 0, fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                fontSize: 10.5, lineHeight: 1.65,
                whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#8aa0bc',
              }}>
                {json}
              </pre>
            </div>
          )}
        </div>
        </>
      )}
    </div>
  );
}

function MitreBadge({ id, name }) {
  if (!id) return null;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
      background: '#8b72d615', color: 'var(--fl-purple)', border: '1px solid #8b72d630',
      whiteSpace: 'nowrap', flexShrink: 0,
    }} title={name || id}>
      {id}
    </span>
  );
}

const SEV_COLORS = {
  critical: { bg: '#da363318', color: 'var(--fl-danger)', border: '#da363340' },
  high:     { bg: '#d97c2014', color: 'var(--fl-warn)', border: '#d97c2035' },
  medium:   { bg: '#c89d1d12', color: 'var(--fl-gold)', border: '#c89d1d30' },
  low:      { bg: '#22c55e0c', color: '#22c55e', border: '#22c55e25' },
};
function SeverityBadge({ level }) {
  const s = SEV_COLORS[level] || SEV_COLORS.low;
  return (
    <span style={{
      padding: '1px 7px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      textTransform: 'uppercase', flexShrink: 0,
    }}>
      {level || 'info'}
    </span>
  );
}

function PersistancePanel({ caseId }) {
  const { t } = useTranslation();
  const [data, setData]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);
  const [collapsed, setCollapsed] = useState({});

  useEffect(() => {
    if (!caseId) return;
    setCollapsed({}); // BUG-4 fix: reset group expand/collapse state on case change
    setLoading(true);
    detectionsAPI.persistence(caseId)
      .then(res => { setData(res.data); setLoading(false); })
      .catch(err => { setError(err.response?.data?.error || err.message); setLoading(false); });
  }, [caseId]);

  if (loading) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 11 }}>
      {t('workbench.loading_persistence')}
    </div>
  );
  if (error) return (
    <div style={{ flex: 1, padding: 16, color: 'var(--fl-danger)', fontFamily: 'monospace', fontSize: 11 }}>
      {t('common.error')}: {error}
    </div>
  );

  const findings = data?.findings || data?.results || data || [];
  if (!Array.isArray(findings) || findings.length === 0) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, flexDirection: 'column' }}>
      <ShieldAlert size={28} style={{ color: '#22c55e', opacity: 0.5 }} />
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-subtle)' }}>
        {t('workbench.no_persistence')}
      </span>
    </div>
  );

  const byVector = useMemo(() => {
    const result = {};
    for (const f of findings) {
      const k = f.vector || f.artifact_type || f.type || 'Autre';
      if (!result[k]) result[k] = [];
      result[k].push(f);
    }
    return result;
  }, [findings]);

  const VECTOR_COLORS = {
    'Registry RunKey': 'var(--fl-pink)', registry: 'var(--fl-pink)',
    lnk: 'var(--fl-warn)', bits: '#64748b', prefetch: '#22c55e',
    jumplist: '#8b5cf6', amcache: 'var(--fl-gold)',
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 5 }}>
        <ShieldAlert size={10} />
        {findings.length} {findings.length !== 1 ? t('workbench.persistence_items_pl') : t('workbench.persistence_items')} — {Object.keys(byVector).length} {Object.keys(byVector).length !== 1 ? t('workbench.vectors_pl') : t('workbench.vectors')}
      </div>
      {Object.entries(byVector).map(([vector, items]) => {
        const isOpen = !collapsed[vector];
        const col = VECTOR_COLORS[vector] || 'var(--fl-accent)';
        const sample = items[0];
        const mitre_id   = sample?.mitre_technique_id || sample?.technique_id;
        const mitre_name = sample?.mitre_technique_name || sample?.technique_name;
        return (
          <div key={vector} style={{ borderRadius: 6, border: `1px solid ${col}25`, background: `${col}08`, overflow: 'hidden' }}>
            
            <button
              onClick={() => setCollapsed(p => ({ ...p, [vector]: !p[vector] }))}
              style={{
                display: 'flex', alignItems: 'center', gap: 7, width: '100%', textAlign: 'left',
                padding: '6px 10px', background: 'none', border: 'none', cursor: 'pointer',
                borderBottom: isOpen ? `1px solid ${col}20` : 'none',
              }}
            >
              {isOpen ? <ChevronDown size={10} style={{ color: col }} /> : <ChevronRight size={10} style={{ color: col }} />}
              <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, color: col, flex: 1 }}>
                {vector}
              </span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>
                {items.length} {items.length !== 1 ? t('workbench.artifacts_pl') : t('workbench.artifacts')}
              </span>
              <MitreBadge id={mitre_id} name={mitre_name} />
            </button>
            
            {isOpen && items.map((item, i) => (
              <div key={i} style={{
                padding: '5px 12px 5px 26px', borderBottom: i < items.length - 1 ? `1px solid ${col}12` : 'none',
                display: 'flex', flexDirection: 'column', gap: 2,
              }}>
                <span style={{ fontSize: 11, color: 'var(--fl-on-dark)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {item.description || item.value || item.name || item.source || JSON.stringify(item).slice(0, 120)}
                </span>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                  {item.timestamp && (
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d6080' }}>
                      {fmtTs(item.timestamp)}
                    </span>
                  )}
                  {item.source && item.source !== (item.description || '') && (
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
                      {item.source}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

function DissimulationPanel({ caseId, records }) {
  const { t } = useTranslation();
  const [tsData,   setTsData]   = useState(null);
  const [dextData, setDextData] = useState(null);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    Promise.allSettled([
      detectionsAPI.timestomping(caseId),
      detectionsAPI.doubleExt(caseId),
    ]).then(([tsRes, dextRes]) => {
      if (tsRes.status === 'fulfilled')   setTsData(tsRes.value.data);
      if (dextRes.status === 'fulfilled') setDextData(dextRes.value.data);
      setLoading(false);
    });
  }, [caseId]);

  const mftAnomalies = useMemo(() => {
    if (!records) return [];
    return records.filter(r =>
      r.artifact_type === 'mft' &&
      r.raw && (r.raw['Created0x10'] || r.raw['LastModified0x10']) &&
      r.raw['Created0x30'] && r.raw['Created0x10'] &&
      r.raw['Created0x10'] !== r.raw['Created0x30']
    ).slice(0, 100);
  }, [records]);

  if (loading) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 11 }}>
      {t('workbench.loading_evasion')}
    </div>
  );

  const tsFindings  = tsData?.findings   || tsData?.results   || (Array.isArray(tsData)   ? tsData   : []);
  const dextFindings = dextData?.findings || dextData?.results || (Array.isArray(dextData) ? dextData : []);

  const total = tsFindings.length + dextFindings.length + mftAnomalies.length;

  if (total === 0) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, flexDirection: 'column' }}>
      <Eye size={28} style={{ color: '#22c55e', opacity: 0.5 }} />
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-subtle)' }}>
        {t('workbench.no_evasion')}
      </span>
    </div>
  );

  function ArtifactRow({ item, type, label, color }) {
    return (
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 12px',
        borderBottom: '1px solid var(--fl-bg)', flexWrap: 'wrap',
      }}>
        <SeverityBadge level={item.severity || (type === 'timestomping' ? 'high' : type === 'double_ext' ? 'medium' : 'low')} />
        <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3,
          background: `${color}15`, color, border: `1px solid ${color}30`, flexShrink: 0 }}>
          {label}
        </span>
        <span style={{ fontSize: 11, color: 'var(--fl-on-dark)', fontFamily: 'monospace', flex: 1, wordBreak: 'break-all', minWidth: 0 }}>
          {item.description || item.filename || item.name || item.value || item.source || JSON.stringify(item).slice(0, 120)}
        </span>
        {item.timestamp && (
          <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d6080', flexShrink: 0 }}>
            {fmtTs(item.timestamp)}
          </span>
        )}
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
      
      <div style={{
        flexShrink: 0, padding: '6px 12px', background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-bg)',
        fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-subtle)',
        textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', gap: 10, alignItems: 'center',
      }}>
        <Eye size={10} />
        {total} {total !== 1 ? t('workbench.evasion_items_pl') : t('workbench.evasion_items')}
        {tsFindings.length > 0 && <span style={{ color: 'var(--fl-warn)' }}>Timestomping ×{tsFindings.length}</span>}
        {dextFindings.length > 0 && <span style={{ color: 'var(--fl-danger)' }}>Double ext. ×{dextFindings.length}</span>}
        {mftAnomalies.length > 0 && <span style={{ color: 'var(--fl-purple)' }}>{t('workbench.mft_anomalies')} ×{mftAnomalies.length}</span>}
      </div>
      
      {tsFindings.map((item, i) => <ArtifactRow key={`ts-${i}`} item={item} type="timestomping" label="Timestomping" color="var(--fl-warn)" />)}
      
      {dextFindings.map((item, i) => <ArtifactRow key={`dx-${i}`} item={item} type="double_ext" label="Double extension" color="var(--fl-danger)" />)}
      
      {mftAnomalies.map((item, i) => (
        <ArtifactRow key={`mft-${i}`} item={{ ...item, description: `${item.raw?.['FileName'] || item.source} — ${t('workbench.mft_desc', { sia: item.raw?.['Created0x10'], fn: item.raw?.['Created0x30'] })}` }}
          type="mft_anomaly" label={t('workbench.mft_anomaly')} color="var(--fl-purple)" />
      ))}
    </div>
  );
}

function ResizeHandle() {
  return (
    <PanelResizeHandle style={{ width: 6, background: 'var(--fl-bg)', cursor: 'col-resize', position: 'relative', flexShrink: 0 }}>
      <div style={{
        position: 'absolute',
        left: '50%', top: '50%',
        transform: 'translate(-50%, -50%)',
        width: 3, height: 36,
        borderRadius: 2,
        background: 'var(--fl-sep)',
        pointerEvents: 'none',
      }} />
    </PanelResizeHandle>
  );
}


/* ─── ProcessTree ───────────────────────────────────────────────────────────── */
function ProcessTreeView({ records }) {
  const nodes = useMemo(() => {
    const map = new Map(); // pid → node
    const roots = [];
    const evts = records.filter(r => {
      const eid = String(r.raw?.EventID || r.raw?.EventId || '');
      return eid === '4688' || (r.artifact_type === 'evtx' && eid === '1') || r.artifact_type === 'process';
    });
    evts.forEach(r => {
      const pid  = String(r.raw?.NewProcessId || r.raw?.ProcessId || r.raw?.pid || '?');
      const ppid = String(r.raw?.ProcessId    || r.raw?.ParentProcessId || r.raw?.ppid || '0');
      const img  = r.raw?.NewProcessName || r.raw?.Image || r.raw?.process_name || r.process_name || pid;
      const name = img.split(/[\\/]/).pop();
      map.set(pid, { pid, ppid, name, img, ts: r.timestamp, record: r, children: [] });
    });
    map.forEach(node => {
      if (node.ppid && map.has(node.ppid)) {
        map.get(node.ppid).children.push(node);
      } else {
        roots.push(node);
      }
    });
    return roots;
  }, [records]);

  function renderNode(node, depth) {
    const c = depth === 0 ? 'var(--fl-accent)' : depth === 1 ? 'var(--fl-warn)' : 'var(--fl-on-dark)';
    return (
      <div key={node.pid} style={{ marginLeft: depth * 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 6px', borderRadius: 3, marginBottom: 2 }}>
          <span style={{ fontSize: 9, color: '#2a5a8a', fontFamily: 'monospace', flexShrink: 0 }}>{node.pid}</span>
          <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 600, color: c, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={node.img}>{node.name}</span>
          <span style={{ fontSize: 8, color: '#2a4a6a', fontFamily: 'monospace', flexShrink: 0 }}>{node.ts ? fmtTs(node.ts).slice(0, 19) : ''}</span>
        </div>
        {node.children.map(ch => renderNode(ch, depth + 1))}
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '12px', background: '#05080f' }}>
      <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
        Arbre de processus — EID 4688 / Sysmon 1 ({nodes.length} racines)
      </div>
      {nodes.length === 0 ? (
        <div style={{ textAlign: 'center', marginTop: 40, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
          Aucun événement de création de processus (EID 4688 ou Sysmon 1) dans la sélection
        </div>
      ) : nodes.map(n => renderNode(n, 0))}
    </div>
  );
}

/* ─── PatternMatcher ────────────────────────────────────────────────────────── */
function PatternMatcherView({ records }) {
  const hits = useMemo(() => {
    const results = [];
    for (const pattern of IOA_PATTERNS) {
      const matched = records.filter(r => { try { return pattern.match(r); } catch { return false; } });
      if (matched.length > 0) results.push({ pattern, matched });
    }
    return results;
  }, [records]);

  const [expanded, setExpanded] = useState(new Set());
  const toggle = id => setExpanded(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '12px', background: '#05080f' }}>
      <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
        Détection de patterns IoA — {hits.length} pattern(s) détecté(s)
      </div>
      {hits.length === 0 ? (
        <div style={{ textAlign: 'center', marginTop: 40, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
          Aucun pattern IoA détecté dans les {records.length} événements chargés
        </div>
      ) : hits.map(({ pattern, matched }) => (
        <div key={pattern.id} style={{ marginBottom: 8, borderRadius: 6, border: `1px solid ${pattern.color}40`, overflow: 'hidden' }}>
          <div
            onClick={() => toggle(pattern.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px',
              background: `${pattern.color}12`, cursor: 'pointer',
            }}>
            {expanded.has(pattern.id) ? <ChevronDown size={10} style={{ color: pattern.color, flexShrink: 0 }} /> : <ChevronRight size={10} style={{ color: pattern.color, flexShrink: 0 }} />}
            <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'monospace', color: pattern.color }}>⚡ {pattern.name}</span>
            <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#4d6080' }}>{pattern.tactic}</span>
            <span style={{ marginLeft: 'auto', fontSize: 9, padding: '1px 6px', borderRadius: 8, background: `${pattern.color}25`, color: pattern.color, fontFamily: 'monospace' }}>
              {matched.length} hit{matched.length > 1 ? 's' : ''}
            </span>
          </div>
          {expanded.has(pattern.id) && (
            <div style={{ padding: '6px 10px', display: 'flex', flexDirection: 'column', gap: 3 }}>
              {matched.slice(0, 20).map((r, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 6px', borderRadius: 3, background: 'rgba(255,255,255,0.02)', fontSize: 10, fontFamily: 'monospace' }}>
                  <span style={{ color: '#3a6a9a', flexShrink: 0, width: 130 }}>{fmtTs(r.timestamp).slice(0, 19)}</span>
                  <span style={{ color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{r.description || r.source}</span>
                </div>
              ))}
              {matched.length > 20 && <span style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'monospace' }}>+{matched.length - 20} autres</span>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ─── ClusterView ───────────────────────────────────────────────────────────── */
function ClusterView({ records }) {
  const [groupBy, setGroupBy] = useState('artifact_type');
  const fields = ['artifact_type', 'host_name', 'user_name', 'process_name', 'source'];

  const clusters = useMemo(() => {
    const map = new Map();
    records.forEach(r => {
      const key = String(r[groupBy] || r.raw?.[groupBy] || '—');
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(r);
    });
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [records, groupBy]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#05080f' }}>
      <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)' }}>
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Grouper par</span>
        {fields.map(f => (
          <button key={f} onClick={() => setGroupBy(f)}
            style={{
              padding: '2px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', cursor: 'pointer',
              background: groupBy === f ? 'rgba(77,130,192,0.2)' : 'transparent',
              border: `1px solid ${groupBy === f ? 'var(--fl-accent)' : 'var(--fl-sep)'}`,
              color: groupBy === f ? 'var(--fl-accent)' : 'var(--fl-muted)',
            }}>{f}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>{clusters.length} groupes</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {clusters.map(([key, rows]) => {
          const pct = records.length > 0 ? (rows.length / records.length) * 100 : 0;
          const c = ac(rows[0]?.artifact_type);
          return (
            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px', borderRadius: 4, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-on-dark)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={key}>{key}</span>
              <div style={{ width: 80, height: 4, background: 'var(--fl-sep)', borderRadius: 2, overflow: 'hidden', flexShrink: 0 }}>
                <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 2 }} />
              </div>
              <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', flexShrink: 0, width: 40, textAlign: 'right' }}>{rows.length}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─── MultiHostTrackView ────────────────────────────────────────────────────── */
function MultiHostTrackView({ records }) {
  const hosts = useMemo(() => [...new Set(records.map(r => r.host_name).filter(Boolean))].sort(), [records]);
  const [selHost, setSelHost] = useState(null);
  const displayed = useMemo(() => selHost ? records.filter(r => r.host_name === selHost) : records, [records, selHost]);

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', background: '#05080f' }}>
      <div style={{ width: 160, flexShrink: 0, borderRight: '1px solid var(--fl-border)', overflow: 'auto', padding: '8px 0' }}>
        <div style={{ padding: '4px 12px 6px', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Hôtes</div>
        <div onClick={() => setSelHost(null)}
          style={{ padding: '4px 12px', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', color: !selHost ? 'var(--fl-accent)' : 'var(--fl-muted)', background: !selHost ? 'rgba(77,130,192,0.1)' : 'transparent' }}>
          Tous ({records.length})
        </div>
        {hosts.map(h => {
          const cnt = records.filter(r => r.host_name === h).length;
          return (
            <div key={h} onClick={() => setSelHost(h)}
              style={{ padding: '4px 12px', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', color: selHost === h ? 'var(--fl-accent)' : 'var(--fl-on-dark)', background: selHost === h ? 'rgba(77,130,192,0.1)' : 'transparent', borderLeft: selHost === h ? '2px solid var(--fl-accent)' : '2px solid transparent', display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{h}</span>
              <span style={{ color: 'var(--fl-subtle)', flexShrink: 0 }}>{cnt}</span>
            </div>
          );
        })}
        {hosts.length === 0 && <div style={{ padding: '8px 12px', fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>Aucun hôte</div>}
      </div>
      <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px' }}>
        <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', marginBottom: 8 }}>
          {selHost ? `Hôte: ${selHost}` : 'Tous les hôtes'} — {displayed.length} événements
        </div>
        {displayed.slice(0, 200).map((r, i) => {
          const c = ac(r.artifact_type);
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 4px', borderLeft: `2px solid ${c}`, marginBottom: 2, paddingLeft: 8 }}>
              <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3a6a9a', flexShrink: 0, width: 130 }}>{fmtTs(r.timestamp).slice(0, 19)}</span>
              <span style={{ fontSize: 9, padding: '0 4px', borderRadius: 2, background: `${c}18`, color: c, fontFamily: 'monospace', flexShrink: 0 }}>{r.artifact_type}</span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{r.description || r.source}</span>
              {r.host_name && !selHost && <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#22c55e', flexShrink: 0 }}>{r.host_name}</span>}
            </div>
          );
        })}
        {displayed.length > 200 && <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-muted)', textAlign: 'center', padding: '8px' }}>+{displayed.length - 200} événements supplémentaires</div>}
      </div>
    </div>
  );
}

/* ─── AttackChainBuilderView ─────────────────────────────────────────────────── */
function AttackChainBuilderView({ records }) {
  const [chain, setChain] = useState([]);
  const [label, setLabel] = useState('');

  const suggestions = useMemo(() => {
    return records.filter(r => {
      const ioas = IOA_PATTERNS.filter(p => { try { return p.match(r); } catch { return false; } });
      return ioas.length > 0;
    }).slice(0, 50);
  }, [records]);

  const addToChain = r => {
    setChain(prev => {
      if (prev.find(x => x === r)) return prev;
      return [...prev, r];
    });
  };

  const TACTIC_ORDER = ['recon','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','exfiltration','impact'];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', background: '#05080f' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: '1px solid var(--fl-border)' }}>
        <div style={{ flexShrink: 0, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Événements notables ({suggestions.length})
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: '6px' }}>
          {suggestions.map((r, i) => {
            const ioas = IOA_PATTERNS.filter(p => { try { return p.match(r); } catch { return false; } });
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', borderRadius: 4, marginBottom: 3, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 9, fontFamily: 'monospace', color: '#3a6a9a' }}>{fmtTs(r.timestamp).slice(0, 19)}</div>
                  <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || r.source}</div>
                  <div style={{ display: 'flex', gap: 3, marginTop: 2 }}>
                    {ioas.map(p => <span key={p.id} style={{ fontSize: 7, padding: '0 4px', borderRadius: 2, background: `${p.color}20`, color: p.color, fontFamily: 'monospace' }}>{p.name}</span>)}
                  </div>
                </div>
                <button onClick={() => addToChain(r)}
                  style={{ flexShrink: 0, padding: '2px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', background: 'rgba(77,130,192,0.1)', border: '1px solid var(--fl-accent)', color: 'var(--fl-accent)', cursor: 'pointer' }}>
                  +
                </button>
              </div>
            );
          })}
          {suggestions.length === 0 && <div style={{ textAlign: 'center', marginTop: 20, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>Aucun événement notable détecté</div>}
        </div>
      </div>

      <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flexShrink: 0, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', flex: 1 }}>Chaîne d'attaque ({chain.length})</span>
          {chain.length > 0 && <button onClick={() => setChain([])} style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-danger)', background: 'none', border: 'none', cursor: 'pointer' }}>Vider</button>}
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: '6px 10px' }}>
          {chain.length === 0 ? (
            <div style={{ textAlign: 'center', marginTop: 20, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>Ajoutez des événements depuis la liste</div>
          ) : chain.map((r, i) => {
            const c = ac(r.artifact_type);
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 4 }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: c, marginTop: 2 }} />
                  {i < chain.length - 1 && <div style={{ width: 1, height: 24, background: 'var(--fl-sep)', marginTop: 2 }} />}
                </div>
                <div style={{ flex: 1, minWidth: 0, padding: '2px 6px', borderRadius: 3, background: 'var(--fl-bg)', border: `1px solid ${c}30` }}>
                  <div style={{ fontSize: 8, fontFamily: 'monospace', color: '#3a6a9a' }}>{fmtTs(r.timestamp).slice(0, 19)}</div>
                  <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || r.source}</div>
                </div>
                <button onClick={() => setChain(prev => prev.filter((_, j) => j !== i))}
                  style={{ flexShrink: 0, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-danger)', fontSize: 9, padding: '2px' }}>✕</button>
              </div>
            );
          })}
        </div>
        {chain.length > 0 && (
          <div style={{ flexShrink: 0, padding: '8px 10px', borderTop: '1px solid var(--fl-border)' }}>
            <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Nom du rapport…"
              style={{ width: '100%', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'monospace', fontSize: 9, padding: '4px 8px', outline: 'none', boxSizing: 'border-box', marginBottom: 6 }} />
            <button
              onClick={() => {
                const lines = [`# Chaîne d'attaque${label ? ': ' + label : ''}`, `Générée le ${new Date().toISOString()}`, '', ...chain.map((r, i) => `${i + 1}. [${r.artifact_type}] ${fmtTs(r.timestamp)} — ${r.description || r.source}`)].join('\n');
                navigator.clipboard.writeText(lines).catch(() => {});
              }}
              style={{ width: '100%', padding: '4px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace', background: 'rgba(77,130,192,0.15)', border: '1px solid var(--fl-accent)', color: 'var(--fl-accent)', cursor: 'pointer' }}>
              Copier le rapport
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── ExportFindingsView ─────────────────────────────────────────────────────── */
function ExportFindingsView({ records, caseId }) {
  const [format, setFormat] = useState('csv');
  const [scope, setScope]   = useState('all');
  const [withIoa, setWithIoa] = useState(true);

  function doExport() {
    const rows = scope === 'ioa'
      ? records.filter(r => IOA_PATTERNS.some(p => { try { return p.match(r); } catch { return false; } }))
      : records;

    if (format === 'csv') {
      const header = 'timestamp,artifact_type,host,user,process,description,source,ioa_patterns';
      const csv = [header, ...rows.map(r => {
        const ioas = withIoa ? IOA_PATTERNS.filter(p => { try { return p.match(r); } catch { return false; } }).map(p => p.name).join('|') : '';
        return [r.timestamp, r.artifact_type, r.host_name, r.user_name, r.process_name, r.description, r.source, ioas]
          .map(v => `"${String(v ?? '').replace(/"/g, '""')}"`)
          .join(',');
      })].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `heimdall-export-${Date.now()}.csv`; a.click();
      URL.revokeObjectURL(url);
    } else if (format === 'json') {
      const data = rows.map(r => ({
        timestamp: r.timestamp, artifact_type: r.artifact_type, host: r.host_name, user: r.user_name,
        process: r.process_name, description: r.description, source: r.source,
        ioa_patterns: withIoa ? IOA_PATTERNS.filter(p => { try { return p.match(r); } catch { return false; } }).map(p => p.name) : [],
        raw: r.raw,
      }));
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `heimdall-export-${Date.now()}.json`; a.click();
      URL.revokeObjectURL(url);
    } else if (format === 'md') {
      const ioas = IOA_PATTERNS.filter(p => records.some(r => { try { return p.match(r); } catch { return false; } }));
      const lines = [
        `# Rapport d'investigation Heimdall DFIR`,
        `**Date**: ${new Date().toISOString()}`,
        `**Événements analysés**: ${records.length}`,
        '',
        '## Patterns IoA détectés',
        ioas.length > 0
          ? ioas.map(p => `- **${p.name}** (${p.tactic}): ${records.filter(r => { try { return p.match(r); } catch { return false; } }).length} occurrence(s)`).join('\n')
          : '_Aucun pattern détecté_',
        '',
        '## Événements exportés',
        `| Timestamp | Type | Hôte | Description |`,
        `|---|---|---|---|`,
        ...rows.slice(0, 500).map(r => `| ${r.timestamp || ''} | ${r.artifact_type || ''} | ${r.host_name || ''} | ${(r.description || '').replace(/\|/g, '\\|').slice(0, 100)} |`),
        rows.length > 500 ? `\n_...et ${rows.length - 500} événements supplémentaires_` : '',
      ].join('\n');
      const blob = new Blob([lines], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `heimdall-rapport-${Date.now()}.md`; a.click();
      URL.revokeObjectURL(url);
    }
  }

  const scopeRows = scope === 'ioa' ? records.filter(r => IOA_PATTERNS.some(p => { try { return p.match(r); } catch { return false; } })) : records;

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px', background: '#05080f' }}>
      <div style={{ maxWidth: 520, margin: '0 auto' }}>
        <div style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>Export & Rapport</div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', marginBottom: 6 }}>Format</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['csv', 'json', 'md'].map(f => (
              <button key={f} onClick={() => setFormat(f)}
                style={{ padding: '5px 14px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', fontWeight: format === f ? 700 : 400, background: format === f ? 'rgba(77,130,192,0.2)' : 'transparent', border: `1px solid ${format === f ? 'var(--fl-accent)' : 'var(--fl-sep)'}`, color: format === f ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', marginBottom: 6 }}>Périmètre</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {[{ k: 'all', l: `Tous (${records.length})` }, { k: 'ioa', l: `IoA seulement (${records.filter(r => IOA_PATTERNS.some(p => { try { return p.match(r); } catch { return false; } })).length})` }].map(opt => (
              <button key={opt.k} onClick={() => setScope(opt.k)}
                style={{ padding: '5px 14px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', fontWeight: scope === opt.k ? 700 : 400, background: scope === opt.k ? 'rgba(77,130,192,0.2)' : 'transparent', border: `1px solid ${scope === opt.k ? 'var(--fl-accent)' : 'var(--fl-sep)'}`, color: scope === opt.k ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>
                {opt.l}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" id="withIoa" checked={withIoa} onChange={e => setWithIoa(e.target.checked)} />
          <label htmlFor="withIoa" style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', cursor: 'pointer' }}>
            Inclure colonne IoA patterns
          </label>
        </div>

        <div style={{ padding: '12px', borderRadius: 6, background: 'rgba(77,130,192,0.05)', border: '1px solid var(--fl-sep)', marginBottom: 16, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>
          {scopeRows.length} événements · format {format.toUpperCase()}
        </div>

        <button onClick={doExport}
          style={{ width: '100%', padding: '10px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace', fontWeight: 700, cursor: 'pointer', background: 'rgba(77,130,192,0.2)', border: '1px solid var(--fl-accent)', color: 'var(--fl-accent)' }}>
          ↓ Télécharger le rapport
        </button>
      </div>
    </div>
  );
}

/* ─── end new view components ──────────────────────────────────────────────── */

export default function SuperTimelineWorkbench({ records, availTypes, caseId, onFilterTimeline, socket, total = 0, page = 1, totalPages = 1, onPageChange, onExitWorkbench, enteredAt, onAITabChange }) {
  const { t } = useTranslation();
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [notedRefs, setNotedRefs]           = useState(new Set());
  const [gapThresholdMs, setGapThresholdMs] = useState(0);
  const [searchParams, setSearchParams]     = useSearchParams();
  const activeTab                           = searchParams.get('tab') || 'timeline';
  const setActiveTab                        = useCallback((newTab) => {
    setSearchParams(prev => { const p = new URLSearchParams(prev); p.set('tab', newTab); return p; });
  }, [setSearchParams]);
  const [pinnedRows, setPinnedRows]         = useState(new Map()); // key = pin.id
  const [pinsOpen, setPinsOpen]             = useState(true);
  const [promoteDialog, setPromoteDialog]   = useState(null); // pin object or null

  const [elapsed, setElapsed] = useState('00:00');
  useEffect(() => {
    if (!enteredAt) return;
    const iv = setInterval(() => {
      const s = Math.floor((Date.now() - enteredAt) / 1000);
      const mm = String(Math.floor(s / 60)).padStart(2, '0');
      const ss = String(s % 60).padStart(2, '0');
      setElapsed(`${mm}:${ss}`);
    }, 1000);
    return () => clearInterval(iv);
  }, [enteredAt]);

  const singleType = useMemo(() => {
    if (availTypes?.length === 1) return availTypes[0];
    if (!records?.length) return null;
    const first = records[0].artifact_type;
    return records.every(r => r.artifact_type === first) ? first : null;
  }, [availTypes, records]);

  useEffect(() => { setSelectedRecord(null); }, [records]);

  const [processFilter, setProcessFilter] = useState(null);
  const [quickFilter, setQuickFilter] = useState(null); // null | { field:'hay_severity'|'text'|'host'|'user', value }

  const filteredRecords = useMemo(() => {
    let rows = records || [];
    if (processFilter) {
      rows = rows.filter(r => {
        const p = r.process_name || r.raw?.ProcessName || r.raw?.process_name || '';
        return String(p).toLowerCase() === processFilter.toLowerCase();
      });
    }
    if (quickFilter) {
      if (quickFilter.field === 'hay_severity') {
        rows = rows.filter(r => r.hay_severity === quickFilter.value || r.artifact_type === 'hayabusa' && r.hay_severity === quickFilter.value);
      } else if (quickFilter.field === 'text') {
        const q = quickFilter.value.toLowerCase();
        rows = rows.filter(r =>
          (r.description || '').toLowerCase().includes(q) ||
          (r.source || '').toLowerCase().includes(q) ||
          (r.artifact_type || '').toLowerCase().includes(q)
        );
      } else if (quickFilter.field === 'host') {
        rows = rows.filter(r => r.host_name === quickFilter.value);
      } else if (quickFilter.field === 'user') {
        rows = rows.filter(r => r.user_name === quickFilter.value);
      }
    }
    return rows;
  }, [records, processFilter, quickFilter]);

  const [showPlayback, setShowPlayback] = useState(false);
  const [playbackHighlight, setPlaybackHighlight] = useState(null);

  const [verdictMap, setVerdictMap] = useState(new Map());
  useEffect(() => {
    if (!caseId) return;
    collectionAPI.verdicts(caseId)
      .then(r => {
        const m = new Map();
        for (const v of (r.data?.verdicts || [])) m.set(v.event_ref, v.verdict);
        setVerdictMap(m);
      })
      .catch(() => {});
  }, [caseId]);
  const handleVerdictChange = useCallback((ref, verdict) => {
    setVerdictMap(prev => {
      const m = new Map(prev);
      if (verdict === null) m.delete(ref);
      else m.set(ref, verdict);
      return m;
    });
  }, []);

  const [showCmdPalette, setShowCmdPalette] = useState(false);
  const [showActionsMenu, setShowActionsMenu] = useState(false);
  const actionsMenuRef = useRef(null);
  useEffect(() => {
    function h(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setShowCmdPalette(v => !v);
      }
    }
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  useEffect(() => {
    function h(e) {
      if (actionsMenuRef.current && !actionsMenuRef.current.contains(e.target)) {
        setShowActionsMenu(false);
      }
    }
    if (showActionsMenu) {
      document.addEventListener('mousedown', h);
      return () => document.removeEventListener('mousedown', h);
    }
  }, [showActionsMenu]);

  function handlePaletteCommand(id) {
    if (id === 'exit') { onExitWorkbench?.(); return; }

    if (id.startsWith('view:')) {
      const v = id.slice(5);
      if (v === 'playback') { setShowPlayback(p => !p); setActiveTab('timeline'); onAITabChange?.(false); }
      else if (v === 'gantt')    { setActiveTab('gantt');    onAITabChange?.(false); }
      else if (v === 'heatmap')  { setActiveTab('heatmap');  onAITabChange?.(false); }
      else if (v === 'mitre')    { setActiveTab('mitre');    onAITabChange?.(false); }
      else if (v === 'timeline') { setActiveTab('timeline'); onAITabChange?.(false); }
      return;
    }

    if (id.startsWith('tab:')) {
      const m = { timeline: 'timeline', persistence: 'persistence', dissim: 'dissimulation' };
      const newTab = m[id.slice(4)] || 'timeline';
      setActiveTab(newTab);
      onAITabChange?.(false);
      return;
    }

    if (id.startsWith('type:')) {
      onFilterTimeline?.(id.slice(5));
      return;
    }

    if (id.startsWith('filter:')) {
      const kw = id.slice(7); // critical, high, malware, lsass, powershell
      if (kw === 'critical' || kw === 'high') {
        setQuickFilter({ field: 'hay_severity', value: kw });
      } else {
        setQuickFilter({ field: 'text', value: kw });
      }
      setActiveTab('timeline');
      return;
    }

    if (id === 'copy:all') {
      const rows = filteredRecords.slice(0, 5000);
      const header = 'timestamp,artifact_type,source,description,host,user,process';
      const csv = [header, ...rows.map(r =>
        [r.timestamp, r.artifact_type, r.source, r.description, r.host_name, r.user_name, r.process_name]
          .map(v => `"${String(v ?? '').replace(/"/g, '""')}"`)
          .join(',')
      )].join('\n');
      navigator.clipboard.writeText(csv).catch(() => {});
      return;
    }
  }

  const workbenchTabs = useMemo(() => [
    { id: 'timeline',      label: t('workbench.tab_timeline'),    icon: Clock },
    { id: 'gantt',         label: 'Gantt',                        icon: Tag },
    { id: 'heatmap',       label: 'Heatmap',                      icon: AlertTriangle },
    { id: 'mitre',         label: 'MITRE',                        icon: ShieldAlert },
    { id: 'persistence',   label: t('workbench.tab_persistence'), icon: HardDrive },
    { id: 'dissimulation', label: t('workbench.tab_evasion'),     icon: Eye },
    { id: 'process-tree',  label: 'Processus',                    icon: GitBranch },
    { id: 'patterns',      label: 'IoA',                          icon: Zap },
    { id: 'cluster',       label: 'Cluster',                      icon: Layers },
    { id: 'multi-host',    label: 'Multi-hôte',                   icon: Network },
    { id: 'attack-chain',  label: 'Kill Chain',                   icon: Activity },
    { id: 'export',        label: 'Export',                       icon: Download },
    { id: 'ai',            label: 'IA',                           icon: Bot },
  ], [t]);

  const gapThresholds = useMemo(() => [
    { label: t('common.none'), ms: 0 },
    { label: '5 min',  ms: 5  * 60 * 1000 },
    { label: '30 min', ms: 30 * 60 * 1000 },
    { label: '1h',     ms: 60 * 60 * 1000 },
    { label: '4h',     ms: 4  * 60 * 60 * 1000 },
  ], [t]);

  const loadNotedRefs = useCallback(() => {
    if (!caseId) return;
    artifactsAPI.refsWithNotes(caseId)
      .then(res => setNotedRefs(new Set(res.data?.refs ?? [])))
      .catch(e => console.warn('[Workbench] noted refs:', e.message));
  }, [caseId]);

  useEffect(() => { loadNotedRefs(); }, [loadNotedRefs]);

  useEffect(() => {
    if (!caseId) return;
    pinsAPI.list(caseId)
      .then(res => {
        const map = new Map();
        for (const p of (res.data?.pins ?? res.data ?? [])) map.set(p.id, p);
        setPinnedRows(map);
      })
      .catch(e => console.warn('[Workbench] pins load:', e.message));
  }, [caseId]);

  useEffect(() => {
    if (!socket) return;
    function onAdded(pin) {
      setPinnedRows(prev => new Map(prev).set(pin.id, pin));
    }
    function onRemoved({ id }) {
      setPinnedRows(prev => { const m = new Map(prev); m.delete(id); return m; });
    }
    function onPromoted(pin) {
      setPinnedRows(prev => new Map(prev).set(pin.id, pin));
    }
    socket.on('timeline:pin:added',   onAdded);
    socket.on('timeline:pin:removed', onRemoved);
    socket.on('timeline:pin:promoted', onPromoted);
    return () => {
      socket.off('timeline:pin:added',   onAdded);
      socket.off('timeline:pin:removed', onRemoved);
      socket.off('timeline:pin:promoted', onPromoted);
    };
  }, [socket]);

  async function handlePin(record) {
    if (!caseId || !record) return;
    const existing = [...pinnedRows.values()].find(
      p => p.event_ts === record.timestamp && p.source === record.source
    );
    if (existing) {
      try { await pinsAPI.remove(caseId, existing.id); } catch {}
    } else {
      try {
        await pinsAPI.add(caseId, {
          event_ts:     record.timestamp,
          artifact_type: record.artifact_type,
          description:  record.description,
          source:       record.source,
          raw_data:     record.raw ?? null,
          evidence_id:  record.evidence_id ?? null,
        });
      } catch {}
    }
  }

  function isPinned(record) {
    return [...pinnedRows.values()].some(
      p => p.event_ts === record.timestamp && p.source === record.source
    );
  }

  async function handlePromoteConfirm(pin) {
    setPromoteDialog(null);
    try {
      await pinsAPI.promote(caseId, pin.id);
    } catch (e) {
      console.warn('[Workbench] promote pin:', e.message);
    }
  }

  function handleSelect(record) {
    setSelectedRecord(prev => prev === record ? null : record);
  }

  return (
    <div style={{ height: '100%', overflow: 'hidden', display: 'flex', flexDirection: 'column', background: 'var(--fl-bg)' }}>

      
      <div style={{
        flexShrink: 0,
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '6px 14px',
        background: 'linear-gradient(90deg, #06111f 0%, #091624 60%, var(--fl-bg) 100%)',
        borderBottom: '2px solid var(--fl-accent)',
        boxShadow: '0 1px 12px rgba(77,130,192,0.12)',
      }}>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{
            display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
            background: 'var(--fl-accent)',
            boxShadow: '0 0 6px var(--fl-accent)',
            animation: 'wbPulse 2s ease-in-out infinite',
          }} />
          <style>{`@keyframes wbPulse { 0%,100%{opacity:1;box-shadow:0 0 6px var(--fl-accent)} 50%{opacity:.5;box-shadow:0 0 12px var(--fl-accent)} }`}</style>
          <span style={{
            fontSize: 9, fontFamily: 'monospace', fontWeight: 800,
            textTransform: 'uppercase', letterSpacing: '0.12em',
            color: 'var(--fl-accent)',
          }}>
            Mode Investigation
          </span>
        </div>

        
        <div style={{ width: 1, height: 14, background: 'var(--fl-accent)' }} />

        
        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3a6a9a' }}>
          <span style={{ color: '#7abfff', fontWeight: 700 }}>{filteredRecords?.length?.toLocaleString() ?? 0}</span>
          {processFilter
            ? <span style={{ color: '#22c55e' }}> filtrés</span>
            : total > 0 ? <> / {total.toLocaleString()} événements</> : null
          }
        </span>

        
        {total > 2000 && totalPages > 1 && onPageChange && (
          <>
            <div style={{ width: 1, height: 14, background: 'var(--fl-accent)' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <button
                onClick={() => onPageChange(page - 1)}
                disabled={page <= 1}
                style={{
                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                  background: 'transparent', border: '1px solid var(--fl-accent)',
                  color: page <= 1 ? 'var(--fl-accent)' : 'var(--fl-accent)', cursor: page <= 1 ? 'default' : 'pointer',
                }}>‹</button>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3a6a9a' }}>
                {page} / {totalPages}
              </span>
              <button
                onClick={() => onPageChange(page + 1)}
                disabled={page >= totalPages}
                style={{
                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                  background: 'transparent', border: '1px solid var(--fl-accent)',
                  color: page >= totalPages ? 'var(--fl-accent)' : 'var(--fl-accent)', cursor: page >= totalPages ? 'default' : 'pointer',
                }}>›</button>
            </div>
          </>
        )}

        
        <div style={{ flex: 1 }} />

        
        {enteredAt && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={9} style={{ color: '#2a5a8a' }} />
            <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#2a5a8a', letterSpacing: '0.05em' }}>
              {elapsed}
            </span>
          </div>
        )}

        
        <div ref={actionsMenuRef} style={{ position: 'relative' }}>
          <button
            onClick={() => setShowActionsMenu(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '3px 10px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
              background: showActionsMenu ? 'rgba(77,130,192,0.18)' : 'rgba(77,130,192,0.08)',
              border: `1px solid ${showActionsMenu ? '#4d82c060' : 'var(--fl-accent)'}`,
              color: showActionsMenu ? '#7abfff' : 'var(--fl-accent)',
              cursor: 'pointer', fontWeight: 600,
            }}
          >
            ⚡ Actions <ChevronDown size={9} style={{ transform: showActionsMenu ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
          </button>
          {showActionsMenu && (
            <div style={{
              position: 'absolute', top: '100%', right: 0, marginTop: 4,
              zIndex: 9000, background: '#0a1520', border: '1px solid var(--fl-accent)',
              borderRadius: 8, boxShadow: '0 12px 40px rgba(0,0,0,0.7)',
              width: 520, padding: '10px 0', userSelect: 'none',
            }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 0 }}>
                
                <ActionMenuSection title="Vues" icon="🖥">
                  {[
                    { id: 'view:timeline',  label: 'Timeline',    icon: '⏱' },
                    { id: 'view:gantt',     label: 'Gantt',       icon: '📊' },
                    { id: 'view:heatmap',   label: 'Heatmap',     icon: '🔥' },
                    { id: 'view:mitre',     label: 'MITRE Live',  icon: '🎯' },
                    { id: 'view:playback',  label: 'Lecture auto',icon: '▶'  },
                    { id: 'tab:persistence',label: 'Persistance', icon: '🛡' },
                    { id: 'tab:dissim',     label: 'Dissimulation',icon:'👁' },
                  ].map(c => (
                    <ActionMenuItem key={c.id} icon={c.icon} label={c.label}
                      onClick={() => { handlePaletteCommand(c.id); setShowActionsMenu(false); }} />
                  ))}
                </ActionMenuSection>
                
                <ActionMenuSection title="Filtres rapides" icon="🔍">
                  {[
                    { id: 'filter:critical',   label: 'Hayabusa Critical', icon: '🔴' },
                    { id: 'filter:high',        label: 'Hayabusa High',     icon: '🟠' },
                    { id: 'filter:malware',     label: 'Rechercher: malware',icon:'🔍' },
                    { id: 'filter:lsass',       label: 'Rechercher: lsass', icon: '🔍' },
                    { id: 'filter:powershell',  label: 'Rechercher: powershell',icon:'🔍' },
                  ].map(c => (
                    <ActionMenuItem key={c.id} icon={c.icon} label={c.label}
                      onClick={() => { handlePaletteCommand(c.id); setShowActionsMenu(false); }} />
                  ))}
                  {quickFilter && (
                    <ActionMenuItem icon="✕" label="Effacer le filtre actif" danger
                      onClick={() => { setQuickFilter(null); setShowActionsMenu(false); }} />
                  )}
                  {processFilter && (
                    <ActionMenuItem icon="✕" label="Effacer le suivi processus" danger
                      onClick={() => { setProcessFilter(null); setShowActionsMenu(false); }} />
                  )}
                </ActionMenuSection>
                
                <ActionMenuSection title="Actions" icon="⚡">
                  {[
                    { id: 'copy:all', label: `Copier ${filteredRecords.length} lignes CSV`, icon: '📋' },
                  ].map(c => (
                    <ActionMenuItem key={c.id} icon={c.icon} label={c.label}
                      onClick={() => { handlePaletteCommand(c.id); setShowActionsMenu(false); }} />
                  ))}
                  <ActionMenuItem icon="⌘K" label="Palette complète (Ctrl+K)"
                    onClick={() => { setShowActionsMenu(false); setShowCmdPalette(true); }} />
                  {onExitWorkbench && (
                    <ActionMenuItem icon="✕" label="Quitter Investigation" danger
                      onClick={() => { setShowActionsMenu(false); onExitWorkbench(); }} />
                  )}
                </ActionMenuSection>
              </div>
              
              {availTypes?.length > 0 && (
                <div style={{ borderTop: '1px solid var(--fl-bg)', margin: '6px 0 0', padding: '8px 14px 2px' }}>
                  <div style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
                    🏷 Filtrer par type d'artefact
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {availTypes.map(t => (
                      <button key={t} onClick={() => { handlePaletteCommand(`type:${t}`); setShowActionsMenu(false); }}
                        style={{
                          padding: '2px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                          background: 'rgba(77,130,192,0.08)', border: '1px solid var(--fl-accent)',
                          color: '#7abfff', cursor: 'pointer',
                        }}>
                        {t}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ padding: '8px 14px 2px', borderTop: '1px solid var(--fl-bg)', marginTop: 6 }}>
                <div style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', marginTop: 2 }}>
                  Astuce : <kbd style={{ border: '1px solid var(--fl-accent)', borderRadius: 2, padding: '0 4px', fontSize: 8, color: '#2a5a8a' }}>Ctrl+K</kbd> pour la palette complète avec recherche
                </div>
              </div>
            </div>
          )}
        </div>

        
        <button
          onClick={() => setShowCmdPalette(true)}
          title="Palette de commandes (Ctrl+K)"
          style={{
            display: 'flex', alignItems: 'center', gap: 4,
            padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid var(--fl-bg)',
            color: '#2a5a8a', cursor: 'pointer',
          }}
        >
          ⌘K
        </button>

        
        {onExitWorkbench && (
          <button
            onClick={onExitWorkbench}
            title="Quitter le mode investigation"
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
              background: 'transparent', border: '1px solid var(--fl-accent)',
              color: '#3a6a9a', cursor: 'pointer',
              transition: 'all 0.1s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#7abfff'; e.currentTarget.style.borderColor = '#4d82c060'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#3a6a9a'; e.currentTarget.style.borderColor = 'var(--fl-accent)'; }}
          >
            <X size={9} /> Quitter
          </button>
        )}
      </div>

      
      <div style={{
        flexShrink: 0, display: 'flex', alignItems: 'center', gap: 2,
        padding: '3px 10px', background: '#05080f', borderBottom: '1px solid var(--fl-bg)',
      }}>
        {workbenchTabs.map(tab => {
          const Icon   = tab.icon;
          const active = activeTab === tab.id;
          const color  = tab.id === 'persistence'
            ? 'var(--fl-pink)'
            : tab.id === 'dissimulation'
            ? 'var(--fl-warn)'
            : tab.id === 'gantt'
            ? '#22d3ee'
            : tab.id === 'heatmap'
            ? '#f97316'
            : tab.id === 'mitre'
            ? '#a855f7'
            : tab.id === 'ai'
            ? '#22c55e'
            : 'var(--fl-accent)';
          return (
            <button
              key={tab.id}
              onClick={() => { setActiveTab(tab.id); onAITabChange?.(tab.id === 'ai'); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '3px 10px', borderRadius: '4px 4px 0 0', fontSize: 10, fontFamily: 'monospace',
                cursor: 'pointer', background: 'none', border: 'none',
                fontWeight: active ? 700 : 400,
                color: active ? color : 'var(--fl-muted)',
                borderBottom: active ? `2px solid ${color}` : '2px solid transparent',
                transition: 'color 0.12s',
              }}
            >
              <Icon size={10} />
              {tab.label}
            </button>
          );
        })}
      </div>

      
      {activeTab === 'timeline' && (
        <QuickFilterBar
          records={records}
          availTypes={availTypes}
          quickFilter={quickFilter}
          processFilter={processFilter}
          onFilter={(field, value) => {
            if (field === 'type') onFilterTimeline?.(value);
            else setQuickFilter(value ? { field, value } : null);
          }}
          onClearProcess={() => setProcessFilter(null)}
          onClearAll={() => { setQuickFilter(null); setProcessFilter(null); }}
        />
      )}

      
      {showCmdPalette && (
        <CommandPalette
          onClose={() => setShowCmdPalette(false)}
          onCommand={handlePaletteCommand}
          recordCount={records?.length}
          availTypes={availTypes}
        />
      )}

      
      {activeTab === 'heatmap' && (
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--fl-bg)' }}>
          <TimelineHeatmap caseId={caseId} availTypes={availTypes} />
        </div>
      )}

      
      {activeTab === 'gantt' && (
        <div style={{ flex: 1, overflow: 'hidden', background: 'var(--fl-bg)' }}>
          <GanttView records={filteredRecords} onSelectRecord={r => handleSelect(r)} />
        </div>
      )}

      
      {activeTab === 'mitre' && (
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--fl-bg)' }}>
          <MitreMatrixLive records={filteredRecords} />
        </div>
      )}

      
      <div style={{ flex: 1, overflow: 'hidden', flexDirection: 'column', display: activeTab === 'ai' ? 'flex' : 'none' }}>
        <AiAnalystPanel records={filteredRecords} caseId={caseId} totalEvents={total} />
      </div>

      
      {activeTab === 'persistence' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: '#05080f' }}>
          <PersistancePanel caseId={caseId} />
        </div>
      )}
      {activeTab === 'dissimulation' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: '#05080f' }}>
          <DissimulationPanel caseId={caseId} records={records} />
        </div>
      )}

      {activeTab === 'process-tree' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <ProcessTreeView records={filteredRecords} />
        </div>
      )}

      {activeTab === 'patterns' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <PatternMatcherView records={filteredRecords} />
        </div>
      )}

      {activeTab === 'cluster' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <ClusterView records={filteredRecords} />
        </div>
      )}

      {activeTab === 'multi-host' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <MultiHostTrackView records={filteredRecords} />
        </div>
      )}

      {activeTab === 'attack-chain' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <AttackChainBuilderView records={filteredRecords} />
        </div>
      )}

      {activeTab === 'export' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <ExportFindingsView records={filteredRecords} caseId={caseId} />
        </div>
      )}


      {activeTab === 'timeline' && (
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

        
        {promoteDialog && (
          <div style={{
            position: 'fixed', inset: 0, zIndex: 9999,
            background: 'rgba(0,0,0,0.6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
            onClick={() => setPromoteDialog(null)}
          >
            <div
              onClick={e => e.stopPropagation()}
              style={{
                background: 'var(--fl-bg)', border: '1px solid #1e2d45', borderRadius: 10,
                padding: '20px 24px', width: 360, boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <Globe2 size={16} style={{ color: promoteDialog.is_global ? 'var(--fl-danger)' : '#f0b040' }} />
                <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-on-dark)', fontSize: 13 }}>
                  {promoteDialog.is_global ? 'Retirer le pin global' : 'Partager ce pin avec tous'}
                </span>
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#6a8090', marginBottom: 16, lineHeight: 1.5 }}>
                {promoteDialog.is_global
                  ? 'Ce pin ne sera plus visible par les autres membres du cas.'
                  : 'Tous les membres du cas pourront voir ce pin dans leur Workbench.'}
              </div>
              <div style={{ display: 'flex', gap: 6, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-accent)', marginBottom: 14 }}>
                <span style={{ color: ac(promoteDialog.artifact_type), flexShrink: 0 }}>[{promoteDialog.artifact_type || '?'}]</span>
                <span style={{ color: '#7abfff', flexShrink: 0 }}>{promoteDialog.event_ts ? fmtTs(promoteDialog.event_ts) : '-'}</span>
                <span style={{ color: 'var(--fl-on-dark)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{promoteDialog.description || '-'}</span>
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button
                  onClick={() => setPromoteDialog(null)}
                  style={{ padding: '5px 14px', borderRadius: 5, border: '1px solid #1e2d45', background: 'transparent', color: '#6a8090', cursor: 'pointer', fontFamily: 'monospace', fontSize: 11 }}
                >
                  Annuler
                </button>
                <button
                  onClick={() => handlePromoteConfirm(promoteDialog)}
                  style={{
                    padding: '5px 14px', borderRadius: 5, border: 'none', cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, fontWeight: 700,
                    background: promoteDialog.is_global ? 'color-mix(in srgb, var(--fl-danger) 20%, var(--fl-bg))' : 'color-mix(in srgb, #f0b040 20%, var(--fl-bg))',
                    color: promoteDialog.is_global ? 'var(--fl-danger)' : '#f0b040',
                    border: `1px solid ${promoteDialog.is_global ? 'color-mix(in srgb, var(--fl-danger) 40%, transparent)' : 'color-mix(in srgb, #f0b040 40%, transparent)'}`,
                  }}
                >
                  {promoteDialog.is_global ? 'Retirer' : 'Partager'}
                </button>
              </div>
            </div>
          </div>
        )}

        
        {pinnedRows.size > 0 && (
          <div style={{ flexShrink: 0, borderBottom: '1px solid var(--fl-sep)', background: '#070d1a' }}>
            <button
              onClick={() => setPinsOpen(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                padding: '4px 10px', background: 'none', border: 'none', cursor: 'pointer',
                borderBottom: pinsOpen ? '1px solid var(--fl-sep)' : 'none',
              }}
            >
              {pinsOpen ? <ChevronDown size={10} style={{ color: 'var(--fl-accent)' }} /> : <ChevronRight size={10} style={{ color: 'var(--fl-accent)' }} />}
              <Pin size={10} style={{ color: 'var(--fl-accent)' }} />
              <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                Épinglés ({pinnedRows.size})
              </span>
              {[...pinnedRows.values()].some(p => p.is_global) && (
                <span style={{ marginLeft: 4, display: 'inline-flex', alignItems: 'center', gap: 2, fontSize: 9, color: '#f0b040' }}>
                  <Globe2 size={8} /> {[...pinnedRows.values()].filter(p => p.is_global).length} global
                </span>
              )}
            </button>
            {pinsOpen && (
              <div style={{ maxHeight: 160, overflow: 'auto' }}>
                {[...pinnedRows.values()].map(pin => (
                  <div key={pin.id} style={{
                    display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px 4px 24px',
                    borderBottom: '1px solid var(--fl-bg)', fontSize: 10, fontFamily: 'monospace',
                    borderLeft: pin.is_global ? '2px solid #f0b04060' : '2px solid transparent',
                  }}>
                    {pin.is_global
                      ? <Globe2 size={9} style={{ color: '#f0b040', flexShrink: 0 }} title={`Global — partagé par ${pin.promoted_by_name || 'un membre'}`} />
                      : <Pin size={9} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
                    }
                    <span style={{ color: ac(pin.artifact_type), flexShrink: 0 }}>{pin.artifact_type || '?'}</span>
                    <span style={{ color: '#7abfff', flexShrink: 0 }}>{pin.event_ts ? fmtTs(pin.event_ts) : '-'}</span>
                    <span style={{ color: 'var(--fl-on-dark)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pin.description || '-'}</span>
                    {pin.note && <span style={{ color: '#6a8090', fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>{pin.note}</span>}
                    <button
                      onClick={() => setPromoteDialog(pin)}
                      title={pin.is_global ? 'Retirer le partage global' : 'Partager avec tous les membres'}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 1, flexShrink: 0, display: 'flex', alignItems: 'center',
                        color: pin.is_global ? '#f0b040' : 'var(--fl-card)',
                      }}
                    >
                      <Globe2 size={9} />
                    </button>
                    <button
                      onClick={() => handlePin({ timestamp: pin.event_ts, source: pin.source, artifact_type: pin.artifact_type })}
                      title="Désépingler"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-danger)', display: 'flex', alignItems: 'center', padding: 0, flexShrink: 0 }}
                    >
                      <PinOff size={9} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

      <PanelGroup direction="horizontal" style={{ flex: 1 }}>


        <Panel defaultSize={65} minSize={30} style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          
          <div style={{
            flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6,
            padding: '3px 10px', background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-bg)',
          }}>
            <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
              {t('workbench.gaps_label')} :
            </span>
            {gapThresholds.map(thresh => (
              <button
                key={thresh.ms}
                onClick={() => setGapThresholdMs(thresh.ms)}
                style={{
                  padding: '1px 7px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                  cursor: 'pointer', border: 'none',
                  background: gapThresholdMs === thresh.ms
                    ? (thresh.ms ? 'color-mix(in srgb, var(--fl-danger) 10%, var(--fl-bg))' : 'color-mix(in srgb, var(--fl-accent) 10%, var(--fl-bg))')
                    : 'transparent',
                  color: gapThresholdMs === thresh.ms ? (thresh.ms ? 'var(--fl-danger)' : 'var(--fl-accent)') : 'var(--fl-muted)',
                  outline: gapThresholdMs === thresh.ms
                    ? `1px solid ${thresh.ms ? 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 20%, transparent)'}`
                    : 'none',
                }}
              >
                {thresh.label}
              </button>
            ))}
            
            <div style={{ marginLeft: 'auto' }}>
              <button onClick={() => setShowPlayback(v => !v)}
                title="Lecture chronologique (W-4)"
                style={{
                  padding: '1px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                  cursor: 'pointer', border: `1px solid ${showPlayback ? '#4d82c030' : 'var(--fl-bg)'}`,
                  background: showPlayback ? 'rgba(77,130,192,0.15)' : 'transparent',
                  color: showPlayback ? 'var(--fl-accent)' : '#2a5a8a',
                }}>▶ Lecture</button>
            </div>
          </div>
          
          {processFilter && (
            <div style={{
              flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8,
              padding: '3px 10px', background: 'rgba(34,197,94,0.08)',
              borderBottom: '1px solid rgba(34,197,94,0.2)',
            }}>
              <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#22c55e' }}>
                🔗 Suivre: <strong>{processFilter}</strong> — {filteredRecords.length} événements
              </span>
              <button onClick={() => setProcessFilter(null)}
                style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: '#22c55e', background: 'none', border: 'none', cursor: 'pointer' }}>
                ✕ Effacer
              </button>
            </div>
          )}
          
          {quickFilter && (
            <div style={{
              flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8,
              padding: '3px 10px', background: 'rgba(249,115,22,0.08)',
              borderBottom: '1px solid rgba(249,115,22,0.2)',
            }}>
              <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#f97316' }}>
                🔍 Filtre <strong>{quickFilter.field}</strong>: <strong>{quickFilter.value}</strong> — {filteredRecords.length} événements
              </span>
              <button onClick={() => setQuickFilter(null)}
                style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: '#f97316', background: 'none', border: 'none', cursor: 'pointer' }}>
                ✕ Effacer
              </button>
            </div>
          )}
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <ArtifactGrid
              records={filteredRecords}
              selectedRecord={playbackHighlight || selectedRecord}
              onSelect={handleSelect}
              notedRefs={notedRefs}
              gapThresholdMs={gapThresholdMs}
              onPin={handlePin}
              isPinned={isPinned}
              artifactType={singleType}
              pinnedRows={pinnedRows}
              verdictMap={verdictMap}
              caseId={caseId}
              onVerdictChange={handleVerdictChange}
              onFollowProcess={p => setProcessFilter(p)}
              onFilterRow={(field, val) => {
                if (field === 'type') onFilterTimeline?.(val);
                else if (field === 'host' || field === 'user') setQuickFilter({ field, value: val });
              }}
            />
          </div>
          
          {showPlayback && (
            <TimelinePlayback
              records={filteredRecords}
              onHighlight={(r) => { setPlaybackHighlight(r); handleSelect(r); }}
              onStop={() => setPlaybackHighlight(null)}
            />
          )}
        </Panel>

        <ResizeHandle />

        
        <Panel defaultSize={35} minSize={20} style={{ overflow: 'hidden' }}>
          <ArtifactInspector
            record={selectedRecord}
            allRecords={filteredRecords}
            caseId={caseId}
            onNotedRefsChange={loadNotedRefs}
            onFilterTimeline={onFilterTimeline}
          />
        </Panel>

      </PanelGroup>
      </div>
      )}

    </div>
  );
}

function QuickFilterBar({ records, availTypes, quickFilter, processFilter, onFilter, onClearProcess, onClearAll }) {
  const hosts   = useMemo(() => [...new Set((records || []).map(r => r.host_name).filter(Boolean))].sort(), [records]);
  const users   = useMemo(() => [...new Set((records || []).map(r => r.user_name).filter(Boolean))].sort(), [records]);
  const sevs    = ['critical', 'high', 'medium', 'low'];
  const SEV_COLOR = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };

  const isActive = quickFilter || processFilter;

  return (
    <div style={{
      flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'nowrap',
      padding: '4px 10px', background: '#04070e', borderBottom: '1px solid var(--fl-bg)',
      overflowX: 'auto',
    }}>
      
      <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', whiteSpace: 'nowrap' }}>SÉVÉRITÉ</span>
      {sevs.map(s => {
        const active = quickFilter?.field === 'hay_severity' && quickFilter.value === s;
        return (
          <button key={s} onClick={() => onFilter('hay_severity', active ? null : s)}
            style={{
              padding: '1px 7px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', whiteSpace: 'nowrap',
              cursor: 'pointer', fontWeight: active ? 700 : 400,
              background: active ? `${SEV_COLOR[s]}22` : 'transparent',
              border: `1px solid ${active ? SEV_COLOR[s] : 'var(--fl-bg)'}`,
              color: active ? SEV_COLOR[s] : '#2a5a8a',
            }}>
            {s}
          </button>
        );
      })}

      <div style={{ width: 1, height: 14, background: 'var(--fl-bg)', flexShrink: 0 }} />

      
      {hosts.length > 0 && (
        <>
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', whiteSpace: 'nowrap' }}>HÔTE</span>
          <select
            value={quickFilter?.field === 'host' ? quickFilter.value : ''}
            onChange={e => onFilter('host', e.target.value || null)}
            style={{
              background: quickFilter?.field === 'host' ? 'rgba(77,130,192,0.12)' : '#04070e',
              border: `1px solid ${quickFilter?.field === 'host' ? '#4d82c060' : 'var(--fl-bg)'}`,
              borderRadius: 3, color: quickFilter?.field === 'host' ? '#7abfff' : '#3a6a9a',
              fontSize: 9, fontFamily: 'monospace', padding: '1px 4px', cursor: 'pointer',
              maxWidth: 130,
            }}>
            <option value="">Tous les hôtes</option>
            {hosts.map(h => <option key={h} value={h}>{h}</option>)}
          </select>
        </>
      )}

      
      {users.length > 0 && (
        <>
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', whiteSpace: 'nowrap' }}>USER</span>
          <select
            value={quickFilter?.field === 'user' ? quickFilter.value : ''}
            onChange={e => onFilter('user', e.target.value || null)}
            style={{
              background: quickFilter?.field === 'user' ? 'rgba(77,130,192,0.12)' : '#04070e',
              border: `1px solid ${quickFilter?.field === 'user' ? '#4d82c060' : 'var(--fl-bg)'}`,
              borderRadius: 3, color: quickFilter?.field === 'user' ? '#7abfff' : '#3a6a9a',
              fontSize: 9, fontFamily: 'monospace', padding: '1px 4px', cursor: 'pointer',
              maxWidth: 130,
            }}>
            <option value="">Tous les utilisateurs</option>
            {users.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
        </>
      )}

      
      {availTypes?.length > 0 && (
        <>
          <div style={{ width: 1, height: 14, background: 'var(--fl-bg)', flexShrink: 0 }} />
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', whiteSpace: 'nowrap' }}>TYPE</span>
          <select
            defaultValue=""
            onChange={e => { if (e.target.value) onFilter('type', e.target.value); e.target.value = ''; }}
            style={{
              background: '#04070e', border: '1px solid var(--fl-bg)',
              borderRadius: 3, color: '#3a6a9a',
              fontSize: 9, fontFamily: 'monospace', padding: '1px 4px', cursor: 'pointer',
              maxWidth: 140,
            }}>
            <option value="">Filtrer par type…</option>
            {availTypes.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </>
      )}

      
      {isActive && (
        <>
          <div style={{ width: 1, height: 14, background: 'var(--fl-bg)', flexShrink: 0 }} />
          <button onClick={onClearAll}
            style={{
              padding: '1px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              color: 'var(--fl-danger)', cursor: 'pointer', whiteSpace: 'nowrap',
            }}>
            ✕ Réinitialiser filtres
          </button>
        </>
      )}
    </div>
  );
}

function ActionMenuSection({ title, icon, children }) {
  return (
    <div style={{ padding: '0 0 8px' }}>
      <div style={{ padding: '2px 14px 6px', fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        {icon} {title}
      </div>
      {children}
    </div>
  );
}

function ActionMenuItem({ icon, label, onClick, danger }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '5px 14px', cursor: 'pointer',
        background: hov ? (danger ? 'rgba(239,68,68,0.08)' : '#0d1f35') : 'transparent',
        borderLeft: `2px solid ${hov ? (danger ? 'var(--fl-danger)' : 'var(--fl-accent)') : 'transparent'}`,
      }}>
      <span style={{ fontSize: 11, flexShrink: 0 }}>{icon}</span>
      <span style={{ fontFamily: 'monospace', fontSize: 10, color: danger ? 'var(--fl-danger)' : (hov ? 'var(--fl-on-dark)' : '#7abfff'), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </span>
    </div>
  );
}
