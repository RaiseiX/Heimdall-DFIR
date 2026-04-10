
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
import { SortAsc, SortDesc, Copy, CheckCheck, Clock, FileText, HardDrive, Tag, MessageSquare, Send, Trash2, Pencil, ShieldAlert, Eye, AlertTriangle, ChevronDown, ChevronRight, Share2, Pin, PinOff, Globe2, X, Bot, Star, CheckSquare, Square, Cpu } from 'lucide-react';
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
import { fmtTs } from '../../utils/formatters';

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

  { test: s => /\.(exe|dll|bat|ps1|sh|py|cmd|vbs|js)(\s|$|:)/i.test(s) || /^(Image|Process|CommandLine|ParentImage):/i.test(s), color: '#c792ea', bg: '#c792ea18' },

  { test: s => /[A-Za-z]:\\|\/home\/|\/etc\/|\/var\/|\/tmp\/|%\w+%/i.test(s) || /^(Path|File|Dir|TargetFilename|ObjectName):/i.test(s), color: '#4d82c0', bg: '#4d82c018' },

  { test: s => /^(User|Username|SubjectUserName|TargetUserName|Account):/i.test(s), color: '#d4a44c', bg: '#d4a44c18' },

  { test: s => /^(PID|ProcessId|ParentProcessId|ppid):/i.test(s) || /\bpid\s*[:=]\s*\d+/i.test(s), color: '#8b72d6', bg: '#8b72d618' },

  { test: s => /\b\d{1,3}(\.\d{1,3}){3}\b/.test(s) || /^(IP|DestinationIp|SourceIp|dst|src):/i.test(s), color: '#3fb950', bg: '#3fb95018' },

  { test: s => /^(MD5|SHA1|SHA256|Hash|Hashes):/i.test(s) || /\b[0-9a-f]{32,64}\b/i.test(s), color: '#58a6ff', bg: '#58a6ff18' },

  { test: s => /^(Key|Registry|TargetObject|HKLM|HKCU|HKU)/i.test(s), color: '#d97c20', bg: '#d97c2018' },

  { test: s => /^(Port|DestinationPort|SourcePort|dst_port|src_port):/i.test(s), color: '#79c0ff', bg: '#79c0ff18' },
];

function chipColor(segment) {
  for (const rule of DESC_CHIP_RULES) {
    if (rule.test(segment)) return { color: rule.color, bg: rule.bg };
  }
  return { color: '#5a7a9a', bg: '#5a7a9a12' };
}

function DescriptionCell({ value }) {
  if (!value || value === '-') return <span style={{ color: '#2a3a50' }}>—</span>;

  const parts = value.split(/\s*\|\s*/);
  if (parts.length === 1) {

    return (
      <span title={value} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#c0cce0' }}>
        {value}
      </span>
    );
  }

  const [main, ...chips] = parts;
  const tooltip = parts.join('\n');

  return (
    <span title={tooltip} style={{ display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', minWidth: 0 }}>
      
      <span style={{
        color: '#e2eaf5', fontWeight: 600, flexShrink: 0,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        maxWidth: '35%',
      }}>
        {main.trim()}
      </span>
      
      {chips.map((chip, i) => {
        const { color, bg } = chipColor(chip.trim());
        return (
          <span key={i} style={{
            flexShrink: 0, display: 'inline-block',
            padding: '0px 5px', borderRadius: 3,
            fontSize: 10, fontFamily: 'monospace',
            background: bg, color, border: `1px solid ${color}30`,
            whiteSpace: 'nowrap', maxWidth: 160,
            overflow: 'hidden', textOverflow: 'ellipsis',
          }}>
            {chip.trim()}
          </span>
        );
      })}
    </span>
  );
}

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
  { key: 'critical', label: 'Malveillant', color: '#ef4444', dot: '●' },
  { key: 'high',     label: 'Suspect',     color: '#d97c20', dot: '●' },
  { key: 'medium',   label: 'Ambigu',      color: '#c89d1d', dot: '●' },
  { key: 'low',      label: 'Bénin',       color: '#22c55e', dot: '●' },
];
const WB_TAGS = [
  { key: 'exec',            label: 'Exécution',       color: '#d97c20' },
  { key: 'persist',         label: 'Persistance',     color: '#8b72d6' },
  { key: 'lateral',         label: 'Mvt latéral',     color: '#22c55e' },
  { key: 'exfil',           label: 'Exfiltration',    color: '#ef4444' },
  { key: 'c2',              label: 'C2',               color: '#f43f5e' },
  { key: 'recon',           label: 'Reconnaissance',  color: '#06b6d4' },
  { key: 'privesc',         label: 'Privesc',          color: '#f59e0b' },
  { key: 'defense_evasion', label: 'Évasion défense', color: '#64748b' },
  { key: 'credential',      label: 'Credentials',     color: '#c96898' },
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
        background: '#0d1525', border: '1px solid #1a2a40', borderRadius: 6,
        boxShadow: '0 8px 32px #00000080', padding: '8px 10px', width: 210,
        fontFamily: 'monospace',
      }}
      onClick={e => e.stopPropagation()}
    >
      
      <div style={{ fontSize: 8, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Niveau</div>
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
      
      <div style={{ fontSize: 8, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Tags</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {WB_TAGS.map(t => {
          const active = tags.includes(t.key);
          return (
            <button key={t.key} onClick={() => onChange({ ...current, tags: active ? tags.filter(k => k !== t.key) : [...tags, t.key] })}
              style={{
                padding: '2px 6px', borderRadius: 8, fontSize: 9, cursor: 'pointer', fontWeight: 600,
                background: active ? `${t.color}30` : 'rgba(255,255,255,0.05)',
                color: active ? t.color : '#7d8590',
                border: `1px solid ${active ? t.color + '60' : 'rgba(255,255,255,0.1)'}`,
              }}>
              {t.label}
            </button>
          );
        })}
      </div>
      
      <button onClick={() => { onChange({ level: null, tags: [] }); onClose(); }}
        style={{ marginTop: 7, background: 'none', border: 'none', cursor: 'pointer', fontSize: 9, color: '#3d5070', padding: 0 }}>
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
          if (val === null || val === undefined || val === '') return <span style={{ color: '#2a3a50' }}>—</span>;
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
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#0d1117' }}>
      
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
              <tr key={hg.id} style={{ background: '#07101f' }}>
                
                <th
                  onClick={() => {
                    const allIds = new Set(tableRows.map(r => r.id));
                    setSelectedRows(prev => prev.size === tableRows.length ? new Set() : allIds);
                  }}
                  style={{ width: 24, padding: '6px 4px', borderBottom: '2px solid #1a2035', background: '#07101f', textAlign: 'center', cursor: 'pointer' }}
                  title="Tout sélectionner"
                >
                  {selectedRows.size > 0 && selectedRows.size === tableRows.length
                    ? <CheckSquare size={11} style={{ color: '#4d82c0' }} />
                    : <Square size={11} style={{ color: selectedRows.size > 0 ? '#4d82c060' : '#30363d' }} />
                  }
                </th>
                
                <th style={{ width: 22, padding: '6px 4px', borderBottom: '2px solid #1a2035', background: '#07101f', textAlign: 'center' }} title="Signets">
                  <Star size={10} style={{ color: '#30363d' }} />
                </th>
                
                <th style={{ width: 20, padding: '6px 4px', borderBottom: '2px solid #1a2035', background: '#07101f', textAlign: 'center' }} title="Épingles">
                  <Pin size={10} style={{ color: '#30363d' }} />
                </th>
                
                <th style={{ width: 30, padding: '6px 4px', borderBottom: '2px solid #1a2035', background: '#07101f', textAlign: 'center' }} title="Tags forensiques">
                  <Tag size={10} style={{ color: '#30363d' }} />
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
                        background: '#07101f',
                        borderRight: pinned ? '1px solid #1a2035' : undefined,
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
                      ? <CheckSquare size={11} style={{ color: '#4d82c0' }} />
                      : <Square size={11} style={{ color: isHovered ? '#3d5070' : '#1e2535' }} />
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
                      style={{ color: bookmarkedRows.has(row.id) ? '#f59e0b' : (isHovered ? '#3d5070' : '#1e2535') }}
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
                          : <Pin size={11} fill="#d97c20" style={{ color: '#d97c20' }} />;
                      }
                      return (
                        <Pin
                          size={11}
                          fill="none"
                          style={{ color: isHovered ? '#3d5070' : '#1e2535' }}
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
                      if (td.tags?.length > 0) return <Tag size={11} style={{ color: '#3d5070' }} />;
                      return <span style={{ fontSize: 11, color: isHovered ? '#2a3a50' : '#111827' }}>○</span>;
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
                          color: mono ? '#7a9abf' : '#c0cce0',
                          position:   pinned ? 'sticky' : undefined,
                          left:       pinned ? 0 : undefined,
                          zIndex:     pinned ? 5 : undefined,
                          background: pinned ? rowBg : undefined,
                          borderRight: pinned ? '1px solid #1a2035' : undefined,
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
        background: '#07101f',
        borderTop: '1px solid #1a2035',
        fontFamily: 'monospace',
        fontSize: 10,
        color: '#2a3a50',
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
          <span style={{ color: '#3d5070', marginLeft: 'auto' }}>
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
          background: 'none', border: '1px solid #1a2a3a', borderRadius: 3,
          cursor: 'pointer', padding: '1px 6px', fontSize: 9, fontFamily: 'monospace',
          color: '#4d82c0', display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0,
        }}
      >
        ⤢ Pivot
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', zIndex: 100, marginTop: 2,
          background: '#07101f', border: '1px solid #2a3a50', borderRadius: 6,
          padding: '4px 0', minWidth: 180, boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
        }}>
          {onFilterTimeline && (
            <button
              onClick={() => { onFilterTimeline(value); setOpen(false); }}
              style={{
                display: 'block', width: '100%', textAlign: 'left',
                padding: '5px 12px', fontSize: 10, fontFamily: 'monospace',
                background: 'none', border: 'none', cursor: 'pointer', color: '#c0cce0',
              }}
              onMouseEnter={e => e.currentTarget.style.background = '#1a2a3a'}
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
                background: 'none', border: 'none', cursor: 'pointer', color: '#c0cce0',
              }}
              onMouseEnter={e => e.currentTarget.style.background = '#1a2a3a'}
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

function ArtifactInspector({ record, caseId, onNotedRefsChange, onFilterTimeline }) {
  const { t } = useTranslation();
  const [copied, setCopied]         = useState(false);
  const [inspectorTab, setTab]      = useState('details');
  const [notes, setNotes]           = useState([]);
  const [noteText, setNoteText]     = useState('');
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteEditId, setNoteEditId] = useState(null);
  const [noteEditText, setNoteEditText] = useState('');

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
        <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#2a3a50' }}>
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
          
          {['details', 'notes'].map(tab => (
            <button key={tab} onClick={() => setTab(tab)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: '6px 12px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
              fontWeight: inspectorTab === tab ? 600 : 400,
              color: inspectorTab === tab ? 'var(--fl-accent)' : 'var(--fl-muted)',
              borderBottom: inspectorTab === tab ? '2px solid var(--fl-accent)' : '2px solid transparent',
            }}>
              {tab === 'details' ? t('workbench.details') : (
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <MessageSquare size={10} />
                  {t('notes.tab')} {notes.length > 0 && `(${notes.length})`}
                </span>
              )}
            </button>
          ))}
          
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
            ? `http:
            : 'http://localhost:8888';
          return (
            <button
              onClick={() => window.open(url, '_blank')}
              style={{
                flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
                marginLeft: 4, background: 'rgba(139,114,214,0.12)',
                border: '1px solid rgba(139,114,214,0.35)',
                borderRadius: 4, cursor: 'pointer', padding: '2px 8px',
                fontSize: 10, fontFamily: 'monospace', color: '#8b72d6',
              }}
              title={pid ? `Ouvrir VolWeb — PID ${pid}` : 'Ouvrir VolWeb'}
            >
              ↗ VolWeb{pid ? ` (PID ${pid})` : ''}
            </button>
          );
        })()}
        
        <button onClick={copyJson} style={{
          flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
          marginLeft: 8, background: 'none', border: '1px solid #1a2035',
          borderRadius: 4, cursor: 'pointer', padding: '2px 8px',
          fontSize: 10, fontFamily: 'monospace',
          color: copied ? '#3fb950' : '#3d5070', transition: 'color 0.15s',
        }}>
          {copied ? <CheckCheck size={11} /> : <Copy size={11} />}
          {copied ? t('timeline.copy_success') : t('workbench.copy')}
        </button>
      </div>

      
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
                        {n.author_name || n.author_username} · {new Date(n.created_at).toLocaleString()}
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
          borderBottom: '1px solid #0d1525',
          display: 'flex', flexDirection: 'column', gap: 5,
        }}>
          
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
              <Clock size={10} /> {t('workbench.timestamp_label')}
            </span>
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#7abfff', fontWeight: 600, lineHeight: 1.4 }}>
              {fmtTs(record.timestamp)}
              {record.timestamp_column && (
                <span style={{ marginLeft: 8, fontSize: 9, padding: '1px 5px', borderRadius: 3, background: '#1a2035', color: '#4d6080', fontWeight: 400 }}>
                  {record.timestamp_column}
                </span>
              )}
            </span>
          </div>

          
          {(record.host_name || record.source_device) && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
                <HardDrive size={10} /> Hôte
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#22c55e', fontWeight: 600 }}>
                {record.host_name || record.source_device}
              </span>
            </div>
          )}

          
          {record.user_name && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
                <Eye size={10} /> Utilisateur
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#c89d1d', fontWeight: 600 }}>
                {record.user_name}
              </span>
            </div>
          )}

          
          {record.process_name && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
                <Cpu size={10} /> Processus
              </span>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#d97c20', fontWeight: 600, wordBreak: 'break-all' }}>
                {record.process_name}
              </span>
            </div>
          )}

          
          {record.mitre_technique_id && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
                <ShieldAlert size={10} /> MITRE
              </span>
              <MitreBadge id={record.mitre_technique_id} name={record.mitre_technique_name} />
            </div>
          )}

          
          {record.description && (
            <div style={{
              padding: '6px 8px', borderRadius: 5,
              background: `${color}08`, border: `1px solid ${color}20`,
              fontSize: 11, color: '#c0cce0', lineHeight: 1.55, wordBreak: 'break-word',
            }}>
              {record.description}
            </div>
          )}

          
          {record.source && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, width: 80, flexShrink: 0, fontSize: 10, color: '#3d5070', fontFamily: 'monospace', paddingTop: 1 }}>
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
                color: '#2a3a50', letterSpacing: '0.08em', textTransform: 'uppercase',
                background: '#05080f', borderBottom: '1px solid #0d1525',
                display: 'flex', alignItems: 'center', gap: 5,
              }}>
                <Tag size={9} />
                {t('workbench.raw_csv')} — {rawFields.length}
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <tbody>
                  {rawFields.map(([key, val]) => {
                    const strVal = String(val);
                    const isIP   = /^\d{1,3}(\.\d{1,3}){3}$/.test(strVal);
                    const isHash = /^[0-9a-fA-F]{32,}$/.test(strVal);
                    const isURL  = /^https?:\/\//.test(strVal);
                    const isPivotable = isIP || isHash || isURL;
                    return (
                      <tr key={key} style={{ borderBottom: '1px solid #090e1a' }}>
                        <td style={{
                          padding: '3px 12px 3px 12px',
                          fontFamily: 'monospace', color: '#3d6080',
                          whiteSpace: 'nowrap', verticalAlign: 'top',
                          width: '35%', maxWidth: 160, userSelect: 'none',
                        }}>
                          {key}
                        </td>
                        <td style={{
                          padding: '3px 12px 3px 6px',
                          fontFamily: 'monospace', color: '#a0b8d0',
                          wordBreak: 'break-all', lineHeight: 1.45,
                        }}>
                          <span style={{ display: 'flex', alignItems: 'flex-start', gap: 6, flexWrap: 'wrap' }}>
                            <span style={{ flex: 1, wordBreak: 'break-all' }}>{strVal}</span>
                            {isPivotable && (
                              <PivotButton value={strVal} isIP={isIP} caseId={caseId} onFilterTimeline={onFilterTimeline} />
                            )}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          ) : (
            <div style={{ padding: '8px 12px' }}>
              <div style={{
                fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#2a3a50',
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
      background: '#8b72d615', color: '#8b72d6', border: '1px solid #8b72d630',
      whiteSpace: 'nowrap', flexShrink: 0,
    }} title={name || id}>
      {id}
    </span>
  );
}

const SEV_COLORS = {
  critical: { bg: '#da363318', color: '#da3633', border: '#da363340' },
  high:     { bg: '#d97c2014', color: '#d97c20', border: '#d97c2035' },
  medium:   { bg: '#c89d1d12', color: '#c89d1d', border: '#c89d1d30' },
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
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#3d5070' }}>
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
    'Registry RunKey': '#c96898', registry: '#c96898',
    lnk: '#d97c20', bits: '#64748b', prefetch: '#22c55e',
    jumplist: '#8b5cf6', amcache: '#c89d1d',
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 5 }}>
        <ShieldAlert size={10} />
        {findings.length} {findings.length !== 1 ? t('workbench.persistence_items_pl') : t('workbench.persistence_items')} — {Object.keys(byVector).length} {Object.keys(byVector).length !== 1 ? t('workbench.vectors_pl') : t('workbench.vectors')}
      </div>
      {Object.entries(byVector).map(([vector, items]) => {
        const isOpen = !collapsed[vector];
        const col = VECTOR_COLORS[vector] || '#4d82c0';
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
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3d5070' }}>
                {items.length} {items.length !== 1 ? t('workbench.artifacts_pl') : t('workbench.artifacts')}
              </span>
              <MitreBadge id={mitre_id} name={mitre_name} />
            </button>
            
            {isOpen && items.map((item, i) => (
              <div key={i} style={{
                padding: '5px 12px 5px 26px', borderBottom: i < items.length - 1 ? `1px solid ${col}12` : 'none',
                display: 'flex', flexDirection: 'column', gap: 2,
              }}>
                <span style={{ fontSize: 11, color: '#c0cce0', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {item.description || item.value || item.name || item.source || JSON.stringify(item).slice(0, 120)}
                </span>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                  {item.timestamp && (
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d6080' }}>
                      {fmtTs(item.timestamp)}
                    </span>
                  )}
                  {item.source && item.source !== (item.description || '') && (
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
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
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#3d5070' }}>
        {t('workbench.no_evasion')}
      </span>
    </div>
  );

  function ArtifactRow({ item, type, label, color }) {
    return (
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 12px',
        borderBottom: '1px solid #0d1525', flexWrap: 'wrap',
      }}>
        <SeverityBadge level={item.severity || (type === 'timestomping' ? 'high' : type === 'double_ext' ? 'medium' : 'low')} />
        <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3,
          background: `${color}15`, color, border: `1px solid ${color}30`, flexShrink: 0 }}>
          {label}
        </span>
        <span style={{ fontSize: 11, color: '#c0cce0', fontFamily: 'monospace', flex: 1, wordBreak: 'break-all', minWidth: 0 }}>
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
        flexShrink: 0, padding: '6px 12px', background: '#07101f', borderBottom: '1px solid #0d1525',
        fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#3d5070',
        textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', gap: 10, alignItems: 'center',
      }}>
        <Eye size={10} />
        {total} {total !== 1 ? t('workbench.evasion_items_pl') : t('workbench.evasion_items')}
        {tsFindings.length > 0 && <span style={{ color: '#d97c20' }}>Timestomping ×{tsFindings.length}</span>}
        {dextFindings.length > 0 && <span style={{ color: '#da3633' }}>Double ext. ×{dextFindings.length}</span>}
        {mftAnomalies.length > 0 && <span style={{ color: '#8b72d6' }}>{t('workbench.mft_anomalies')} ×{mftAnomalies.length}</span>}
      </div>
      
      {tsFindings.map((item, i) => <ArtifactRow key={`ts-${i}`} item={item} type="timestomping" label="Timestomping" color="#d97c20" />)}
      
      {dextFindings.map((item, i) => <ArtifactRow key={`dx-${i}`} item={item} type="double_ext" label="Double extension" color="#da3633" />)}
      
      {mftAnomalies.map((item, i) => (
        <ArtifactRow key={`mft-${i}`} item={{ ...item, description: `${item.raw?.['FileName'] || item.source} — ${t('workbench.mft_desc', { sia: item.raw?.['Created0x10'], fn: item.raw?.['Created0x30'] })}` }}
          type="mft_anomaly" label={t('workbench.mft_anomaly')} color="#8b72d6" />
      ))}
    </div>
  );
}

function ResizeHandle() {
  return (
    <PanelResizeHandle style={{ height: 6, background: '#0d1117', cursor: 'row-resize', position: 'relative', flexShrink: 0 }}>
      <div style={{
        position: 'absolute',
        left: '50%', top: '50%',
        transform: 'translate(-50%, -50%)',
        width: 36, height: 3,
        borderRadius: 2,
        background: '#1a2035',
        pointerEvents: 'none',
      }} />
    </PanelResizeHandle>
  );
}


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
    <div style={{ height: '100%', overflow: 'hidden', display: 'flex', flexDirection: 'column', background: '#060b14' }}>

      
      <div style={{
        flexShrink: 0,
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '6px 14px',
        background: 'linear-gradient(90deg, #06111f 0%, #091624 60%, #060b14 100%)',
        borderBottom: '2px solid #1a3a5c',
        boxShadow: '0 1px 12px rgba(77,130,192,0.12)',
      }}>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{
            display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
            background: '#4d82c0',
            boxShadow: '0 0 6px #4d82c0',
            animation: 'wbPulse 2s ease-in-out infinite',
          }} />
          <style>{`@keyframes wbPulse { 0%,100%{opacity:1;box-shadow:0 0 6px #4d82c0} 50%{opacity:.5;box-shadow:0 0 12px #4d82c0} }`}</style>
          <span style={{
            fontSize: 9, fontFamily: 'monospace', fontWeight: 800,
            textTransform: 'uppercase', letterSpacing: '0.12em',
            color: '#4d82c0',
          }}>
            Mode Investigation
          </span>
        </div>

        
        <div style={{ width: 1, height: 14, background: '#1a3a5c' }} />

        
        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3a6a9a' }}>
          <span style={{ color: '#7abfff', fontWeight: 700 }}>{filteredRecords?.length?.toLocaleString() ?? 0}</span>
          {processFilter
            ? <span style={{ color: '#22c55e' }}> filtrés</span>
            : total > 0 ? <> / {total.toLocaleString()} événements</> : null
          }
        </span>

        
        {total > 2000 && totalPages > 1 && onPageChange && (
          <>
            <div style={{ width: 1, height: 14, background: '#1a3a5c' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <button
                onClick={() => onPageChange(page - 1)}
                disabled={page <= 1}
                style={{
                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                  background: 'transparent', border: '1px solid #1a3a5c',
                  color: page <= 1 ? '#1a3a5c' : '#4d82c0', cursor: page <= 1 ? 'default' : 'pointer',
                }}>‹</button>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3a6a9a' }}>
                {page} / {totalPages}
              </span>
              <button
                onClick={() => onPageChange(page + 1)}
                disabled={page >= totalPages}
                style={{
                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                  background: 'transparent', border: '1px solid #1a3a5c',
                  color: page >= totalPages ? '#1a3a5c' : '#4d82c0', cursor: page >= totalPages ? 'default' : 'pointer',
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
              border: `1px solid ${showActionsMenu ? '#4d82c060' : '#1a3a5c'}`,
              color: showActionsMenu ? '#7abfff' : '#4d82c0',
              cursor: 'pointer', fontWeight: 600,
            }}
          >
            ⚡ Actions <ChevronDown size={9} style={{ transform: showActionsMenu ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
          </button>
          {showActionsMenu && (
            <div style={{
              position: 'absolute', top: '100%', right: 0, marginTop: 4,
              zIndex: 9000, background: '#0a1520', border: '1px solid #1a3a5c',
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
                <div style={{ borderTop: '1px solid #0d1f30', margin: '6px 0 0', padding: '8px 14px 2px' }}>
                  <div style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
                    🏷 Filtrer par type d'artefact
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {availTypes.map(t => (
                      <button key={t} onClick={() => { handlePaletteCommand(`type:${t}`); setShowActionsMenu(false); }}
                        style={{
                          padding: '2px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                          background: 'rgba(77,130,192,0.08)', border: '1px solid #1a3a5c',
                          color: '#7abfff', cursor: 'pointer',
                        }}>
                        {t}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ padding: '8px 14px 2px', borderTop: '1px solid #0d1f30', marginTop: 6 }}>
                <div style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', marginTop: 2 }}>
                  Astuce : <kbd style={{ border: '1px solid #1a3a5c', borderRadius: 2, padding: '0 4px', fontSize: 8, color: '#2a5a8a' }}>Ctrl+K</kbd> pour la palette complète avec recherche
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
            background: 'transparent', border: '1px solid #0d1f30',
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
              background: 'transparent', border: '1px solid #1a3a5c',
              color: '#3a6a9a', cursor: 'pointer',
              transition: 'all 0.1s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#7abfff'; e.currentTarget.style.borderColor = '#4d82c060'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#3a6a9a'; e.currentTarget.style.borderColor = '#1a3a5c'; }}
          >
            <X size={9} /> Quitter
          </button>
        )}
      </div>

      
      <div style={{
        flexShrink: 0, display: 'flex', alignItems: 'center', gap: 2,
        padding: '3px 10px', background: '#05080f', borderBottom: '1px solid #0d1525',
      }}>
        {workbenchTabs.map(tab => {
          const Icon   = tab.icon;
          const active = activeTab === tab.id;
          const color  = tab.id === 'persistence'
            ? '#c96898'
            : tab.id === 'dissimulation'
            ? '#d97c20'
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
        <div style={{ flex: 1, overflow: 'auto', background: '#060b14' }}>
          <TimelineHeatmap caseId={caseId} availTypes={availTypes} />
        </div>
      )}

      
      {activeTab === 'gantt' && (
        <div style={{ flex: 1, overflow: 'hidden', background: '#060b14' }}>
          <GanttView records={filteredRecords} onSelectRecord={r => handleSelect(r)} />
        </div>
      )}

      
      {activeTab === 'mitre' && (
        <div style={{ flex: 1, overflow: 'auto', background: '#060b14' }}>
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
                background: '#0d1525', border: '1px solid #1e2d45', borderRadius: 10,
                padding: '20px 24px', width: 360, boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <Globe2 size={16} style={{ color: promoteDialog.is_global ? 'var(--fl-danger)' : '#f0b040' }} />
                <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#c0cce0', fontSize: 13 }}>
                  {promoteDialog.is_global ? 'Retirer le pin global' : 'Partager ce pin avec tous'}
                </span>
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#6a8090', marginBottom: 16, lineHeight: 1.5 }}>
                {promoteDialog.is_global
                  ? 'Ce pin ne sera plus visible par les autres membres du cas.'
                  : 'Tous les membres du cas pourront voir ce pin dans leur Workbench.'}
              </div>
              <div style={{ display: 'flex', gap: 6, fontSize: 10, fontFamily: 'monospace', color: '#4d82c0', marginBottom: 14 }}>
                <span style={{ color: ac(promoteDialog.artifact_type), flexShrink: 0 }}>[{promoteDialog.artifact_type || '?'}]</span>
                <span style={{ color: '#7abfff', flexShrink: 0 }}>{promoteDialog.event_ts ? fmtTs(promoteDialog.event_ts) : '-'}</span>
                <span style={{ color: '#c0cce0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{promoteDialog.description || '-'}</span>
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
                    background: promoteDialog.is_global ? 'color-mix(in srgb, var(--fl-danger) 20%, #0d1525)' : 'color-mix(in srgb, #f0b040 20%, #0d1525)',
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
          <div style={{ flexShrink: 0, borderBottom: '1px solid #1a2035', background: '#070d1a' }}>
            <button
              onClick={() => setPinsOpen(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                padding: '4px 10px', background: 'none', border: 'none', cursor: 'pointer',
                borderBottom: pinsOpen ? '1px solid #1a2035' : 'none',
              }}
            >
              {pinsOpen ? <ChevronDown size={10} style={{ color: '#4d82c0' }} /> : <ChevronRight size={10} style={{ color: '#4d82c0' }} />}
              <Pin size={10} style={{ color: '#4d82c0' }} />
              <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#4d82c0', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
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
                    borderBottom: '1px solid #0d1525', fontSize: 10, fontFamily: 'monospace',
                    borderLeft: pin.is_global ? '2px solid #f0b04060' : '2px solid transparent',
                  }}>
                    {pin.is_global
                      ? <Globe2 size={9} style={{ color: '#f0b040', flexShrink: 0 }} title={`Global — partagé par ${pin.promoted_by_name || 'un membre'}`} />
                      : <Pin size={9} style={{ color: '#4d82c0', flexShrink: 0 }} />
                    }
                    <span style={{ color: ac(pin.artifact_type), flexShrink: 0 }}>{pin.artifact_type || '?'}</span>
                    <span style={{ color: '#7abfff', flexShrink: 0 }}>{pin.event_ts ? fmtTs(pin.event_ts) : '-'}</span>
                    <span style={{ color: '#c0cce0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pin.description || '-'}</span>
                    {pin.note && <span style={{ color: '#6a8090', fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>{pin.note}</span>}
                    <button
                      onClick={() => setPromoteDialog(pin)}
                      title={pin.is_global ? 'Retirer le partage global' : 'Partager avec tous les membres'}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 1, flexShrink: 0, display: 'flex', alignItems: 'center',
                        color: pin.is_global ? '#f0b040' : '#2a3a50',
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

      <PanelGroup direction="vertical" style={{ flex: 1 }}>

        
        <Panel defaultSize={60} minSize={20} style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          
          <div style={{
            flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6,
            padding: '3px 10px', background: '#07101f', borderBottom: '1px solid #0d1525',
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
                  cursor: 'pointer', border: `1px solid ${showPlayback ? '#4d82c030' : '#0d1f30'}`,
                  background: showPlayback ? 'rgba(77,130,192,0.15)' : 'transparent',
                  color: showPlayback ? '#4d82c0' : '#2a5a8a',
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

        
        <Panel defaultSize={26} minSize={10} style={{ overflow: 'hidden' }}>
          <ArtifactInspector
            record={selectedRecord}
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
  const SEV_COLOR = { critical: '#da3633', high: '#d97c20', medium: '#c89d1d', low: '#3fb950' };

  const isActive = quickFilter || processFilter;

  return (
    <div style={{
      flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'nowrap',
      padding: '4px 10px', background: '#04070e', borderBottom: '1px solid #0d1525',
      overflowX: 'auto',
    }}>
      
      <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', whiteSpace: 'nowrap' }}>SÉVÉRITÉ</span>
      {sevs.map(s => {
        const active = quickFilter?.field === 'hay_severity' && quickFilter.value === s;
        return (
          <button key={s} onClick={() => onFilter('hay_severity', active ? null : s)}
            style={{
              padding: '1px 7px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', whiteSpace: 'nowrap',
              cursor: 'pointer', fontWeight: active ? 700 : 400,
              background: active ? `${SEV_COLOR[s]}22` : 'transparent',
              border: `1px solid ${active ? SEV_COLOR[s] : '#0d1f30'}`,
              color: active ? SEV_COLOR[s] : '#2a5a8a',
            }}>
            {s}
          </button>
        );
      })}

      <div style={{ width: 1, height: 14, background: '#0d1f30', flexShrink: 0 }} />

      
      {hosts.length > 0 && (
        <>
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', whiteSpace: 'nowrap' }}>HÔTE</span>
          <select
            value={quickFilter?.field === 'host' ? quickFilter.value : ''}
            onChange={e => onFilter('host', e.target.value || null)}
            style={{
              background: quickFilter?.field === 'host' ? 'rgba(77,130,192,0.12)' : '#04070e',
              border: `1px solid ${quickFilter?.field === 'host' ? '#4d82c060' : '#0d1f30'}`,
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
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', whiteSpace: 'nowrap' }}>USER</span>
          <select
            value={quickFilter?.field === 'user' ? quickFilter.value : ''}
            onChange={e => onFilter('user', e.target.value || null)}
            style={{
              background: quickFilter?.field === 'user' ? 'rgba(77,130,192,0.12)' : '#04070e',
              border: `1px solid ${quickFilter?.field === 'user' ? '#4d82c060' : '#0d1f30'}`,
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
          <div style={{ width: 1, height: 14, background: '#0d1f30', flexShrink: 0 }} />
          <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', whiteSpace: 'nowrap' }}>TYPE</span>
          <select
            defaultValue=""
            onChange={e => { if (e.target.value) onFilter('type', e.target.value); e.target.value = ''; }}
            style={{
              background: '#04070e', border: '1px solid #0d1f30',
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
          <div style={{ width: 1, height: 14, background: '#0d1f30', flexShrink: 0 }} />
          <button onClick={onClearAll}
            style={{
              padding: '1px 8px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              color: '#ef4444', cursor: 'pointer', whiteSpace: 'nowrap',
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
      <div style={{ padding: '2px 14px 6px', fontSize: 8, fontFamily: 'monospace', color: '#1a3a5c', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
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
        borderLeft: `2px solid ${hov ? (danger ? '#ef4444' : '#4d82c0') : 'transparent'}`,
      }}>
      <span style={{ fontSize: 11, flexShrink: 0 }}>{icon}</span>
      <span style={{ fontFamily: 'monospace', fontSize: 10, color: danger ? '#ef4444' : (hov ? '#c0cce0' : '#7abfff'), overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </span>
    </div>
  );
}
