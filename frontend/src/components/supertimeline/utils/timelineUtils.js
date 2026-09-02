import { artifactFamily } from './artifactFamily';

export const ARTIFACT_TAB_HEX = {
  evtx: '#2E5090',
  prefetch: '#8B4789',
  mft: '#D97706',
  lnk: '#7C3AED',
  registry: '#DC2626',
  amcache: '#0891B2',
  shellbags: '#059669',
  jumplist: '#CA8A04',
  srum: '#4F46E5',
  recycle: '#EA580C',
  wxtcmd: '#2563EB',
  sqle: '#6366F1',
  sum: '#1E40AF',
  appcompat: '#8B5CF6',
  bits: '#0369A1',
  hayabusa: '#991B1B',
};

export function tabColor(type) {
  return ARTIFACT_TAB_HEX[type] || '#8b9ab4';
}

export const DETECTION_SEV_RANK = {
  greyware: 1,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const DETECTION_SEV_COLOR = {
  critical: 'var(--fl-danger)',
  high: 'var(--fl-danger)',
  medium: 'var(--fl-warn)',
  low: 'var(--fl-gold)',
  greyware: 'var(--fl-gold)',
};

export function topDetectionSeverity(dets) {
  if (!Array.isArray(dets) || dets.length === 0) return null;
  let highest = null;
  let highestRank = -1;
  for (const d of dets) {
    const rank = DETECTION_SEV_RANK[d.severity] ?? -1;
    if (rank > highestRank) {
      highestRank = rank;
      highest = d.severity;
    }
  }
  return highest;
}

export const INVENTORY_TS_KIND = 'inventory';

export function isInventoryRow(r) {
  return r?.timestamp_kind === INVENTORY_TS_KIND;
}

export function tsTypeLabel(r, labels) {
  const kind = r?.timestamp_kind || '';
  if (kind !== INVENTORY_TS_KIND) return kind;
  return labels?.inventory || INVENTORY_TS_KIND;
}

export function splitCounts(total, undated) {
  const t = Number(total) || 0;
  const u = Number(undated) || 0;
  return { dated: Math.max(t - u, 0), undated: u };
}

export function rankTypes(types, counts, visible = 12, selected = []) {
  const list = Array.isArray(types) ? types.filter(Boolean) : [];
  if (list.length === 0) return { shown: [], hidden: [] };
  const c = counts || {};
  const sel = new Set(Array.isArray(selected) ? selected : []);

  const ranked = [...list].sort((a, b) => {
    const na = Number(c[a] ?? -1), nb = Number(c[b] ?? -1);
    return nb - na || String(a).localeCompare(String(b));
  });

  if (ranked.length <= visible + 3) return { shown: ranked, hidden: [] };

  const shown = ranked.slice(0, visible);
  const hidden = ranked.slice(visible);
  const rescued = hidden.filter(t => sel.has(t));
  return rescued.length
    ? { shown: [...shown, ...rescued], hidden: hidden.filter(t => !sel.has(t)) }
    : { shown, hidden };
}

const CONSTANT_MIN_SAMPLE = 3;

export function constantColumns(records, keys) {
  const rows = Array.isArray(records) ? records : [];
  const cols = Array.isArray(keys) ? keys : [];
  if (rows.length < CONSTANT_MIN_SAMPLE || cols.length === 0) return [];

  return cols.filter(k => {
    const first = rows[0]?.[k];
    if (first === undefined || first === null || first === '') return false;
    return rows.every(r => r?.[k] === first);
  });
}

export const DENSITIES = ['compact', 'normal', 'relaxed'];
export const DEFAULT_DENSITY = 'normal';

export const STACKED_TIMESTAMP_PX = 27;

const ROW_HEIGHTS = {
  compact: { row: 22, group: 24, groupNested: 20, loadmore: 34 },
  normal:  { row: 28, group: 28, groupNested: 24, loadmore: 40 },
  relaxed: { row: 36, group: 34, groupNested: 30, loadmore: 46 },
};

function heightsFor(density) {
  return ROW_HEIGHTS[density] || ROW_HEIGHTS[DEFAULT_DENSITY];
}

export function rowHeightFor(density, item) {
  const h = heightsFor(density);
  if (!item) return h.row;
  if (item.type === 'group')    return item.level === 0 ? h.group : h.groupNested;
  if (item.type === 'loadmore') return h.loadmore;
  return h.row;
}

export function stacksTimestamp(density) {
  return heightsFor(density).row >= STACKED_TIMESTAMP_PX;
}

export function describeCount(state) {
  const s = state || {};
  const t = s.total;
  if (s.loading || t === null || t === undefined || t === '') return { kind: 'loading' };
  const n = Number(t);
  if (!Number.isFinite(n)) return { kind: 'loading' };
  if (n <= 0) return { kind: 'empty' };
  return { kind: 'count', total: n };
}

export function pagePosition(lo, hi, firstTs, lastTs) {
  const num = v => (v === null || v === undefined || v === '' ? NaN : Number(v));
  const L = num(lo), H = num(hi);
  const a = num(firstTs), b = num(lastTs);
  if (![L, H, a, b].every(Number.isFinite)) return null;
  const span = H - L;
  if (span <= 0) return null;
  const from = Math.min(a, b), to = Math.max(a, b);
  const pct = v => Math.max(0, Math.min(100, ((v - L) / span) * 100));
  return { startPct: pct(from), endPct: pct(to) };
}

export const MONO_ADVANCE_PX = 6;
export const CELL_PADDING_PX = 16;
const TS_COL_STACKED_PX = 110;
const TS_COL_INLINE_PX  = 23 * MONO_ADVANCE_PX + CELL_PADDING_PX;

export function timestampColumnWidth(density) {
  return stacksTimestamp(density) ? TS_COL_STACKED_PX : TS_COL_INLINE_PX;
}

export function splitPathTail(path) {
  const s = path === null || path === undefined ? '' : String(path);
  if (!s) return { head: '', tail: '' };
  let cut = -1;
  for (let i = s.length - 1; i >= 0; i--) {
    const c = s[i];
    if (c === '/' || c === '\\') { cut = i; break; }
  }
  if (cut === -1) return { head: '', tail: s };
  return { head: s.slice(0, cut + 1), tail: s.slice(cut + 1) };
}

export function initialExplorerOpen(stored) {
  return stored === 'true';
}

export const ANCIENT_BEFORE_YEAR = 1980;
const ANCIENT_BEFORE_MS = Date.UTC(ANCIENT_BEFORE_YEAR, 0, 1);

export function timestampPlausibility(ts, now = Date.now()) {
  if (ts === null || ts === undefined || ts === '') return 'none';
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return 'none';
  if (t > now) return 'future';
  if (t < ANCIENT_BEFORE_MS) return 'ancient';
  return 'ok';
}

export function countImplausible(records, now = Date.now()) {
  const rows = Array.isArray(records) ? records : [];
  let future = 0, ancient = 0;
  for (const r of rows) {
    const verdict = timestampPlausibility(r?.timestamp, now);
    if (verdict === 'future')  future++;
    else if (verdict === 'ancient') ancient++;
  }
  return { future, ancient, total: future + ancient };
}

const SERVER_FACETS = {
  artifact_type: s => ({ values: s.availTypes, counts: s.typeCounts }),
  host_name:     s => ({ values: s.hostsAvail, counts: null }),
  user_name:     s => ({ values: s.usersAvail, counts: null }),
};

export function buildFacet(colKey, state, limit = 12) {
  const s = state || {};
  const server = SERVER_FACETS[colKey]?.(s);
  let entries;
  let scope;

  if (server && Array.isArray(server.values) && server.values.length > 0) {
    scope = 'collection';
    entries = server.values
      .filter(v => v !== undefined && v !== null && v !== '')
      .map(v => ({ value: String(v), count: server.counts ? (Number(server.counts[v]) || 0) : null }));
  } else {
    scope = 'page';
    const tally = new Map();
    for (const r of (Array.isArray(s.records) ? s.records : [])) {
      const v = r?.[colKey];
      if (v === undefined || v === null || v === '') continue;
      const k = String(v);
      tally.set(k, (tally.get(k) || 0) + 1);
    }
    entries = [...tally].map(([value, count]) => ({ value, count }));
  }

  entries.sort((a, b) =>
    (b.count ?? -1) - (a.count ?? -1) || a.value.localeCompare(b.value));

  return {
    values: entries.slice(0, limit),
    hidden: Math.max(entries.length - limit, 0),
    scope,
  };
}

export function orderColumns(cols, order) {
  const list = Array.isArray(cols) ? cols : [];
  const wanted = Array.isArray(order) ? order : [];
  if (wanted.length === 0) return list;

  const byKey = new Map(list.map(c => [c.key, c]));
  const placed = [];
  const seen = new Set();
  for (const key of wanted) {
    const col = byKey.get(key);
    if (col && !seen.has(key)) { placed.push(col); seen.add(key); }
  }
  return [...placed, ...list.filter(c => !seen.has(c.key))];
}

export function moveColumn(order, fromKey, toKey) {
  const list = Array.isArray(order) ? [...order] : [];
  const from = list.indexOf(fromKey);
  const to   = list.indexOf(toKey);
  if (from < 0 || to < 0 || from === to) return Array.isArray(order) ? order : [];
  list.splice(from, 1);
  list.splice(to, 0, fromKey);
  return list;
}

export function computeRef(r) {
  const input = `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  }
  return Math.abs(hash).toString(16).substring(0, 8).padStart(8, '0');
}

export function fmtDesc(r) {
  const raw = r.raw || {};
  switch (artifactFamily(r.artifact_type)) {
    case 'evtx': {
      const md  = raw.MapDescription || r.description || '';
      const eid = String(raw.EventId || raw.EventID || '').trim();
      const pd  = raw.PayloadData1 || raw.PayloadData2 || '';
      if (/^\d+\s*\|\s*\d+\s*\|/.test(md)) {
        const parts = md.split('|');
        const eidParsed = String(raw.EventId || raw.EventID || parts[0]).trim();
        const title     = parts.slice(2).join('|').trim();
        if (title && pd)   return `[EID:${eidParsed}] ${title} — ${pd}`;
        if (title)         return `[EID:${eidParsed}] ${title}`;
        if (pd && !/^\d+$/.test(String(pd).trim())) return `[EID:${eidParsed}] ${pd}`;
        return `EventID ${eidParsed}`;
      }
      const isNum = v => !v || /^\d+$/.test(String(v).trim());
      const mdOk  = md && md !== eid && !isNum(md);
      if (eid && mdOk) return `[EID:${eid}] ${md}`;
      for (let n = 1; n <= 6; n++) {
        const pv = raw[`PayloadData${n}`];
        if (pv != null && !isNum(pv)) return `[EID:${eid}] ${String(pv)}`;
      }
      const ch = raw.Channel || raw.channel || '';
      if (eid && ch) return `[EID:${eid}] ${ch}`;
      if (eid)       return `EventID ${eid}`;
      return r.description || '';
    }
    case 'appcompat': {
      const p = raw.Path || r.description || '';
      if (/\t/.test(p) || /^[0-9a-f]{6,}[\s\t]/i.test(p)) {
        const meaningful = p
          .split(/\t+/).map(s => s.trim()).filter(Boolean)
          .filter(s => !/^[0-9a-f]{4,}$/i.test(s)
                    && !/^(8664|x86_64|x64|x86|32)$/i.test(s)
                    && !/^\d+$/.test(s));
        if (meaningful.length) return meaningful.join(' ');
      }
      return p
        .replace(/^(8664|x86_64|x64|x86|32)\s+/i, '')
        .replace(/^([0-9a-f]{6,}\s+)+/i, '')
        .trim() || p;
    }
    case 'registry': {
      const desc  = raw.Description  || '';
      const name  = raw.ValueName    || '';
      const data  = raw.ValueData    || raw.Data || '';
      const key   = raw.KeyPath      || r.description || '';
      if (name && data) return desc ? `${desc}: ${name} = ${data}` : `${name} = ${data}`;
      if (name)         return desc ? `${desc}: ${name}` : name;
      return desc || key;
    }
    case 'prefetch':
      return (raw.ExecutableName || r.description || '').split('|')[0].trim();
    case 'mft': {
      const fname  = raw.FileName || raw.Name || r.description || '';
      const parent = raw.ParentPath || raw.FolderPath || '';
      if (parent && fname) return `${parent}\\${fname}`;
      return fname;
    }
    case 'usn': {
      const name    = raw.Name || raw.FileName || '';
      const reasons = (raw.UpdateReasons || '').replace(/\|/g, ' · ');
      const parent  = raw.ParentPath || '';
      const full    = parent && parent !== '.\\' ? `${parent}\\${name}` : name;
      if (full && reasons) return `${full} — ${reasons}`;
      return full || reasons || r.description || '';
    }
    case 'indx': {
      const fname  = raw.FileName || raw.Name || '';
      const parent = raw.ParentPath || '';
      if (parent && fname) return `${parent}\\${fname}`;
      return fname || r.description || '';
    }
    case 'userassist': {
      const prog = raw.ProgramName || r.description || '';
      const rc   = raw.RunCount;
        return rc ? `${prog} (x${rc})` : prog;
    }
    case 'netprofile': {
      const ssid = raw.ProfileName || r.description || '';
      const dns  = raw.DnsSuffix || '';
      const mac  = raw.GatewayMac || '';
      return [ssid, dns, mac && `GW ${mac}`].filter(Boolean).join(' · ');
    }
    case 'usb':
      return raw.DeviceDescription || raw.DeviceInstanceId || r.description || '';
    case 'schtasks': {
      const task = raw.TaskName || '';
      const cmd  = [raw.Command, raw.Arguments].filter(Boolean).join(' ');
      if (task && cmd) return `${task} → ${cmd}`;
      return task || cmd || r.description || '';
    }
    case 'pwsh':
      return raw.Command || r.description || '';
    case 'dns':
      return raw.Entry || r.description || '';
    case 'webcache': {
      const url = raw.Url || r.description || '';
      const ct  = raw.ContainerType || '';
      return ct && url ? `[${ct}] ${url}` : url;
    }
    case 'wmi': {
      const name = raw.Name || '';
      const det  = raw.Detail || '';
      const t    = raw.Type ? `${raw.Type}: ` : '';
      return `${t}${name}${det ? ' — ' + det : ''}` || r.description || '';
    }
    case 'amcache': {
      const path = raw.FullPath || raw.FilePath || '';
      const desc = raw.FileDescription || raw.ProgramName || '';
      if (path && desc) return `${path} (${desc})`;
      if (path || desc) return path || desc;
      const keyName = (raw.KeyName || r.description || '').replace(/\|[0-9a-f]{8,}$/i, '').trim();
      return keyName;
    }
    case 'srum':
      return raw.ExeInfo || raw.AppId || r.description || '';
    case 'shellbags':
      return raw.AbsolutePath || r.description || '';
    case 'sqle': {
      const url   = raw.URL || raw.Url || '';
      const title = raw.Title || '';
      if (url && title) return `${url} — ${title}`;
      return url || title || r.description || '';
    }
    case 'lnk': {
      const localPath = raw.LocalPath || raw.TargetFileDosPath || raw.NetworkPath || '';
      const name      = raw.Name || '';
      if (localPath) return name && name !== localPath ? `${name} → ${localPath}` : localPath;
      return cleanSrcPath(r.description || '') || r.description || '';
    }
    case 'wxtcmd':
      return raw.DisplayText || raw.Description || raw.AppId || r.description || '';
    case 'hayabusa': {
      const ruleTitle = raw.RuleTitle || '';
      const levelRaw  = (raw.Level || raw.level || '').toLowerCase();
      const LEVEL_EXPAND = { crit: 'critical', med: 'medium', info: 'informational' };
      const level  = LEVEL_EXPAND[levelRaw] || levelRaw;
      const prefix = level ? `[${level}] ` : '';
      if (ruleTitle) return `${prefix}${ruleTitle}`;
      return r.description || '';
    }
    default:
      return r.description || '';
  }
}

function cleanSrcPath(src) {
  if (!src) return '';
  const savedFiles = src.match(/\/Saved_Files\/(?:[^/]+\/)?(.*)/);
  if (savedFiles) {
    const p = savedFiles[1];
    return p.replace(/\//g, '\\');
  }
  if (src.startsWith('/app/') || src.startsWith('/tmp/')) {
    return src.split('/').pop() || src;
  }
  return src;
}

export function fmtSrc(r) {
  const raw = r.raw || {};
  const src = cleanSrcPath(r.source);
  switch (artifactFamily(r.artifact_type)) {
    case 'evtx':
      return raw.Channel || src.replace(/\.evtx$/i, '').split('\\').pop() || src;
    case 'appcompat':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src;
    case 'mft':
      return raw.ParentPath || src;
    case 'prefetch':
      return raw.SourceFilename || src;
    case 'lnk':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src;
    case 'registry':
      return raw.HivePath || src;
    case 'amcache':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src;
    case 'shellbags':
      return raw.HivePath || (raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src);
    case 'jumplist':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src;
    case 'srum':
      return raw.AppId || raw.UserId || src;
    case 'recycle':
      return raw.SourceName || raw.FileName || src;
    case 'bits':
      return raw.TargetDirectory || raw.Url || src;
    case 'sum':
      return raw.Address || src;
    case 'sqle':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : src;
    case 'wxtcmd':
      return raw.SourceFile ? cleanSrcPath(raw.SourceFile) : (raw.AppId || src);
    default:
      return src || r.source || '';
  }
}

export const COLUMNS_BASE = [
  { key: 'timestamp', label: 'Timestamp', size: 186 },
  { key: 'artifact_type', label: 'Artifact Type', size: 96 },
  { key: 'description', label: 'Description', size: 400, meta: { flex: true } },
  { key: 'source', label: 'Source', size: 170 },
  { key: 'timestamp_kind', label: 'Timestamp Type', size: 100 },
  { key: 'tool', label: 'Tool', size: 100 },
  { key: 'event_id', label: 'Event ID', size: 80, meta: { hiddenByDefault: true } },
  { key: 'ext', label: 'Extension', size: 64, meta: { hiddenByDefault: true } },
  { key: 'host_name', label: 'Host Name', size: 130 },
  { key: 'user_name', label: 'User Name', size: 110 },
  { key: 'process_name', label: 'Process Name', size: 140, meta: { hiddenByDefault: true } },
  { key: 'mitre_technique_id', label: 'MITRE Technique', size: 90, meta: { hiddenByDefault: true } },
  { key: 'detections', label: 'Detections', size: 130 },
];

export const SERVER_SORTABLE = new Set([
  'timestamp',
  'artifact_type',
  'description',
  'source',
]);

const _GROUP_BY_EXCLUDE = new Set(['timestamp', 'description', 'detections']);
export const GROUP_BY_FIELDS = [
  ...COLUMNS_BASE
    .filter(c => !_GROUP_BY_EXCLUDE.has(c.key))
    .map(c => ({ key: c.key, label: c.label })),
  { key: 'sha1',   label: 'SHA-1' },
  { key: 'src_ip', label: 'Source IP' },
  { key: 'dst_ip', label: 'Dest IP' },
];

export const FORENSIC_TAGS = [
  { key: 'exec', label: 'Execution', color: '#EF4444' },
  { key: 'persist', label: 'Persistence', color: '#F59E0B' },
  { key: 'lateral', label: 'Lateral Movement', color: '#8B5CF6' },
  { key: 'exfil', label: 'Exfiltration', color: '#EC4899' },
  { key: 'c2', label: 'C2', color: '#DC2626' },
  { key: 'recon', label: 'Reconnaissance', color: '#06B6D4' },
  { key: 'privesc', label: 'Privilege Escalation', color: '#F97316' },
  { key: 'defense_evasion', label: 'Defense Evasion', color: '#6366F1' },
  { key: 'credential', label: 'Credential Access', color: '#DB2777' },
  { key: 'discovery', label: 'Discovery', color: '#0891B2' },
  { key: 'initial_access', label: 'Initial Access', color: '#EA580C' },
  { key: 'impact', label: 'Impact', color: '#7C2D12' },
];

export const CONFIDENCE_LEVELS = [
  { key: 'critical', label: 'Malicious',   color: '#f87171', bg: 'rgba(220,38,38,0.14)',  dot: '#ef4444' },
  { key: 'high',     label: 'Suspect',     color: '#fb923c', bg: 'rgba(234,88,12,0.12)',  dot: '#f97316' },
  { key: 'medium',   label: 'To Analyze',  color: '#fbbf24', bg: 'rgba(245,158,11,0.10)', dot: '#f59e0b' },
  { key: 'low',      label: 'Benign',      color: '#34d399', bg: 'rgba(16,185,129,0.10)', dot: '#10b981' },
];

export const CONFIDENCE_MAP = Object.fromEntries(CONFIDENCE_LEVELS.map(c => [c.key, c]));

export const ARTIFACT_FIELD_PRIORITY = {
  hayabusa:  ['RuleTitle','Level','Computer','Channel','EventID',
              'AllFieldInfo.TargetUserName','AllFieldInfo.SubjectUserName',
              'AllFieldInfo.IpAddress','AllFieldInfo.WorkstationName',
              'AllFieldInfo.LogonType','AllFieldInfo.ProcessName','AllFieldInfo.CommandLine'],
  evtx:      ['EventId','Channel','PayloadData1','SubjectUserName','TargetUserName','IpAddress','LogonType','WorkstationName','ProcessName','ProcessId'],
  prefetch:  ['ExecutableName','RunCount','LastRun','SourceFilename','VolumeName','VolumeSerial'],
  mft:       ['FileName','ParentPath','FileSize','Created0x10','LastModified0x10','LastAccess0x10','InUse'],
  registry:  ['KeyPath','ValueName','ValueData','ValueType','HivePath','LastWriteTimestamp'],
  amcache:   ['FullPath','FileDescription','ProgramName','FileSize','SHA1','LanguageCode','PublisherName'],
  shellbags: ['AbsolutePath','HivePath','SlotModifiedDate','ShellType'],
  lnk:       ['LocalPath','TargetMFTEntryNumber','TargetMFTSequenceNumber','DriveType','VolumeLabel','MachineName'],
  srum:      ['ExeInfo','AppId','UserId','BytesSent','BytesReceived','NetworkInterface'],
  hayabusa:  ['RuleTitle','Level','Channel','EventId','Details','ExtraFieldInfo','MitreTags'],
  jumplist:  ['AppId','EntryName','TargetPath','TargetMFTEntryNumber','LastModified'],
  bits:      ['JobName','FileUrl','TargetDirectory','TransferCompletionTime','Url'],
  sqle:      ['Title','URL','VisitTime','VisitCount','SourceFile'],
  wxtcmd:    ['AppId','DisplayText','LaunchUri','SourceFile'],
  recycle:   ['FileName','FileSize','DeletedTimestamp','SourceName'],
  sum:       ['Address','UserName','LastAccess','TotalSessions'],
  appcompat: ['Path','LastModifiedTime','FileSize','SHA1'],
};

const NORMALIZED_KEYS = new Set([
  'timestamp','artifact_type','artifact_name','description','source','tool',
  'timestamp_kind','details','path','ext','event_id','file_size','src_ip','dst_ip',
  'sha1','host_name','user_name','process_name','mitre_technique_id',
]);

export function readRawPath(raw, key) {
  if (!raw || typeof raw !== 'object') return undefined;
  if (Object.prototype.hasOwnProperty.call(raw, key)) return raw[key];
  let cur = raw;
  for (const part of String(key).split('.')) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

export function buildDynamicCols(records, artifactType, caseId) {
  if (!records?.length) return [];
  const allKeys = new Set();
  records.slice(0, 20).forEach(r => {
    Object.entries(r?.raw || {}).forEach(([k, v]) => {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        Object.keys(v).forEach(sub => allKeys.add(`${k}.${sub}`));
      } else {
        allKeys.add(k);
      }
    });
  });
  const rawKeys = [...allKeys].filter(k => {
    if (NORMALIZED_KEYS.has(k)) return false;
    const sample = records.slice(0, 20)
      .map(r => readRawPath(r?.raw, k)).find(v => v != null);
    if (sample != null && typeof sample === 'object') return false;
    return true;
  });
  const rawKeysSet = new Set(rawKeys);
  const priority = ARTIFACT_FIELD_PRIORITY[artifactType] || [];
  const prioritySet = new Set(priority);
  const sorted = [
    ...priority.filter(k => rawKeysSet.has(k)),
    ...rawKeys.filter(k => !prioritySet.has(k)).sort(),
  ];
  let userAdded = [];
  try {
    userAdded = JSON.parse(localStorage.getItem(`supertl.dynamicCols.${artifactType}.${caseId}`) || '[]');
  } catch { }
  const finalKeys = [...new Set([...sorted, ...userAdded.filter(k => allKeys.has(k))])];
  return finalKeys.map(k => ({
    key: `raw.${k}`,
    label: k,
    size: 130,
    meta: { dynamic: true, rawKey: k },
  }));
}
