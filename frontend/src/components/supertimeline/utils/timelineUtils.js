// ============================================================================
// timelineUtils.js — Shared utilities for SuperTimeline components
// ============================================================================

// ARTIFACT_TAB_HEX — hex colors per artifact type
export const ARTIFACT_TAB_HEX = {
  evtx: '#2E5090',      // Deep Blue
  prefetch: '#8B4789',  // Purple
  mft: '#D97706',       // Amber
  lnk: '#7C3AED',       // Violet
  registry: '#DC2626',  // Red
  amcache: '#0891B2',   // Cyan
  shellbags: '#059669', // Emerald
  jumplist: '#CA8A04',  // Yellow
  srum: '#4F46E5',      // Indigo
  recycle: '#EA580C',   // Orange
  wxtcmd: '#2563EB',    // Blue
  sqle: '#6366F1',      // Iris
  sum: '#1E40AF',       // Dark Blue
  appcompat: '#8B5CF6', // Fuchsia
  bits: '#0369A1',      // Sky
  hayabusa: '#991B1B',  // Dark Red
};

/**
 * Returns hex color for artifact type, with fallback
 */
export function tabColor(type) {
  return ARTIFACT_TAB_HEX[type] || '#8b9ab4';
}

// DETECTION_SEV_RANK — severity ranking for sorting
export const DETECTION_SEV_RANK = {
  greyware: 1,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// DETECTION_SEV_COLOR — CSS variable colors per severity
export const DETECTION_SEV_COLOR = {
  critical: 'var(--fl-danger)',
  high: 'var(--fl-danger)',
  medium: 'var(--fl-warn)',
  low: 'var(--fl-gold)',
  greyware: 'var(--fl-gold)',
};

/**
 * Returns highest severity label from array of {severity} objects, or null
 */
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

/**
 * djb2 hash function for computing unique reference
 * Returns 8-character hex string of hash(timestamp|artifact_type|source)
 */
export function computeRef(r) {
  const input = `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  }
  return Math.abs(hash).toString(16).substring(0, 8).padStart(8, '0');
}

/**
 * Format description per artifact type
 */
export function fmtDesc(r) {
  const raw = r.raw || {};
  switch (r.artifact_type) {
    case 'evtx': {
      const md  = raw.MapDescription || r.description || '';
      const eid = String(raw.EventId || raw.EventID || '').trim();
      const pd  = raw.PayloadData1 || raw.PayloadData2 || '';
      if (/^\d+\s*\|\s*\d+\s*\|/.test(md)) {
        // Pipe-delimited EvtxECmd format: "EventID | count | Human readable title"
        const parts = md.split('|');
        const eidParsed = String(raw.EventId || raw.EventID || parts[0]).trim();
        const title     = parts.slice(2).join('|').trim();
        if (title && pd)   return `[EID:${eidParsed}] ${title} — ${pd}`;
        if (title)         return `[EID:${eidParsed}] ${title}`;
        // PayloadData utile seulement si ce n'est pas un nombre brut (count EvtxECmd)
        if (pd && !/^\d+$/.test(String(pd).trim())) return `[EID:${eidParsed}] ${pd}`;
        return `EventID ${eidParsed}`;
      }
      // Pas de MapDescription utile — chercher dans tous les PayloadData, puis Channel
      const isNum = v => !v || /^\d+$/.test(String(v).trim());
      const mdOk  = md && md !== eid && !isNum(md);
      if (eid && mdOk) return `[EID:${eid}] ${md}`;
      // First non-numeric PayloadData
      for (let n = 1; n <= 6; n++) {
        const pv = raw[`PayloadData${n}`];
        if (pv != null && !isNum(pv)) return `[EID:${eid}] ${String(pv)}`;
      }
      // Last resort: Channel (already visible in DataPath, but useful in the description)
      const ch = raw.Channel || raw.channel || '';
      if (eid && ch) return `[EID:${eid}] ${ch}`;
      if (eid)       return `EventID ${eid}`;
      return r.description || '';
    }
    case 'appcompat': {
      const p = raw.Path || r.description || '';
      // ShimCache rows are often tab-delimited metadata:
      //   position \t timestamp \t timestamp \t arch(8664) \t name \t publisherId
      // Keep only the human-readable tokens (drop position / timestamps / arch).
      if (/\t/.test(p) || /^[0-9a-f]{6,}[\s\t]/i.test(p)) {
        const meaningful = p
          .split(/\t+/).map(s => s.trim()).filter(Boolean)
          .filter(s => !/^[0-9a-f]{4,}$/i.test(s)            // pure hex: position, timestamps, 8664
                    && !/^(8664|x86_64|x64|x86|32)$/i.test(s)
                    && !/^\d+$/.test(s));                     // pure decimal
        if (meaningful.length) return meaningful.join(' ');
      }
      // Otherwise just strip a leading arch code / hex prefix from a normal path.
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
      // ShortCuts entries: strip |hexhash suffix from KeyName
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
      // r.description may be a server collection path — strip it
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

/**
 * Nettoie un chemin serveur Heimdall (/app/collections/case-.../Saved_Files/...)
 * et retourne un chemin Windows lisible ou juste le nom de fichier.
 */
function cleanSrcPath(src) {
  if (!src) return '';
  // Chemin serveur type: /app/collections/case-{id}-{ts}/Saved_Files/Category/C/Windows/...
  const savedFiles = src.match(/\/Saved_Files\/(?:[^/]+\/)?(.*)/);
  if (savedFiles) {
    const p = savedFiles[1];
    // Convert Unix separators -> Windows separators
    return p.replace(/\//g, '\\');
  }
  // Chemin /app/ ou /tmp/ sans Saved_Files → juste le nom de fichier
  if (src.startsWith('/app/') || src.startsWith('/tmp/')) {
    return src.split('/').pop() || src;
  }
  return src;
}

/**
 * Format source per artifact type
 */
export function fmtSrc(r) {
  const raw = r.raw || {};
  const src = cleanSrcPath(r.source);
  switch (r.artifact_type) {
    case 'evtx':
      // Channel ex: "Security", "System", "Application"
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
      // HivePath ex: "C:\Windows\System32\config\SYSTEM" ou juste "SYSTEM"
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

// COLUMNS_BASE — Base column definitions for timeline table
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

// SERVER_SORTABLE — Set of columns that can be sorted server-side
export const SERVER_SORTABLE = new Set([
  'timestamp',
  'artifact_type',
  'description',
  'source',
]);

// GROUP_BY_FIELDS — derived from COLUMNS_BASE (grid columns), minus free-text/complex columns,
// plus a few extra forensic fields not visible as columns but groupable at the DB level.
const _GROUP_BY_EXCLUDE = new Set(['timestamp', 'description', 'detections']);
export const GROUP_BY_FIELDS = [
  ...COLUMNS_BASE
    .filter(c => !_GROUP_BY_EXCLUDE.has(c.key))
    .map(c => ({ key: c.key, label: c.label })),
  { key: 'sha1',   label: 'SHA-1' },
  { key: 'src_ip', label: 'Source IP' },
  { key: 'dst_ip', label: 'Dest IP' },
];

// FORENSIC_TAGS — Tags for marking events with forensic significance
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

// CONFIDENCE_LEVELS — Confidence classification with dark-theme colors
export const CONFIDENCE_LEVELS = [
  { key: 'critical', label: 'Malicious',   color: '#f87171', bg: 'rgba(220,38,38,0.14)',  dot: '#ef4444' },
  { key: 'high',     label: 'Suspect',     color: '#fb923c', bg: 'rgba(234,88,12,0.12)',  dot: '#f97316' },
  { key: 'medium',   label: 'To Analyze',  color: '#fbbf24', bg: 'rgba(245,158,11,0.10)', dot: '#f59e0b' },
  { key: 'low',      label: 'Benign',      color: '#34d399', bg: 'rgba(16,185,129,0.10)', dot: '#10b981' },
];

// CONFIDENCE_MAP — Map confidence keys to their definitions
export const CONFIDENCE_MAP = Object.fromEntries(CONFIDENCE_LEVELS.map(c => [c.key, c]));

// ARTIFACT_FIELD_PRIORITY — per-type ordered list of raw fields shown first in Schema tab
// and used to sort dynamic columns in single-artifact mode.
export const ARTIFACT_FIELD_PRIORITY = {
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

// KEEP IN SYNC with COLUMNS_BASE keys above. If you add a new first-class column
// to COLUMNS_BASE, add its key here too to prevent duplication in dynamic columns.
// NORMALIZED_KEYS — raw keys already promoted to first-class columns; skip in dynamic cols
const NORMALIZED_KEYS = new Set([
  'timestamp','artifact_type','artifact_name','description','source','tool',
  'timestamp_kind','details','path','ext','event_id','file_size','src_ip','dst_ip',
  'sha1','host_name','user_name','process_name','mitre_technique_id',
]);

/**
 * buildDynamicCols — generate dynamic column definitions from raw JSONB keys
 * for single-artifact mode. Returns array of { key, label, size }.
 *
 * @param {Array} records - current loaded records
 * @param {string} artifactType - e.g. 'evtx'
 * @param {string} caseId - for localStorage scoping
 * @returns {Array<{key: string, label: string, size: number}>}
 */
export function buildDynamicCols(records, artifactType, caseId) {
  if (!records?.length) return [];
  // Collect all raw keys across first 20 records to catch sparse fields
  const allKeys = new Set();
  // Sample first 20 records to balance field coverage vs. performance;
  // sparse fields that only appear after record 20 will be absent from dynamic cols.
  records.slice(0, 20).forEach(r => {
    Object.keys(r?.raw || {}).forEach(k => allKeys.add(k));
  });
  // Filter out already-normalized keys AND keys whose sampled value is a nested object/array
  // (e.g. AllFieldInfo, ExtraFieldInfo in Hayabusa) — they render as [object Object] in cells.
  const rawKeys = [...allKeys].filter(k => {
    if (NORMALIZED_KEYS.has(k)) return false;
    const sample = records.slice(0, 20).find(r => r?.raw?.[k] != null)?.raw?.[k];
    if (sample != null && typeof sample === 'object') return false;
    return true;
  });
  const rawKeysSet = new Set(rawKeys);
  // Sort: priority list first, then alphabetical
  const priority = ARTIFACT_FIELD_PRIORITY[artifactType] || [];
  const prioritySet = new Set(priority);
  const sorted = [
    ...priority.filter(k => rawKeysSet.has(k)),
    ...rawKeys.filter(k => !prioritySet.has(k)).sort(),
  ];
  // Restore user-added column order from localStorage
  let userAdded = [];
  try {
    // Key format: supertl.dynamicCols.<artifactType>.<caseId>
    // Assumes artifactType is a short lowercase string (e.g. 'evtx') and caseId is a UUID — no encoding needed.
    userAdded = JSON.parse(localStorage.getItem(`supertl.dynamicCols.${artifactType}.${caseId}`) || '[]');
  } catch { /* ignore */ }
  const finalKeys = [...new Set([...sorted, ...userAdded.filter(k => allKeys.has(k))])];
  return finalKeys.map(k => ({
    key: `raw.${k}`,
    label: k,
    size: 130,
    meta: { dynamic: true, rawKey: k },
  }));
}
