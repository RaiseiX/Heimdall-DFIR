const crypto = require('crypto');

function stripNullBytes(record) {
  const clean = {};
  for (const [k, v] of Object.entries(record)) {
    clean[k] = typeof v === 'string' ? v.replace(/\u0000/g, '') : v;
  }
  return clean;
}

function normalizeTimestamp(value) {
  if (!value || value === '' || value === '(null)') return null;
  try {
    let cleaned = value.trim();

    // Handle offset-aware strings (e.g. +02:00 or -05:00) — parse as-is, convert to UTC
    if (/[+-]\d{2}:\d{2}$/.test(cleaned)) {
      const d = new Date(cleaned.replace(' ', 'T'));
      if (isNaN(d.getTime())) return null;
      const year = d.getUTCFullYear();
      if (year < 1980 || year > 2035) return null;
      return d.toISOString();
    }

    // No offset: assume UTC (EZ Tools output)
    if (cleaned.endsWith('Z')) cleaned = cleaned.slice(0, -1);
    if (cleaned.includes(' ') && !cleaned.includes('T')) cleaned = cleaned.replace(' ', 'T');
    const d = new Date(cleaned + 'Z');
    if (isNaN(d.getTime())) return null;
    const year = d.getUTCFullYear();
    if (year < 1980 || year > 2035) return null;
    return d.toISOString();
  } catch {
    return null;
  }
}

function extractTimestamp(record, timestampColumns) {
  for (const col of timestampColumns) {
    if (record[col]) {
      const ts = normalizeTimestamp(record[col]);
      if (ts) return { timestamp: ts, column: col };
    }
  }

  for (const [key, val] of Object.entries(record)) {
    if (typeof val === 'string' && /\d{4}-\d{2}-\d{2}/.test(val)) {
      const ts = normalizeTimestamp(val);
      if (ts) return { timestamp: ts, column: key };
    }
  }
  return null;
}

function extractDescription(record, descriptionColumns) {
  for (const col of descriptionColumns) {
    const val = (record[col] || '').toString().trim();
    if (val && val !== '-' && val !== 'N/A') return val;
  }
  return '';
}

// mirrors collection.js:623-638 (legacy dedupe scheme) — keep in sync
function computeDedupeHash(artifactType, { tsColumn, source, description, eventId, record }) {
  const extraUnique =
    artifactType === 'evtx'
      ? `|${record['EventRecordId'] || record['RecordNumber'] || ''}|${record['Computer'] || ''}`
      : artifactType === 'mft'
      ? `|${record['EntryNumber'] || ''}|${record['SequenceNumber'] || ''}`
      : '';
  return crypto
    .createHash('md5')
    .update([
      tsColumn || '', source || '', artifactType || '',
      (description || '').slice(0, 200), eventId == null ? '' : String(eventId),
    ].join('|') + extraUnique)
    .digest('hex')
    .slice(0, 16);
}

const TIMELINE_FIELD_CONFIG = {
  evtx:     { timestampColumns: ['TimeCreated', 'SystemTime'], descriptionColumns: ['MapDescription', 'PayloadData1'], sourceColumn: 'Channel',        hostColumns: ['Computer', 'HostName', 'host'], eventIdColumn: 'EventId' },
  prefetch: { timestampColumns: ['LastRun', 'SourceCreated', 'SourceModified'], descriptionColumns: ['ExecutableName'], sourceColumn: 'SourceFilename', hostColumns: ['Computer', 'HostName', 'host'], eventIdColumn: null },
  mft:      { timestampColumns: ['Created0x10', 'Created0x30', 'LastModified0x10', 'LastAccess0x10'], descriptionColumns: ['FileName'], sourceColumn: 'ParentPath', hostColumns: ['Computer', 'HostName', 'host'], eventIdColumn: null },
  sqle:     { timestampColumns: ['LastVisitDate', 'VisitDate', 'StartTime'], descriptionColumns: ['Title', 'URL'], sourceColumn: 'SourceFile', hostColumns: ['Computer', 'HostName', 'host'], eventIdColumn: null },
  syslog:       { timestampColumns: ['Timestamp'], descriptionColumns: ['Message'], sourceColumn: 'Program',       hostColumns: ['HostName'],     eventIdColumn: null },
  bash_history: { timestampColumns: ['Timestamp'], descriptionColumns: ['Command'], sourceColumn: 'SourceFile',    hostColumns: [],               eventIdColumn: null },
  webcache:     { timestampColumns: ['AccessedTime', 'ModifiedTime'], descriptionColumns: ['Url'], sourceColumn: 'ContainerType', hostColumns: ['ComputerName'], eventIdColumn: null },
  pcap:         { timestampColumns: ['first_seen', 'last_seen'], descriptionColumns: [], sourceColumn: 'protocol', hostColumns: [], eventIdColumn: null,
                 describe: (r) => `${r.src_ip}:${r.src_port} → ${r.dst_ip}:${r.dst_port} ${r.protocol}` },
};

module.exports = { stripNullBytes, normalizeTimestamp, extractTimestamp, extractDescription, computeDedupeHash, TIMELINE_FIELD_CONFIG };
