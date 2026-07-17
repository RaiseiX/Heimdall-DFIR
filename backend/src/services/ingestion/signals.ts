// backend/src/services/ingestion/signals.ts
export type SignalHit = {
  source: 'magic' | 'path' | 'sniff';
  detectedType: string;
  parser: string;
  weight: number;   // 0-100 confidence contribution of this signal alone
  reason: string;
};

// Magic-byte signatures — the anti-fragile layer (survives renames).
const MAGIC: Array<{ type: string; parser: string; test: (b: Buffer) => boolean; reason: string }> = [
  { type: 'mft',    parser: 'mft',    reason: 'MFT FILE0 signature',   test: b => b.slice(0, 5).toString('binary') === 'FILE0' },
  { type: 'evtx',   parser: 'evtx',   reason: 'EVTX ElfFile signature',test: b => b.slice(0, 7).toString('binary') === 'ElfFile' },
  { type: 'sqlite', parser: 'sqle',   reason: 'SQLite header',         test: b => b.slice(0, 15).toString('binary') === 'SQLite format 3' },
  { type: 'esedb',  parser: 'webcache', reason: 'ESE database header',  test: b => b.length > 8 && b.readUInt32LE(4) === 0x89abcdef },
  { type: 'pcap',   parser: 'pcap',   reason: 'PCAP magic',            test: b => [0xa1b2c3d4, 0xd4c3b2a1].includes(b.length >= 4 ? b.readUInt32BE(0) : 0) },
];

export function detectMagic(header: Buffer): SignalHit | null {
  for (const m of MAGIC) {
    try { if (m.test(header)) return { source: 'magic', detectedType: m.type, parser: m.parser, weight: 90, reason: m.reason }; }
    catch { /* short buffer — skip this signature, never throw */ }
  }
  return null;
}

// Path/name patterns — migrate from collection.js ARTIFACT_PATTERNS as coverage grows.
const PATHS: Array<{ type: string; parser: string; re: RegExp }> = [
  { type: 'evtx',      parser: 'evtx',      re: /\.evtx$/i },
  { type: 'prefetch',  parser: 'prefetch',  re: /\.pf$/i },
  { type: 'mft',       parser: 'mft',       re: /(^|\/)\$MFT$/i },
  { type: 'pcap',      parser: 'pcap',      re: /\.pcapn?g?$/i },
  { type: 'bash',      parser: 'bash_history', re: /(^|\/)\.bash_history$/i },
  { type: 'syslog',    parser: 'syslog',    re: /(^|\/)(syslog|messages)(\.\d+)?$/i },
];

export function detectPath(relativePath: string): SignalHit | null {
  for (const p of PATHS) {
    if (p.re.test(relativePath)) return { source: 'path', detectedType: p.type, parser: p.parser, weight: 60, reason: `path matches ${p.re}` };
  }
  return null;
}

// Content sniff — last resort for generic tabular/JSON exports.
export function detectSniff(header: Buffer): SignalHit | null {
  const text = header.slice(0, 2048).toString('utf8');
  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  if (/,/.test(firstLine) && firstLine.split(',').length >= 2 && /[a-zA-Z]/.test(firstLine)) {
    return { source: 'sniff', detectedType: 'csv', parser: 'sqle', weight: 40, reason: 'looks like CSV header row' };
  }
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return { source: 'sniff', detectedType: 'json', parser: 'sqle', weight: 40, reason: 'looks like JSON' };
  }
  return null;
}
