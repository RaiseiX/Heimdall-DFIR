// Reads the systemd journal — the single largest gap in Linux coverage.
//
// Measured on the reference collection (Dlinux-20260730-1444): 41 binary files,
// 1.1 GB expanded, 1,827,042 entries spanning 2026-04-02 to 2026-07-30. More rows
// than all of catscale_state put together, and none of them were read. On a modern
// host, authentication, sudo, SSH and unit starts live here; what the platform
// parsed instead came from Cat-Scale's separate text exports (last-wtmp, dmesg).
//
// The binary format is NOT reimplemented. The files declare themselves "compressed
// zstd, keyed hash siphash24, compact" — a reimplementation would need the object
// arrays, the hash tables and three compressors, and would drift with every
// systemd release. `journalctl --file` reads them today, foreign machine-id and
// all, which is also what an analyst would reach for. The cost is one package in
// the image; the alternative was a parser we would own forever.
//
// These are events, not inventory, so they take the parseAuditd path straight to
// collection_timeline rather than going through catscale_state. At this volume the
// detour would have doubled the storage for nothing.

export const JOURNAL_FILE_RE = /\.journal~?$/;

export interface JournalContext {
  caseId: string;
  hostname: string;
  source: string;
}

export interface JournalRow {
  case_id: string;
  timestamp: Date;
  artifact_type: string;
  artifact_name: string | null;
  source: string;
  description: string;
  raw: Record<string, unknown>;
  host_name: string | null;
  process_name: string | null;
  path: string | null;
  timestamp_kind: string;
}

// journalctl renders a non-UTF-8 MESSAGE as an array of byte values rather than a
// string. Dropping those would silently lose exactly the entries most likely to
// carry hostile output.
function messageOf(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const bytes = value.filter(b => typeof b === 'number' && b >= 0 && b <= 255) as number[];
    if (bytes.length !== value.length) return '';
    return Buffer.from(bytes).toString('utf8');
  }
  return '';
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null;
}

export function journalRow(entry: Record<string, unknown>, ctx: JournalContext): JournalRow | null {
  const micros = entry.__REALTIME_TIMESTAMP;
  if (typeof micros !== 'string' && typeof micros !== 'number') return null;
  const asNumber = Number(micros);
  if (!Number.isFinite(asNumber) || asNumber <= 0) return null;

  const timestamp = new Date(Math.floor(asNumber / 1000));
  if (Number.isNaN(timestamp.getTime())) return null;

  return {
    case_id: ctx.caseId,
    timestamp,
    artifact_type: 'catscale_journal',
    artifact_name: str(entry.SYSLOG_IDENTIFIER) ?? str(entry._SYSTEMD_UNIT) ?? str(entry._COMM),
    source: ctx.source,
    description: messageOf(entry.MESSAGE),
    raw: { ...entry },
    host_name: str(entry._HOSTNAME) ?? ctx.hostname,
    process_name: str(entry._COMM),
    path: str(entry._EXE),
    timestamp_kind: 'journal',
  };
}

// Streams rather than collecting: 1.8 million entries held in an array before a
// single insert is how an import runs the container out of memory. A malformed
// line is skipped rather than aborting — journalctl output can be cut short by a
// truncated journal, and losing the remaining entries would be worse.
export async function* journalRows(
  lines: AsyncIterable<string>,
  ctx: JournalContext,
): AsyncGenerator<JournalRow> {
  for await (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let doc: unknown;
    try { doc = JSON.parse(trimmed); } catch { continue; }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) continue;
    const row = journalRow(doc as Record<string, unknown>, ctx);
    if (row) yield row;
  }
}
