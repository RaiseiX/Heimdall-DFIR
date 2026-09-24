// /var/log/dpkg.log and /var/log/apt/history.log, from inside var-log.tar.gz.
//
// Neither was read before 2026-08-17. The archive walk filtered on auth.log,
// secure, messages and syslog — none of which exist on this host, because Debian
// 13 logs authentication to the systemd journal. That filter is why a complete
// /var/log yielded four events.
//
// What is here instead is a software installation timeline: 1,961 dpkg operations
// and 54 apt transactions, each timestamped, each naming the package and — for
// apt — the command line and the user who ran it. Attacker tooling arrives
// through exactly this channel, and a package removed to cover a trace is
// recorded here too.

export interface DpkgOp {
  ts: string;
  action: string;
  pkg?: string;
  from?: string;
  to?: string;
}

/** "<date> <time> <action> <pkg> <from> <to>", the dpkg status log. */
export function parseDpkgLogLines(content: string): DpkgOp[] {
  const out: DpkgOp[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const m = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+)(?: (.*))?$/.exec(t);
    if (!m) continue;
    const [, ts, action, rest] = m;
    const parts = (rest ?? '').split(/\s+/).filter(Boolean);
    const op: DpkgOp = { ts, action };
    // `status` lines carry a state word before the package; the others do not.
    const fields = action === 'status' ? parts.slice(1) : parts;
    if (fields[0]) op.pkg = fields[0];
    if (fields[1]) op.from = fields[1];
    if (fields[2]) op.to = fields[2];
    out.push(op);
  }
  return out;
}

export interface AptTransaction {
  ts: string;
  commandline?: string;
  requested_by?: string;
  install?: string;
  upgrade?: string;
  remove?: string;
  purge?: string;
  end?: string;
}

const FIELD: Record<string, keyof AptTransaction> = {
  'commandline': 'commandline',
  'requested-by': 'requested_by',
  'install': 'install',
  'upgrade': 'upgrade',
  'remove': 'remove',
  'purge': 'purge',
  'end-date': 'end',
};

/**
 * apt history.log: blocks introduced by Start-Date. A block without a Start-Date
 * is discarded rather than dated from its neighbour — an invented timestamp on a
 * package installation is worse than a missing one.
 */
export function parseAptHistoryBlocks(content: string): AptTransaction[] {
  const out: AptTransaction[] = [];
  let current: AptTransaction | null = null;

  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) { current = null; continue; }
    const m = /^([A-Za-z-]+):\s*(.*)$/.exec(t);
    if (!m) continue;
    const key = m[1].toLowerCase();
    if (key === 'start-date') {
      current = { ts: m[2].trim() };
      out.push(current);
      continue;
    }
    if (!current) continue;
    const field = FIELD[key];
    if (field) (current as any)[field] = m[2].trim();
  }
  return out;
}
