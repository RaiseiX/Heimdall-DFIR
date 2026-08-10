// The CatScale artifacts whose format is genuinely singular — network
// configuration and the localised account check. Everything whose shape repeats
// is handled by catscaleShapeParsers and declared in catscaleArtifactRegistry.

export interface NetInterface {
  index: number;
  name: string;
  flags: string[];
  mtu: number | null;
  state: string;
  mac: string | null;
  addresses: string[];
  promiscuous: boolean;
}

/**
 * `ip a` — an interface header line, then indented link/inet/inet6 lines that
 * belong to it.
 *
 * PROMISC in the flags means the interface accepts frames not addressed to it:
 * on a server that is a packet capture running, which is worth an analyst's
 * attention on its own.
 */
export function parseIpAddr(content: string): NetInterface[] {
  const out: NetInterface[] = [];
  let current: NetInterface | null = null;

  for (const raw of content.split('\n')) {
    if (!raw.trim()) continue;

    const head = /^(\d+):\s+([^:@]+)[:@]/.exec(raw);
    if (head) {
      const flags = /<([^>]*)>/.exec(raw)?.[1].split(',').filter(Boolean) ?? [];
      const mtu = /\bmtu\s+(\d+)/.exec(raw)?.[1];
      current = {
        index: Number(head[1]),
        name: head[2].trim(),
        flags,
        mtu: mtu ? Number(mtu) : null,
        state: /\bstate\s+(\S+)/.exec(raw)?.[1] ?? '',
        mac: null,
        addresses: [],
        promiscuous: flags.includes('PROMISC'),
      };
      out.push(current);
      continue;
    }

    if (!current) continue; // indented content with no interface header above it
    const link = /^\s+link\/\S+\s+([0-9a-f:]{11,})/i.exec(raw);
    if (link) { current.mac = link[1]; continue; }
    const addr = /^\s+inet6?\s+(\S+)/.exec(raw);
    if (addr) current.addresses.push(addr[1]);
  }
  return out;
}

export interface Route {
  destination: string;
  via: string | null;
  dev: string | null;
  table: string | null;
  proto: string | null;
  scope: string | null;
  src: string | null;
  metric: string | null;
}

const routeField = (line: string, key: string): string | null =>
  new RegExp(`\\b${key}\\s+(\\S+)`).exec(line)?.[1] ?? null;

/** `ip route show table all` — "unicast <dest> via <gw> dev <if> table <t> …". */
export function parseRouteTable(content: string): Route[] {
  const out: Route[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    // The route type prefix (unicast, local, broadcast…) is optional.
    const m = /^(?:unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole)?\s*(default|[0-9a-f.:/]+)\s/i.exec(t + ' ');
    if (!m) continue;
    out.push({
      destination: m[1],
      via: routeField(t, 'via'),
      dev: routeField(t, 'dev'),
      table: routeField(t, 'table'),
      proto: routeField(t, 'proto'),
      scope: routeField(t, 'scope'),
      src: routeField(t, 'src'),
      metric: routeField(t, 'metric'),
    });
  }
  return out;
}

export interface IptablesRule {
  num: string; packets: string; bytes: string; target: string;
  protocol: string; in_if: string; out_if: string;
  source: string; destination: string; detail: string;
}
export interface IptablesChain { chain: string; policy: string | null; rules: IptablesRule[] }

/** `iptables -L -n -v --line-numbers` — chains, their policy and their rules. */
export function parseIptables(content: string): IptablesChain[] {
  const out: IptablesChain[] = [];
  let current: IptablesChain | null = null;

  for (const raw of content.split('\n')) {
    const t = raw.trim();
    if (!t) continue;

    const head = /^Chain\s+(\S+)\s*(?:\(policy\s+(\S+)|.*)/.exec(t);
    if (head) {
      current = { chain: head[1], policy: head[2] ?? null, rules: [] };
      out.push(current);
      continue;
    }
    if (!current) continue;
    if (/^num\s+pkts\s+bytes/.test(t)) continue; // column header

    const p = t.split(/\s+/);
    if (p.length < 9) continue;
    current.rules.push({
      num: p[0], packets: p[1], bytes: p[2], target: p[3],
      protocol: p[4], in_if: p[6], out_if: p[7],
      source: p[8], destination: p[9] ?? '',
      detail: p.slice(10).join(' '),
    });
  }
  return out;
}

/**
 * When the collection was taken — the anchor for every artifact that carries no
 * timestamp of its own (process list, sockets, persistence).
 *
 * `date` follows the collected host's locale, and a real collection reads
 * "Date : jeu. 30 juil. 2026 12:44:06 +00:00". new Date() only knows English
 * month names, so it returns Invalid Date and the previous code silently kept
 * the parse time instead — anchoring hundreds of events four days after the
 * facts, with no error anywhere.
 *
 * Three sources, most precise first:
 *   1. the content, if a Date parser can read it (ISO, English);
 *   2. the numeric time and UTC offset from the content — locale-independent —
 *      combined with the date Cat-Scale puts in the filename;
 *   3. the filename stamp alone, `<host>-YYYYMMDD-HHMM-<artifact>`.
 * A collection cannot have happened after it was parsed, so the result is capped.
 */
export function resolveCollectionTime(content: string, fileName: string, fallback: Date): Date {
  const dtg = /(?:^|-)(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(?=-|\.|$)/.exec(fileName);
  const cap = (d: Date) => (d.getTime() > fallback.getTime() ? fallback : d);

  const value = /Date\s*:\s*(.+)/.exec(content ?? '')?.[1]?.trim();

  if (value) {
    const direct = new Date(value);
    if (!isNaN(direct.getTime())) return cap(direct);

    // Locale-independent salvage: the digits are the same in every language.
    const time = /(\d{1,2}):(\d{2}):(\d{2})/.exec(value);
    const offset = /([+-]\d{2}):?(\d{2})(?!\d)/.exec(value);
    if (time && dtg) {
      const off = offset ? `${offset[1]}:${offset[2]}` : 'Z';
      const iso = `${dtg[1]}-${dtg[2]}-${dtg[3]}T`
        + `${time[1].padStart(2, '0')}:${time[2]}:${time[3]}${off}`;
      const built = new Date(iso);
      if (!isNaN(built.getTime())) return cap(built);
    }
  }

  if (dtg) {
    const built = new Date(`${dtg[1]}-${dtg[2]}-${dtg[3]}T${dtg[4]}:${dtg[5]}:00Z`);
    if (!isNaN(built.getTime())) return cap(built);
  }

  return fallback;
}

export interface PasswdCheckEntry { user: string; path: string | null; message: string }

/**
 * `pwck` output, which follows the collector's locale — the real collection is in
 * French, an English host words it differently. Matching on either wording fails
 * silently on the other, so only the quoted values are read and the original line
 * is kept verbatim.
 */
export function parsePasswdCheck(content: string): PasswdCheckEntry[] {
  const out: PasswdCheckEntry[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const quoted = [...t.matchAll(/'([^']+)'/g)].map(m => m[1]);
    if (!quoted.length) continue;
    const user = quoted[0];
    const path = quoted.slice(1).find(q => q.startsWith('/')) ?? null;
    out.push({ user, path, message: t });
  }
  return out;
}
