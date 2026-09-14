// utmpdump(1) and lastlog(8) output, one record per line.
//
// RESERVE: unlike the dmesg, container-log and `last` parsers, these two are NOT
// validated against real evidence. `last-utmpdump.txt` and `lastlog.txt` are both
// zero bytes on the reference collection, so the tests exercise the documented
// formats only. Re-run them against the first collection that actually carries
// these files before trusting a count drawn from them.
//
// They are written anyway because the artifacts are in Cat-Scale's catalogue and a
// declared-but-unparsed artifact is exactly the silent gap this whole effort exists
// to close: an empty file today is not an empty file on the next host.

export const UTMP_TYPES: Record<number, string> = {
  0: 'EMPTY',
  1: 'RUN_LVL',
  2: 'BOOT_TIME',
  3: 'NEW_TIME',
  4: 'OLD_TIME',
  5: 'INIT_PROCESS',
  6: 'LOGIN_PROCESS',
  7: 'USER_PROCESS',
  8: 'DEAD_PROCESS',
};

const SYSTEM_TYPES = new Set([1, 2, 3, 4]);

export interface UtmpContext {
  caseId: string;
  hostname: string;
  source: string;
}

export interface UtmpRow {
  case_id: string;
  timestamp: Date;
  artifact_type: string;
  artifact_name: string;
  source: string;
  description: string;
  raw: Record<string, unknown>;
  host_name: string;
  user_name: string | null;
  timestamp_kind: string;
  src_ip: string | null;
}

function inet(value: string): string | null {
  const a = value.trim().split('%')[0];
  if (!a || a === '0.0.0.0' || a === '[0.0.0.0]') return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return a.split('.').every(o => +o <= 255) ? a : null;
  if (/^[0-9a-f:]+$/i.test(a) && a.includes(':')) return a;
  return null;
}

// utmpdump writes the time as 2026-07-30T12:44:06,123456+00:00 — a comma before
// the microseconds, and its own offset. The offset being present is why this
// parser needs no host timezone, unlike `last` and `dmesg -T`.
function utmpTime(raw: string): Date | null {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})[.,](\d{1,6})\s*([+-]\d{2}:?\d{2}|Z)?$/.exec(raw.trim());
  if (!m) return null;
  const millis = m[2].padEnd(6, '0').slice(0, 3);
  const zone = !m[3] ? 'Z' : (m[3] === 'Z' ? 'Z' : (m[3].includes(':') ? m[3] : `${m[3].slice(0, 3)}:${m[3].slice(3)}`));
  const at = new Date(`${m[1]}.${millis}${zone}`);
  return Number.isNaN(at.getTime()) ? null : at;
}

export function utmpDumpRow(line: string, ctx: UtmpContext): UtmpRow | null {
  const raw = String(line ?? '').trim();
  if (!raw.startsWith('[')) return null;

  const fields = [...raw.matchAll(/\[([^\]]*)\]/g)].map(m => m[1].trim());
  if (fields.length < 8) return null;

  const [typeRaw, pid, id, user, tty, host, addr, timeRaw] = fields;
  const type = Number(typeRaw);
  if (!Number.isFinite(type)) return null;

  const timestamp = utmpTime(timeRaw);
  if (!timestamp) return null;

  const typeName = UTMP_TYPES[type] ?? String(type);
  const isSystem = SYSTEM_TYPES.has(type);
  const isDead = type === 8;

  const description = isSystem
    ? `Événement système (${typeName})${host ? `: ${host}` : ''}`
    : isDead
      ? `Session fermée (DEAD_PROCESS)${tty ? ` sur ${tty}` : ''}`
      : `${typeName}: ${user || '(sans utilisateur)'}${tty ? ` via ${tty}` : ''}${host ? ` depuis ${host}` : ''}`;

  return {
    case_id: ctx.caseId,
    timestamp,
    artifact_type: 'catscale_utmp',
    artifact_name: isSystem ? 'Linux System Event' : 'Linux Session Record',
    source: ctx.source,
    description,
    raw: { type, type_name: typeName, pid, id, user, line: tty, host, addr, time: timeRaw },
    host_name: ctx.hostname,
    user_name: isSystem || !user ? null : user,
    timestamp_kind: isSystem ? 'system' : 'utmp',
    src_ip: inet(addr) ?? inet(host),
  };
}

const LASTLOG_TS_RE = /(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+([+-]\d{4}|\w+)\s+(\d{4})\s*$/;
const MONTHS: Record<string, number> = {
  Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6,
  Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12,
};

export function lastlogRow(line: string, ctx: UtmpContext): UtmpRow | null {
  const raw = String(line ?? '').trim();
  if (!raw) return null;
  if (/^Username\s+Port\s+From\s+Latest/.test(raw)) return null;
  // A "never logged in" account is a fact, not an event: it has no time, so it has
  // no place on a chronology. Recording it with a fabricated date would be worse
  // than leaving it to the inventory that already lists the account.
  if (/\*\*Never logged in\*\*/i.test(raw)) return null;

  const m = LASTLOG_TS_RE.exec(raw);
  if (!m) return null;
  const month = MONTHS[m[2]];
  if (!month) return null;

  const zone = /^[+-]\d{4}$/.test(m[5]) ? `${m[5].slice(0, 3)}:${m[5].slice(3)}` : 'Z';
  const at = new Date(`${m[6]}-${String(month).padStart(2, '0')}-${m[3].padStart(2, '0')}T${m[4]}${zone}`);
  if (Number.isNaN(at.getTime())) return null;

  const prefix = raw.slice(0, m.index).trim().split(/\s+/).filter(Boolean);
  if (!prefix.length) return null;
  const [user, port, from] = prefix;

  return {
    case_id: ctx.caseId,
    timestamp: at,
    artifact_type: 'catscale_lastlog',
    artifact_name: 'Linux Last Login',
    source: ctx.source,
    description: `Dernière connexion: ${user}${port ? ` via ${port}` : ''}${from ? ` depuis ${from}` : ''}`,
    raw: { user, port: port ?? '', from: from ?? '', latest: m[0].trim() },
    host_name: ctx.hostname,
    user_name: user,
    timestamp_kind: 'lastlog',
    src_ip: from ? inet(from) : null,
  };
}
