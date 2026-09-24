// One line of `last` output, turned into one timeline event.
//
// Extracted from parseLastWtmp so the mapping can be tested against the 130 real
// lines of the reference collection instead of only through a database, and so
// `last -f btmp` can reuse it: btmp is the same format, read with the same tool,
// and only the meaning of a row differs. Writing a second parser for it would have
// been a second parser to keep correct.
//
// Two defects measured on that real file and fixed here:
//
//   1. `if (prefix.length < 2) continue` dropped every session with no tty. Two of
//      the 130 lines, and both were sessions that ended in `crash` — precisely the
//      anomaly an analyst is looking for.
//   2. The trailing `/var/log/wtmp.db begins <date>` footer carries a date, so it
//      became a logon for a user called "/var/log/wtmp.db" on a tty called
//      "begins". An event that never happened, in the middle of a logon history.

const TS_RE = /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/;
const LOGOUT_RE = /-\s+(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})/;
const FOOTER_RE = /^\S*\b(?:wtmp|btmp|utmp)\S*\s+(?:begins\b|has no entries)/i;
const SYSTEM_USERS = new Set(['reboot', 'shutdown', 'runlevel']);

const MONTHS: Record<string, number> = {
  Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6,
  Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12,
};

export type LastVariant = 'logon' | 'failed';

export interface LastContext {
  caseId: string;
  hostname: string;
  source: string;
  /** From the `host-date-timezone` artifact. `last` renders local wall-clock time
   *  with no offset, exactly like `dmesg -T`; reading it as UTC is right only on a
   *  UTC host and two hours wrong on a European one. Null keeps the historical
   *  behaviour rather than guessing. */
  hostOffset: string | null;
}

export interface LastRow {
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
  if (!a) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return a.split('.').every(o => +o <= 255) ? a : null;
  if (/^[0-9a-f:]+$/i.test(a) && a.includes(':')) return a;
  return null;
}

function endedHow(rest: string): string | null {
  if (/still logged in|still running/.test(rest)) return null;
  if (/\bcrash\b/.test(rest)) return 'crash';
  if (/\bdown\b/.test(rest)) return 'down';
  if (/\bgone - no logout\b/.test(rest)) return 'no logout';
  return null;
}

export function lastLineRow(line: string, ctx: LastContext, variant: LastVariant): LastRow | null {
  const raw = String(line ?? '');
  if (!raw.trim()) return null;
  if (FOOTER_RE.test(raw.trim())) return null;
  if (/^(wtmp|btmp|utmp)\b/.test(raw)) return null;

  const m = TS_RE.exec(raw);
  if (!m) return null;
  const month = MONTHS[m[1]];
  if (!month) return null;

  const prefix = raw.slice(0, m.index).trim().split(/\s+/).filter(Boolean);
  if (!prefix.length) return null;

  const user = prefix[0];
  const tty = prefix[1] ?? '';
  const from = prefix[2] && !/^\d{4}-/.test(prefix[2]) ? prefix[2] : '';

  const zone = ctx.hostOffset ?? 'Z';
  const iso = `${m[6]}-${String(month).padStart(2, '0')}-${m[2].padStart(2, '0')}T${m[3]}:${m[4]}:${m[5]}${zone}`;
  const timestamp = new Date(iso);
  if (Number.isNaN(timestamp.getTime())) return null;

  const rest = raw.slice(m.index + m[0].length);
  const stillLogged = /still logged in|still running/.test(rest);
  const ended = endedHow(rest);
  const duration = /\(([^)]+)\)/.exec(rest)?.[1] ?? null;
  const logout = LOGOUT_RE.exec(rest)?.[1] ?? null;
  const isSystem = SYSTEM_USERS.has(user) || tty === 'system';

  let description: string;
  if (variant === 'failed') {
    description = `Échec d'authentification: ${user}${tty ? ` via ${tty}` : ''}${from ? ` depuis ${from}` : ''}`;
  } else if (isSystem) {
    description = `Reboot/shutdown: ${from || tty}`;
  } else if (stillLogged) {
    description = `Connexion active: ${user}${tty ? ` via ${tty}` : ''}${from ? ` depuis ${from}` : ''}`;
  } else {
    const suffix = ended ? ` (fin: ${ended})` : (duration ? ` (durée: ${duration})` : '');
    description = `Logon: ${user}${tty ? ` via ${tty}` : ''}${from ? ` depuis ${from}` : ''}${suffix}`;
  }

  return {
    case_id: ctx.caseId,
    timestamp,
    artifact_type: variant === 'failed' ? 'catscale_failed_login' : 'catscale_logon',
    artifact_name: variant === 'failed'
      ? 'Linux Failed Logon'
      : (isSystem ? 'Linux System Event' : 'Linux Logon History'),
    source: ctx.source,
    description,
    raw: {
      user, tty, from,
      login_time: m[0],
      logout_time: logout,
      still_logged: stillLogged,
      ended,
      duration,
      type: variant === 'failed' ? 'failed_login' : (isSystem ? 'system_event' : 'logon'),
      host: ctx.hostname,
    },
    host_name: ctx.hostname,
    user_name: isSystem && variant !== 'failed' ? null : user,
    timestamp_kind: variant === 'failed' ? 'login_failed' : (isSystem ? 'system' : 'login'),
    src_ip: from ? inet(from) : null,
  };
}
