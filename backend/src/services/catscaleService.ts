
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import os from 'os';
import readline from 'readline';
import { spawnSync } from 'child_process';
import { Pool } from 'pg';

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

function parseBsd(s: string, year: number): Date | null {
  const m = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (!m || MONTHS[m[1]] === undefined) return null;
  const d = new Date(year, MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]);
  if (d > new Date()) d.setFullYear(year - 1);
  return isNaN(d.getTime()) ? null : d;
}

function parseLastTs(s: string): Date | null {

  const m = /(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(s);
  if (!m || MONTHS[m[1]] === undefined) return null;
  const d = new Date(+m[6], MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]);
  return isNaN(d.getTime()) ? null : d;
}

function findFile(dir: string, ...patterns: string[]): string | null {
  if (!fs.existsSync(dir)) return null;
  let entries: string[];
  try { entries = fs.readdirSync(dir); } catch { return null; }
  for (const p of patterns) {
    const found = entries.find(e => e.includes(p));
    if (found) return path.join(dir, found);
  }
  return null;
}

function findFiles(dir: string, ...patterns: string[]): string[] {
  if (!fs.existsSync(dir)) return [];
  let entries: string[];
  try { entries = fs.readdirSync(dir); } catch { return []; }
  return entries
    .filter(e => patterns.some(p => e.includes(p)))
    .map(e => path.join(dir, e));
}

function extractTarGz(archivePath: string, destDir: string): boolean {
  if (!fs.existsSync(archivePath)) return false;
  try { fs.mkdirSync(destDir, { recursive: true }); } catch { return false; }
  const r = spawnSync('tar', ['xzf', archivePath, '-C', destDir], {
    timeout: 300_000,
    maxBuffer: 200 * 1024 * 1024,
  });
  if (r.status !== 0) {
    logger.warn(`[CatScale] tar extract failed (${path.basename(archivePath)}): ${r.stderr?.toString().trim()}`);
    return false;
  }
  return true;
}

async function walkDir(dir: string, cb: (fp: string) => Promise<void>): Promise<void> {
  if (!fs.existsSync(dir)) return;
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const fp = path.join(dir, e.name);
    if (e.isDirectory()) await walkDir(fp, cb);
    else if (e.isFile()) await cb(fp);
  }
}

async function* readLines(filePath: string): AsyncIterable<string> {
  if (!fs.existsSync(filePath)) return;
  const rl = readline.createInterface({ input: fs.createReadStream(filePath), crlfDelay: Infinity });
  for await (const line of rl) yield line;
}

type Row = {
  case_id: string;
  timestamp: Date;
  artifact_type: string;
  source: string;
  description: string;
  raw: Record<string, unknown>;
  host_name?: string | null;
  user_name?: string | null;
};

async function batchInsert(pool: Pool, rows: Row[], resultId: string | null = null): Promise<number> {
  if (!rows.length) return 0;
  let inserted = 0;
  const BATCH = 500;
  for (let i = 0; i < rows.length; i += BATCH) {
    const slice = rows.slice(i, i + BATCH);
    const vals: string[] = [];
    const params: unknown[] = [];
    let idx = 1;
    for (const r of slice) {
      vals.push(`($${idx++},$${idx++},$${idx++},$${idx++},$${idx++},$${idx++},$${idx++},$${idx++},$${idx++})`);
      params.push(
        r.case_id, resultId, r.timestamp.toISOString(), r.artifact_type, r.source,
        r.description, JSON.stringify(r.raw), r.host_name ?? null, r.user_name ?? null,
      );
    }
    try {
      await pool.query(
        `INSERT INTO collection_timeline
           (case_id, result_id, timestamp, artifact_type, source, description, raw, host_name, user_name)
         VALUES ${vals.join(',')}`,
        params,
      );
      inserted += slice.length;
    } catch (e: any) {
      logger.warn('[CatScale] batch insert error:', e.message);
    }
  }
  return inserted;
}

const CATSCALE_MARKER_DIRS = ['Logs', 'Process_and_Network', 'System_Info', 'User_Files', 'Persistence', 'Misc'];

function countMarkers(dir: string): number {
  try { return fs.readdirSync(dir).filter(e => CATSCALE_MARKER_DIRS.includes(e)).length; }
  catch { return 0; }
}

export function findCatScaleRoot(extractDir: string): string | null {
  if (countMarkers(extractDir) >= 2) return extractDir;
  try {
    for (const e of fs.readdirSync(extractDir)) {
      const sub = path.join(extractDir, e);
      try {
        if (fs.statSync(sub).isDirectory() && countMarkers(sub) >= 2) return sub;
      } catch  }
    }
  } catch  }
  return null;
}

const AUTH_PATTERNS_RE = [
  /Accepted (password|publickey|gssapi\S*) for (\S+) from ([\d.:]+)/,
  /Failed (?:password|publickey) for(?: invalid user)? (\S+) from ([\d.:]+)/,
  /Invalid user (\S+) from ([\d.:]+)/,
  /sudo:\s+\S+\s+:\s+TTY=/,
  /pam_unix\(su:session\): session (opened|closed)/,
  /useradd\[|usermod\[|groupadd\[|passwd\[/,
  /session (opened|closed) for user/,
  /Disconnected from.*user/,
  /authentication failure/i,
  /FAILED LOGIN/,
];

async function parseAuthLog(filePath: string, caseId: string, pool: Pool, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];
  const year = new Date().getFullYear();

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;
    if (!AUTH_PATTERNS_RE.some(re => re.test(line))) continue;

    let ts: Date | null = null;
    let msg = line;
    let host = hostname;
    let proc = '';

    const bsd = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$/.exec(line);
    if (bsd) { ts = parseBsd(bsd[1], year); host = bsd[2]; proc = bsd[3]; msg = bsd[4]; }

    const iso = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+(\S+?):\s+(.*)$/.exec(line);
    if (!bsd && iso) {
      ts = new Date(iso[1]); if (isNaN(ts.getTime())) ts = null;
      host = iso[2]; proc = iso[3]; msg = iso[4];
    }
    if (!bsd && !iso) continue;

    let description = msg;
    let username: string | null = null;
    let sourceIp: string | null = null;
    let category = 'auth';

    const accepted = /Accepted (\S+) for (\S+) from ([\d.:]+)/.exec(msg);
    if (accepted) {
      username = accepted[2]; sourceIp = accepted[3];
      description = `SSH Connexion (${accepted[1]}): ${username} depuis ${sourceIp}`;
      category = 'ssh_login';
    }
    const failed = /Failed \S+ for(?:\s+invalid user)? (\S+) from ([\d.:]+)/.exec(msg);
    if (failed) {
      username = failed[1]; sourceIp = failed[2];
      description = `SSH Échec: ${username} depuis ${sourceIp}`;
      category = 'ssh_failed';
    }
    const invalid = /Invalid user (\S+) from ([\d.:]+)/.exec(msg);
    if (invalid) {
      username = invalid[1]; sourceIp = invalid[2];
      description = `SSH Utilisateur invalide: ${username} depuis ${sourceIp}`;
      category = 'ssh_invalid';
    }
    const sudo = /sudo:\s+(\S+)\s+:.*?USER=(\S+).*?COMMAND=(.+)/.exec(msg);
    if (sudo) {
      username = sudo[1];
      description = `SUDO: ${sudo[1]} → ${sudo[2]}: ${sudo[3].trim().substring(0, 120)}`;
      category = 'sudo';
    }
    const su = /pam_unix\(su:session\): session (\S+) for user (\S+)/.exec(msg);
    if (su) {
      username = su[2];
      description = `SU: session ${su[1]} pour ${su[2]}`;
      category = 'su';
    }

    rows.push({
      case_id: caseId, timestamp: ts ?? new Date(),
      artifact_type: 'catscale_auth', source: path.basename(filePath),
      description,
      raw: { line, category, username, source_ip: sourceIp, host, process: proc },
      host_name: host, user_name: username,
    });
  }
  return batchInsert(pool, rows, resultId);
}

const LAST_TS_RE = /\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}/;

async function parseLastWtmp(filePath: string, caseId: string, pool: Pool, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];

  for await (const line of readLines(filePath)) {
    if (!line.trim() || line.startsWith('wtmp') || line.startsWith('btmp')) continue;

    const tsMatch = LAST_TS_RE.exec(line);
    if (!tsMatch) continue;

    const tsIdx = tsMatch.index;
    const prefix = line.substring(0, tsIdx).trim().split(/\s+/).filter(Boolean);
    if (prefix.length < 2) continue;

    const user = prefix[0];
    const tty  = prefix[1];

    const from = prefix[2] && !/^\d{4}-/.test(prefix[2]) ? prefix[2] : '';

    const loginStr = tsMatch[0];
    const loginTs = parseLastTs(loginStr);
    if (!loginTs) continue;

    const rest = line.substring(tsIdx + loginStr.length);

    const isReboot = user === 'reboot' || user === 'shutdown' || user === 'runlevel';
    const type = isReboot ? 'system_event' : (tty === 'system' ? 'system_event' : 'logon');

    const logoutMatch = /- (\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})/.exec(rest);
    const stillLogged = /still logged in|still running/.test(rest);
    const duration = /\(([^)]+)\)/.exec(rest)?.[1];

    let description: string;
    if (isReboot) {
      description = `Reboot/shutdown: ${from}`;
    } else if (stillLogged) {
      description = `Connexion active: ${user} via ${tty}${from ? ` depuis ${from}` : ''}`;
    } else {
      description = `Logon: ${user} via ${tty}${from ? ` depuis ${from}` : ''}${duration ? ` (durée: ${duration})` : ''}`;
    }

    rows.push({
      case_id: caseId, timestamp: loginTs,
      artifact_type: 'catscale_logon',
      source: path.basename(filePath),
      description,
      raw: { user, tty, from, login_time: loginStr, logout_time: logoutMatch?.[1] ?? null, still_logged: stillLogged, duration, type, host: hostname },
      host_name: hostname, user_name: isReboot ? null : user,
    });
  }
  return batchInsert(pool, rows, resultId);
}

async function parseProcessList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];
  let headerLine = '';
  let headerSeen = false;

  for await (const line of readLines(filePath)) {
    if (!headerSeen) {
      if (/\bPID\b/.test(line)) { headerLine = line; headerSeen = true; }
      continue;
    }
    if (!line.trim()) continue;

    let user = '?', pid = '?', command = line.trim();

    if (/PPID/.test(headerLine) && !/CPU/.test(headerLine)) {

      const m = /^(\S+)\s+(\d+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
      if (m) { user = m[1]; pid = m[2]; command = m[3]; }
    } else if (/%CPU/.test(headerLine)) {

      const m = /^(\S+)\s+(\d+)\s+[\d.]+\s+[\d.]+\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
      if (m) { user = m[1]; pid = m[2]; command = m[3]; }
    } else if (/UID/.test(headerLine)) {

      const m = /^(\S+)\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
      if (m) { user = m[1]; pid = m[2]; command = m[3]; }
    } else {

      const m = /^(\S+)\s+(\d+)\s+.+\s+(\/.+|[A-Za-z].+)$/.exec(line);
      if (m) { user = m[1]; pid = m[2]; command = m[3]; }
    }

    if (pid === '?') continue;

    rows.push({
      case_id: caseId, timestamp: t,
      artifact_type: 'catscale_process', source: path.basename(filePath),
      description: `Process [${user}] PID=${pid}: ${command.substring(0, 150)}`,
      raw: { pid: +pid, user, command, host: hostname },
      host_name: hostname, user_name: user,
    });
  }
  return batchInsert(pool, rows, resultId);
}

async function parseNetworkConnections(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;

    if (/^(nl|p_raw|p_dgr|u_str|u_dgr|u_seq)\s/.test(line)) continue;
    const ss = /^(\S+)\s+(ESTAB|LISTEN|CLOSE-WAIT|TIME-WAIT|SYN-SENT|SYN-RECV|FIN-WAIT[12]?|UNCONN|CLOSE|CLOSED)\s+\d+\s+\d+\s+([\S]+)\s+([\S]+)\s*(.*)$/.exec(line);
    if (ss) {
      const [, netid, state, local, peer, rest] = ss;
      const proc = /users:\(\("([^"]+)",pid=(\d+)/.exec(rest);
      const uid = /uid:(\d+)/.exec(rest);
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_network', source: path.basename(filePath),
        description: `${netid.toUpperCase()} ${state}: ${local} ↔ ${peer}${proc ? ` [${proc[1]}]` : ''}`,
        raw: { netid, state, local, peer, process: proc?.[1] ?? null, pid: proc?.[2] ? +proc[2] : null, uid: uid ? +uid[1] : null, host: hostname },
        host_name: hostname,
      });
      continue;
    }

    const netstat = /^(tcp|udp)6?\s+\d+\s+\d+\s+([\d.:\[\]]+:\S+)\s+([\d.:\[\]*]+:\S+)\s+(\S+)/.exec(line);
    if (netstat) {
      const [, proto, local, foreign, state] = netstat;
      if (state === 'TIME_WAIT') continue;
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_network', source: path.basename(filePath),
        description: `${proto.toUpperCase()} ${state}: ${local} ↔ ${foreign}`,
        raw: { proto, local, foreign, state, host: hostname },
        host_name: hostname,
      });
    }
  }
  return batchInsert(pool, rows, resultId);
}


async function parseBashHistory(filePath: string, caseId: string, pool: Pool, t: Date, username: string, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];
  let pendingTs: Date | null = null;

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;
    const tsLine = /^#(\d{10,})$/.exec(line);
    if (tsLine) { pendingTs = new Date(+tsLine[1] * 1000); continue; }

    rows.push({
      case_id: caseId, timestamp: pendingTs ?? t,
      artifact_type: 'catscale_history', source: path.basename(filePath),
      description: `Historique [${username}]: ${line.substring(0, 200)}`,
      raw: { command: line, username, host: hostname },
      host_name: hostname, user_name: username,
    });
    pendingTs = null;
  }
  return batchInsert(pool, rows, resultId);
}


async function parseCronTabList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];
  let currentUser = 'unknown';

  for await (const line of readLines(filePath)) {
    const userHeader = /crontab(?:s)? for (?:user:?\s*)?(\S+)/i.exec(line);
    if (userHeader) { currentUser = userHeader[1].replace(':', ''); continue; }
    if (line.startsWith('#') || !line.trim()) continue;

    if (/^(@\w+|\*|[-\d,\/]+)\s/.test(line.trim())) {
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_persistence', source: 'crontab',
        description: `Cron [${currentUser}]: ${line.trim().substring(0, 200)}`,
        raw: { cron_entry: line.trim(), user: currentUser, host: hostname },
        host_name: hostname, user_name: currentUser,
      });
    }
  }
  return batchInsert(pool, rows, resultId);
}


async function parseSystemdList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];

  for await (const line of readLines(filePath)) {
    const m1 = /^\s*(\S+\.service)\s+\S+\s+(active|failed)\s+(\S+)\s+(.*)$/.exec(line);
    if (m1) {
      const [, unit, active, sub, desc] = m1;
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_persistence', source: 'systemd',
        description: `Service ${active === 'failed' ? '⚠ FAILED' : 'actif'}: ${unit} (${sub}) — ${desc.trim().substring(0, 100)}`,
        raw: { unit, active, sub, description: desc.trim(), host: hostname },
        host_name: hostname,
      });
      continue;
    }
    const m2 = /^\s*(\S+\.service)\s+(enabled|disabled|masked|static|alias|indirect|generated)\s/.exec(line);
    if (m2) {
      const [, unit, state] = m2;
      if (['masked', 'disabled'].includes(state) && !unit.startsWith('ssh') && !unit.startsWith('cron')) continue; // skip noise
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_persistence', source: 'systemd-unit-files',
        description: `Service [${state}]: ${unit}`,
        raw: { unit, state, host: hostname },
        host_name: hostname,
      });
    }
  }
  return batchInsert(pool, rows, resultId);
}


const SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/', '/home/', '/root/', '/etc/'];
const SUSPICIOUS_EXT_RE = /\.(sh|py|pl|rb|php|jsp|php\d?|cgi|exe|elf|so)$/i;

async function parseFsTimeline(filePath: string, caseId: string, pool: Pool, hostname: string, resultId: string | null = null): Promise<number> {
  const rows: Row[] = [];
  let headerSeen = false;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 90); // only last 90 days of activity

  for await (const line of readLines(filePath)) {
    if (!headerSeen) { headerSeen = true; continue; } // skip CSV header
    if (!line.trim()) continue;

    const parts = line.split(',');
    if (parts.length < 11) continue;

    const fullPath = parts[2];
    const lastMod = parts[4];
    const user = parts[7];
    const perms = parts[9];

    if (!fullPath || fullPath === '-') continue;

    const isSuspiciousPath = SUSPICIOUS_PATHS.some(p => fullPath.startsWith(p));
    const isSuspiciousExt = SUSPICIOUS_EXT_RE.test(fullPath);
    let modTs: Date | null = null;
    if (lastMod && lastMod !== '-') {
      modTs = new Date(lastMod.trim());
      if (isNaN(modTs.getTime())) modTs = null;
    }
    const isRecent = modTs && modTs >= cutoff;

    if (!isSuspiciousPath && !isSuspiciousExt && !isRecent) continue;

    const ts = modTs ?? new Date();
    rows.push({
      case_id: caseId, timestamp: ts,
      artifact_type: 'catscale_fstimeline', source: 'full-timeline.csv',
      description: `${perms} [${user}] ${fullPath}`,
      raw: { path: fullPath, last_modified: lastMod, permissions: perms, user, host: hostname },
      host_name: hostname, user_name: user !== 'root' ? user : null,
    });

    if (rows.length >= 1000) {
      await batchInsert(pool, rows.splice(0), resultId);
    }
  }
  return batchInsert(pool, rows, resultId);
}


export interface CatScaleParseResult {
  events: number;
  hostname: string;
  os_info: string;
  collection_time: string;
  artifacts: string[];
}

export async function parseCatScale(
  catscaleRoot: string,
  caseId: string,
  pool: Pool,
  collectionTime: Date,
  emitProgress?: (p: Record<string, unknown>) => void,
  resultId: string | null = null,
): Promise<CatScaleParseResult> {
  let totalEvents = 0;
  const artifacts: string[] = [];
  const tempDirs: string[] = [];

  const emit = (step: string) =>
    emitProgress?.({ type: 'catscale_step', step, artifact: 'catscale' });

  let hostname = 'linux-host';
  let osInfo = '';
  const sysDir = path.join(catscaleRoot, 'System_Info');
  const dateFile = findFile(sysDir, 'host-date-timezone');
  if (dateFile) {
    const content = fs.readFileSync(dateFile, 'utf8');
    const dateLine = content.split('\n')[0];
    const tsMatch = /Date\s*:\s*(.+)/.exec(dateLine);
    if (tsMatch) {
      const parsed = new Date(tsMatch[1]);
      if (!isNaN(parsed.getTime())) collectionTime = parsed;
    }
    const base = path.basename(dateFile);
    const parts = base.split('-');
    hostname = parts[0] || hostname;
  }
  const releaseFile = findFile(sysDir, 'release');
  if (releaseFile) {
    const releaseContent = fs.readFileSync(releaseFile, 'utf8');
    const pretty = /PRETTY_NAME="([^"]+)"/.exec(releaseContent);
    osInfo = pretty?.[1] ?? releaseContent.split('\n')[0] ?? '';
  }

  emit('auth_logs');
  const logsDir = path.join(catscaleRoot, 'Logs');
  const varLogTar = findFile(logsDir, 'var-log.tar.gz');
  if (varLogTar) {
    const varLogTmp = path.join(os.tmpdir(), `catscale-varlog-${caseId}-${Date.now()}`);
    tempDirs.push(varLogTmp);
    if (extractTarGz(varLogTar, varLogTmp)) {
      await walkDir(varLogTmp, async (fp) => {
        const base = path.basename(fp);
        if (/^(auth\.log|secure|messages|syslog)(\.1)?$/.test(base)) {
          const n = await parseAuthLog(fp, caseId, pool, hostname, resultId).catch(() => 0);
          if (n > 0) { totalEvents += n; artifacts.push(`auth:${base} (${n})`); }
        }
      });
    }
  }

  emit('logon_history');
  for (const pat of ['last-wtmp', 'last-utmp']) {
    const fp = findFile(logsDir, pat);
    if (fp) {
      const n = await parseLastWtmp(fp, caseId, pool, hostname, resultId).catch(() => 0);
      if (n > 0) { totalEvents += n; artifacts.push(`logon:${path.basename(fp)} (${n})`); }
    }
  }

  const btmpFile = findFile(logsDir, 'last-btmp');
  if (btmpFile) {
    const n = await parseLastWtmp(btmpFile, caseId, pool, hostname, resultId).catch(() => 0);
    if (n > 0) { totalEvents += n; artifacts.push(`failed_logon:${path.basename(btmpFile)} (${n})`); }
  }

  emit('processes');
  const procDir = path.join(catscaleRoot, 'Process_and_Network');
  const procFile = findFile(procDir, 'processes-axwwSo', 'processes-auxSww', 'processes-auxww', 'processes-eF', 'processes-ef', 'processes-e');
  if (procFile) {
    const n = await parseProcessList(procFile, caseId, pool, collectionTime, hostname, resultId).catch(() => 0);
    if (n > 0) { totalEvents += n; artifacts.push(`process:${path.basename(procFile)} (${n})`); }
  }

  emit('network');
  for (const pat of ['ss-anepo', 'netstat-pvWanoee', 'netstat-pvTanoee', 'netstat-antup', 'netstat-an']) {
    const fp = findFile(procDir, pat);
    if (fp) {
      const n = await parseNetworkConnections(fp, caseId, pool, collectionTime, hostname, resultId).catch(() => 0);
      if (n > 0) { totalEvents += n; artifacts.push(`network:${path.basename(fp)} (${n})`); }
    }
  }

  emit('history');
  const userFilesDir = path.join(catscaleRoot, 'User_Files');
  const homeTar = path.join(userFilesDir, 'hidden-user-home-dir.tar.gz');
  if (fs.existsSync(homeTar)) {
    const homeTmp = path.join(os.tmpdir(), `catscale-home-${caseId}-${Date.now()}`);
    tempDirs.push(homeTmp);
    if (extractTarGz(homeTar, homeTmp)) {
      await walkDir(homeTmp, async (fp) => {
        const base = path.basename(fp);
        if (/^\.?(bash_history|zsh_history|sh_history|fish_history|ksh_history|history)$/.test(base)) {

          const parts = fp.split(path.sep);
          const username = parts[parts.length - 2] || 'unknown';
          const n = await parseBashHistory(fp, caseId, pool, collectionTime, username, hostname, resultId).catch(() => 0);
          if (n > 0) { totalEvents += n; artifacts.push(`history:${username}:${base} (${n})`); }
        }
      });
    }
  }

  emit('persistence');
  const persistDir = path.join(catscaleRoot, 'Persistence');

  const cronTabList = findFile(persistDir, 'cron-tab-list');
  if (cronTabList) {
    const n = await parseCronTabList(cronTabList, caseId, pool, collectionTime, hostname, resultId).catch(() => 0);
    if (n > 0) { totalEvents += n; artifacts.push(`cron:cron-tab-list (${n})`); }
  }

  const cronFolderTar = findFile(persistDir, 'cron-folder.tar.gz');
  if (cronFolderTar) {
    const cronTmp = path.join(os.tmpdir(), `catscale-cron-${caseId}-${Date.now()}`);
    tempDirs.push(cronTmp);
    if (extractTarGz(cronFolderTar, cronTmp)) {
      await walkDir(cronTmp, async (fp) => {
        const base = path.basename(fp);
        if (!base.includes('.') || base.endsWith('.txt')) {
          const n = await parseCronTabList(fp, caseId, pool, collectionTime, hostname, resultId).catch(() => 0);
          if (n > 0) { totalEvents += n; artifacts.push(`cron:spool:${base} (${n})`); }
        }
      });
    }
  }

  for (const pat of ['systemctl_service_status', 'systemctl_all', 'persistence-systemdlist']) {
    const fp = findFile(persistDir, pat);
    if (fp) {
      const n = await parseSystemdList(fp, caseId, pool, collectionTime, hostname, resultId).catch(() => 0);
      if (n > 0) { totalEvents += n; artifacts.push(`systemd:${path.basename(fp)} (${n})`); }
    }
  }

  emit('fstimeline');
  const miscDir = path.join(catscaleRoot, 'Misc');
  const fsTimelineFile = findFile(miscDir, 'full-timeline.csv');
  if (fsTimelineFile) {
    const n = await parseFsTimeline(fsTimelineFile, caseId, pool, hostname, resultId).catch((e) => {
      logger.warn('[CatScale] fstimeline parse error:', e.message); return 0;
    });
    if (n > 0) { totalEvents += n; artifacts.push(`fstimeline:${path.basename(fsTimelineFile)} (${n})`); }
  }

  for (const dir of tempDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch  }
  }

  logger.info(`[CatScale] ${hostname} (${osInfo || 'Linux'}): ${totalEvents} events — ${artifacts.length} sources`);
  return { events: totalEvents, hostname, os_info: osInfo, collection_time: collectionTime.toISOString(), artifacts };
}
