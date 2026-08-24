
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import os from 'os';
import readline from 'readline';
import { spawnSync } from 'child_process';
import { Pool } from 'pg';
import { findArtifactFiles, findArtifactFile, type CatScaleFailure } from './catscaleFiles';
import { collectStateArtifacts } from './catscaleStateCollect';
import { resolveCollectionTime } from './catscaleNetworkParsers';
import { insertStateRows } from './catscaleStateStore';

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

// Linux log timestamps are wall-clock strings with no offset. Building them with
// `new Date(y, m, d, ...)` would resolve them against the *analyst machine's*
// timezone, so the same evidence would land on two different timelines depending
// on who parsed it. Anchor everything to UTC instead: a fixed, documented offset
// beats a variable one. (The host's real timezone sits in
// System_Info/*-date-timezone and is kept in `raw` for later refinement.)
function parseBsd(s: string, collectedAt: Date): Date | null {
  const m = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (!m || MONTHS[m[1]] === undefined) return null;
  const year = collectedAt.getUTCFullYear();
  const at = (y: number) => new Date(Date.UTC(y, MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
  // Syslog omits the year: a line dated after the collection has to belong to the
  // previous one (December entries read from a January collection).
  const d = at(year) > collectedAt ? at(year - 1) : at(year);
  return isNaN(d.getTime()) ? null : d;
}

function parseLastTs(s: string): Date | null {

  const m = /(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(s);
  if (!m || MONTHS[m[1]] === undefined) return null;
  const d = new Date(Date.UTC(+m[6], MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
  return isNaN(d.getTime()) ? null : d;
}

// collection_timeline.src_ip / dst_ip are INET: a bad literal aborts the whole
// 500-row batch, so anything that is not a clean address becomes NULL. Strips the
// :port that ss/netstat append, unwraps [::1], drops the %scope suffix.
function toInet(addr: string | null | undefined): string | null {
  if (!addr) return null;
  let a = String(addr).trim();
  if (!a || a === '*' || a.startsWith('*:')) return null;

  const bracketed = /^\[([^\]]+)\](?::.*)?$/.exec(a);
  if (bracketed) a = bracketed[1];
  else if ((a.match(/:/g) || []).length === 1) a = a.split(':')[0];
  else if (/:\d+$/.test(a)) a = a.replace(/:\d+$/, '');

  a = a.split('%')[0];
  if (!a || a === '*') return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return a.split('.').every(o => +o <= 255) ? a : null;
  if (/^[0-9a-fA-F:]+$/.test(a) && a.includes(':')) return a;
  return null;
}

// ext is VARCHAR(16); anything longer is not a real extension anyway.
function extOf(p: string): string | null {
  const base = path.basename(p);
  const i = base.lastIndexOf('.');
  if (i <= 0 || i === base.length - 1) return null;
  const e = base.slice(i + 1).toLowerCase();
  return e.length <= 16 ? e : null;
}

function portOf(addr: string | null | undefined): string | null {
  if (!addr) return null;
  const m = /:(\d{1,5})$/.exec(String(addr).trim());
  return m ? m[1] : null;
}

// First token of a command line, reduced to what the Process Name column expects.
function procName(command: string): string | null {
  const first = command.trim().split(/\s+/)[0];
  if (!first) return null;
  const kernelThread = /^\[(.+?)[\]/]/.exec(first); // [kworker/0:1] -> kworker
  if (kernelThread) return kernelThread[1];
  return path.basename(first).substring(0, 128) || null;
}

// File discovery lives in catscaleFiles so the state collector can share it
// without a circular import. Re-exported: callers and tests already import it
// from here.
export { findArtifactFiles, findArtifactFile };

function extractTarGz(archivePath: string, destDir: string, failures?: CatScaleFailure[]): boolean {
  const note = (reason: string) => {
    logger.warn(`[CatScale] cannot open ${path.basename(archivePath)}: ${reason}`);
    failures?.push({ stage: 'extract', target: archivePath, reason });
    return false;
  };
  if (!fs.existsSync(archivePath)) return note('archive missing');
  try { fs.mkdirSync(destDir, { recursive: true }); } catch (e: any) { return note(`cannot create temp dir: ${e.message}`); }
  const r = spawnSync('tar', ['xzf', archivePath, '-C', destDir], {
    timeout: 300_000,
    maxBuffer: 200 * 1024 * 1024,
  });
  if (r.status !== 0) return note(r.stderr?.toString().trim() || `tar exited ${r.status}`);
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

// Full-timeline.csv is CSV: paths and usernames can legitimately contain commas
// and are then double-quoted. A naive line.split(',') shifts every column after
// such a field, dropping rows or inventing rows from the wrong columns. Parse
// quoted fields properly (doubled "" is an escaped quote).
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else inQ = false;
      } else cur += c;
    } else if (c === '"') {
      inQ = true;
    } else if (c === ',') {
      out.push(cur); cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}

// Linux `stat` writes wall-clock timestamps with nanosecond precision and no
// offset — e.g. "2026-07-30 12:44:06.123456789 +0000". `new Date()` on the raw
// string is fragile (space separator, 9-digit fraction, offset without colon can
// all fail) and every failed parse silently drops the row later on. Normalise to
// ISO: 'T' separator, milliseconds only, UTC anchor.
function parseFsTs(s: string): Date | null {
  if (!s) return null;
  let str = String(s).trim();
  if (!str || str === '-') return null;
  str = str.replace(/ /, 'T');
  str = str.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'); // +0000 → +00:00
  const fracM = /\.(\d+)/.exec(str);
  if (fracM) str = str.replace(fracM[0], '.' + (fracM[1] + '000').slice(0, 3));
  if (!/[+-]\d{2}:\d{2}$|Z$/i.test(str)) str += 'Z';
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
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
  // Forensic columns promoted out of `raw`. Nothing downstream reads `raw`:
  // evidence scoping, the SuperTimeline facets and the network map all filter on
  // real columns, so a row that only fills `raw` is invisible to them.
  artifact_name?: string | null;
  timestamp_kind?: string | null;
  path?: string | null;
  ext?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  process_name?: string | null;
};

/** One thing that did not work. `stage` names where, so the UI can be specific.
 *  Defined in catscaleFiles and re-exported: importers already reach for it here. */
export type { CatScaleFailure } from './catscaleFiles';

/** Ties every row back to the parse run, and carries the failure channel down to
 *  batchInsert without threading a new argument through nine parser signatures. */
export type TimelineLink = {
  resultId?: string | null;
  evidenceId?: string | null;
  failures?: CatScaleFailure[];
};

const TOOL = 'catscale';

type Detection = { id: string; name: string; severity: string; category: string; mitre: string[] };
const threatEngine = require('./threatEngine') as {
  evaluate: (rec: Record<string, unknown>) => { detections: Detection[]; tags: string[] } | null;
};

// The native and CSV ingest paths run the threat engine inside extractForensicFields;
// CatScale bypasses that helper entirely, so evaluation happens here. Doing it in
// batchInsert means every parser is covered by construction — a new artifact family
// cannot be added without inheriting detection.
function evaluateRow(r: Row): { detections: string | null; tags: string[] } {
  try {
    const hit = threatEngine.evaluate({
      // Raw first: the promoted columns must win if a parser fills both.
      ...r.raw,
      artifact_type: r.artifact_type,
      description: r.description,
      source: r.source,
      path: r.path ?? null,
      ext: r.ext ?? null,
      process_name: r.process_name ?? null,
      host_name: r.host_name ?? null,
      user_name: r.user_name ?? null,
      event_id: null,
    });
    if (!hit) return { detections: null, tags: [] };
    return { detections: JSON.stringify(hit.detections), tags: hit.tags ?? [] };
  } catch (e: any) {
    logger.warn('[CatScale] threat engine error:', e.message);
    return { detections: null, tags: [] };
  }
}

const INSERT_COLS = [
  'case_id', 'result_id', 'evidence_id', 'timestamp', 'artifact_type', 'artifact_name',
  'source', 'description', 'raw', 'host_name', 'user_name', 'process_name',
  'tool', 'timestamp_kind', '"path"', 'ext', 'src_ip', 'dst_ip', 'tags', 'detections',
];

async function batchInsert(pool: Pool, rows: Row[], link: TimelineLink = {}): Promise<number> {
  if (!rows.length) return 0;
  const resultId   = link.resultId   ?? null;
  const evidenceId = link.evidenceId ?? null;
  let inserted = 0;
  const BATCH = 500;
  for (let i = 0; i < rows.length; i += BATCH) {
    const slice = rows.slice(i, i + BATCH);
    const vals: string[] = [];
    const params: unknown[] = [];
    let idx = 1;
    for (const r of slice) {
      const { detections, tags } = evaluateRow(r);
      vals.push(`(${INSERT_COLS.map(() => `$${idx++}`).join(',')})`);
      params.push(
        r.case_id, resultId, evidenceId, r.timestamp.toISOString(), r.artifact_type,
        // artifact_name is NOT NULL DEFAULT '' in db/init.sql, and an explicit
        // NULL does not fall back to the default — it fails the whole batch. A
        // parser that omits the field used to lose every one of its rows.
        r.artifact_name ?? '', r.source, r.description, JSON.stringify(r.raw),
        r.host_name ?? null, r.user_name ?? null, r.process_name ?? null,
        TOOL, r.timestamp_kind ?? null, r.path ?? null, r.ext ?? null,
        r.src_ip ?? null, r.dst_ip ?? null, tags, detections,
      );
    }
    try {
      await pool.query(
        `INSERT INTO collection_timeline
           (${INSERT_COLS.join(', ')})
         VALUES ${vals.join(',')}`,
        params,
      );
      inserted += slice.length;
    } catch (e: any) {
      // Losing 500 rows must not read as "these events did not exist".
      logger.error(`[CatScale] batch insert failed (${slice.length} rows lost): ${e.message}`);
      link.failures?.push({ stage: 'insert', target: `${slice.length} rows`, reason: e.message });
    }
  }
  return inserted;
}

const CATSCALE_MARKER_DIRS = ['Logs', 'Process_and_Network', 'System_Info', 'User_Files', 'Persistence', 'Misc'];

function countMarkers(dir: string): number {
  try { return fs.readdirSync(dir).filter(e => CATSCALE_MARKER_DIRS.includes(e)).length; }
  catch { return 0; }
}

// Cat-Scale writes its output 0600/0700 as root; a backend that dropped
// privileges gets EACCES on every readdir. findFiles/walkDir turn that into an
// empty listing, which would otherwise surface as a successful parse of an empty
// collection — the failure mode an analyst is most likely to misread as "clean".
// Probing up front lets the caller tell "nothing there" from "nothing readable".
function unreadableDirs(root: string): string[] {
  const denied: string[] = [];
  const probe = (p: string) => {
    try { fs.readdirSync(p); }
    catch (e: any) { if (e?.code === 'EACCES' || e?.code === 'EPERM') denied.push(p); }
  };
  probe(root);
  let entries: string[] = [];
  try { entries = fs.readdirSync(root); } catch { return denied; }
  for (const e of entries) {
    const sub = path.join(root, e);
    try { if (fs.statSync(sub).isDirectory()) probe(sub); }
    catch (err: any) { if (err?.code === 'EACCES' || err?.code === 'EPERM') denied.push(sub); }
  }
  return denied;
}

export function findCatScaleRoot(extractDir: string): string | null {
  if (countMarkers(extractDir) >= 2) return extractDir;
  try {
    for (const e of fs.readdirSync(extractDir)) {
      const sub = path.join(extractDir, e);
      try {
        if (fs.statSync(sub).isDirectory() && countMarkers(sub) >= 2) return sub;
      } catch (_e) {}
    }
  } catch (_e) {}
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

async function parseAuthLog(filePath: string, caseId: string, pool: Pool, hostname: string, collectedAt: Date, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;
    if (!AUTH_PATTERNS_RE.some(re => re.test(line))) continue;

    let ts: Date | null = null;
    let msg = line;
    let host = hostname;
    let proc = '';

    const bsd = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$/.exec(line);
    if (bsd) { ts = parseBsd(bsd[1], collectedAt); host = bsd[2]; proc = bsd[3]; msg = bsd[4]; }

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
      case_id: caseId, timestamp: ts ?? collectedAt,
      artifact_type: 'catscale_auth', artifact_name: 'Linux Auth Log',
      source: path.basename(filePath),
      description,
      raw: { line, category, username, source_ip: sourceIp, host, process: proc },
      host_name: host, user_name: username,
      // syslog tags the daemon as "sshd[1234]" — the PID belongs in raw, not in a name.
      timestamp_kind: 'log', src_ip: toInet(sourceIp),
      process_name: proc ? proc.replace(/\[\d+\]$/, '') : null,
    });
  }
  return batchInsert(pool, rows, link);
}

// auditd is the richest execution and file-access source on Linux. Cat-Scale ships
// it inside var-log.tar.gz, where the filename filter previously stopped at
// auth.log/secure/messages/syslog and dropped it entirely.
const AUDIT_RE = /^type=(\S+)\s+msg=audit\((\d+)\.(\d{1,3}):(\d+)\):\s*(.*)$/;

function auditField(body: string, key: string): string | null {
  const m = new RegExp(`\\b${key}="([^"]*)"|\\b${key}=([^\\s]+)`).exec(body);
  return m ? (m[1] ?? m[2] ?? null) : null;
}

async function parseAuditd(filePath: string, caseId: string, pool: Pool, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];
  for await (const line of readLines(filePath)) {
    const m = AUDIT_RE.exec(line);
    if (!m) continue;
    const [, type, secs, ms, serial, body] = m;
    const ts = new Date(Number(secs) * 1000 + Number(ms.padEnd(3, '0')));
    if (isNaN(ts.getTime())) continue;

    const exe = auditField(body, 'exe');
    const comm = auditField(body, 'comm');
    const key = auditField(body, 'key');
    const result = auditField(body, 'res') ?? auditField(body, 'success');
    const uid = auditField(body, 'uid');
    const auid = auditField(body, 'auid');

    // EXECVE splits the command line across a0..aN; rebuilt so execution rules,
    // which all match on `description`, can see the whole invocation.
    let argv: string | null = null;
    if (type === 'EXECVE') {
      const parts: string[] = [];
      for (let i = 0; i < 24; i++) {
        const a = auditField(body, `a${i}`);
        if (a === null) break;
        parts.push(a);
      }
      if (parts.length) argv = parts.join(' ');
    }

    const subject = argv ?? exe ?? comm ?? body.slice(0, 120);
    rows.push({
      case_id: caseId, timestamp: ts,
      artifact_type: 'catscale_auditd', artifact_name: 'Linux Audit Log',
      source: path.basename(filePath),
      description: `AUDITD ${type}: ${subject}${key ? ` [${key}]` : ''}${result ? ` (${result})` : ''}`,
      raw: { type, serial, exe, comm, key, result, uid, auid, argv, line, host: hostname },
      host_name: hostname, user_name: auid && auid !== '4294967295' ? auid : null,
      timestamp_kind: 'log',
      path: exe, process_name: comm ?? (exe ? path.basename(exe) : null),
    });
  }
  return batchInsert(pool, rows, link);
}

const LAST_TS_RE = /\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}/;

async function parseLastWtmp(filePath: string, caseId: string, pool: Pool, hostname: string, link: TimelineLink = {}): Promise<number> {
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
      artifact_name: isReboot ? 'Linux System Event' : 'Linux Logon History',
      source: path.basename(filePath),
      description,
      raw: { user, tty, from, login_time: loginStr, logout_time: logoutMatch?.[1] ?? null, still_logged: stillLogged, duration, type, host: hostname },
      host_name: hostname, user_name: isReboot ? null : user,
      // `from` is a host or an address depending on the login path; toInet keeps
      // only what pg's INET column will actually accept.
      timestamp_kind: isReboot ? 'system' : 'login', src_ip: toInet(from),
    });
  }
  return batchInsert(pool, rows, link);
}

async function parseProcessList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, link: TimelineLink = {}): Promise<number> {
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

    const exe = command.trim().split(/\s+/)[0];
    rows.push({
      case_id: caseId, timestamp: t,
      artifact_type: 'catscale_process', artifact_name: 'Linux Process List',
      source: path.basename(filePath),
      description: `Process [${user}] PID=${pid}: ${command.substring(0, 150)}`,
      raw: { pid: +pid, user, command, host: hostname },
      host_name: hostname, user_name: user,
      // A ps listing is a snapshot: the timestamp is when we looked, not when the
      // process started. Saying so keeps an analyst from reading it as an event.
      timestamp_kind: 'collection',
      path: exe.startsWith('/') ? exe : null,
      process_name: procName(command),
    });
  }
  return batchInsert(pool, rows, link);
}

// A listening socket has no peer: ss renders it as 0.0.0.0:* / [::]:*. Recording
// that as a destination would invent an edge on the network map, so listeners keep
// src_ip (the exposed surface) and leave dst_ip NULL.
const NO_PEER_STATES = new Set(['LISTEN', 'UNCONN', 'CLOSE', 'CLOSED']);

// /network/:caseId/graph builds its edges from raw JSONB names, not from the
// src_ip/dst_ip columns — `Computer` for the source node, then dst_ip/dst_port/proto.
// Speaking that vocabulary is what puts a Linux host on the map; omitting the keys
// entirely when there is no peer keeps listeners from becoming phantom edges.
function graphKeys(hostname: string, peerIp: string | null, peer: string, proto: string) {
  if (!peerIp) return { Computer: hostname };
  return { Computer: hostname, dst_ip: peerIp, dst_port: portOf(peer), proto };
}

async function parseNetworkConnections(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;

    if (/^(nl|p_raw|p_dgr|u_str|u_dgr|u_seq)\s/.test(line)) continue;
    const ss = /^(\S+)\s+(ESTAB|LISTEN|CLOSE-WAIT|TIME-WAIT|SYN-SENT|SYN-RECV|FIN-WAIT[12]?|UNCONN|CLOSE|CLOSED)\s+\d+\s+\d+\s+([\S]+)\s+([\S]+)\s*(.*)$/.exec(line);
    if (ss) {
      const [, netid, state, local, peer, rest] = ss;
      const proc = /users:\(\("([^"]+)",pid=(\d+)/.exec(rest);
      const uid = /uid:(\d+)/.exec(rest);
      const peerIp = NO_PEER_STATES.has(state) ? null : toInet(peer);
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_network', source: path.basename(filePath),
        description: `${netid.toUpperCase()} ${state}: ${local} ↔ ${peer}${proc ? ` [${proc[1]}]` : ''}`,
        raw: {
          netid, state, local, peer, process: proc?.[1] ?? null,
          pid: proc?.[2] ? +proc[2] : null, uid: uid ? +uid[1] : null, host: hostname,
          ...graphKeys(hostname, peerIp, peer, netid),
        },
        host_name: hostname,
        artifact_name: 'Linux Network Sockets', timestamp_kind: 'collection',
        src_ip: toInet(local), dst_ip: peerIp,
        process_name: proc?.[1] ?? null,
      });
      continue;
    }

    const netstat = /^(tcp|udp)6?\s+\d+\s+\d+\s+([\d.:\[\]]+:\S+)\s+([\d.:\[\]*]+:\S+)\s+(\S+)/.exec(line);
    if (netstat) {
      const [, proto, local, foreign, state] = netstat;
      if (state === 'TIME_WAIT') continue;
      const foreignIp = NO_PEER_STATES.has(state) ? null : toInet(foreign);
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_network', source: path.basename(filePath),
        description: `${proto.toUpperCase()} ${state}: ${local} ↔ ${foreign}`,
        raw: { proto, local, foreign, state, host: hostname, ...graphKeys(hostname, foreignIp, foreign, proto) },
        host_name: hostname,
        artifact_name: 'Linux Network Sockets', timestamp_kind: 'collection',
        src_ip: toInet(local), dst_ip: foreignIp,
      });
    }
  }
  return batchInsert(pool, rows, link);
}


async function parseBashHistory(filePath: string, caseId: string, pool: Pool, t: Date, username: string, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];
  let pendingTs: Date | null = null;

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;
    const tsLine = /^#(\d{10,})$/.exec(line);
    if (tsLine) { pendingTs = new Date(+tsLine[1] * 1000); continue; }

    rows.push({
      case_id: caseId, timestamp: pendingTs ?? t,
      artifact_type: 'catscale_history', artifact_name: 'Linux Shell History',
      source: path.basename(filePath),
      description: `Historique [${username}]: ${line.substring(0, 200)}`,
      raw: { command: line, username, host: hostname },
      host_name: hostname, user_name: username,
      // Without HISTTIMEFORMAT a shell history carries no time at all: every command
      // collapses onto the collection instant. Flagging that stops an analyst from
      // reading a thousand co-timestamped commands as a burst of activity.
      timestamp_kind: pendingTs ? 'command' : 'collection',
      process_name: procName(line),
    });    pendingTs = null;
  }
  return batchInsert(pool, rows, link);
}


// dmesg: "[Fri Dec 26 07:41:28 2025] CIFS: Status code returned ..." — kernel
// ring buffer. The bracketed timestamp is fully qualified (no year guessing),
// and lines without one are kept anchored to the collection time.
async function parseDmesg(filePath: string, caseId: string, pool: Pool, collectedAt: Date, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];
  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;
    const m = /^\[\s*(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s*\]\s*(.*)$/.exec(line.trim());
    const ts = m ? new Date(Date.UTC(+m[6], MONTHS[m[1]] ?? 0, +m[2], +m[3], +m[4], +m[5])) : null;
    const msg = (m?.[7] ?? line.trim());
    rows.push({
      case_id: caseId, timestamp: ts && !isNaN(ts.getTime()) ? ts : collectedAt,
      artifact_type: 'catscale_dmesg', artifact_name: 'Linux Kernel Log (dmesg)',
      source: 'dmesg',
      description: msg.substring(0, 300),
      raw: { message: msg, host: hostname },
      host_name: hostname,
      timestamp_kind: ts && !isNaN(ts.getTime()) ? 'kernel' : 'collection',
      process_name: null,
    });
  }
  return batchInsert(pool, rows, link);
}





async function parseCronTabList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];
  let currentUser = 'unknown';

  for await (const line of readLines(filePath)) {
    const userHeader = /crontab(?:s)? for (?:user:?\s*)?(\S+)/i.exec(line);
    if (userHeader) { currentUser = userHeader[1].replace(':', ''); continue; }
    if (line.startsWith('#') || !line.trim()) continue;

    if (/^(@\w+|\*|[-\d,\/]+)\s/.test(line.trim())) {
      rows.push({
        case_id: caseId, timestamp: t,
        artifact_type: 'catscale_persistence', artifact_name: 'Linux Cron',
        source: 'crontab',
        description: `Cron [${currentUser}]: ${line.trim().substring(0, 200)}`,
        raw: { cron_entry: line.trim(), user: currentUser, host: hostname },
        host_name: hostname, user_name: currentUser,
        timestamp_kind: 'collection',
      });
    }
  }
  return batchInsert(pool, rows, link);
}


// CatScale ships systemd data in two shapes:
//  - `systemctl list-units` / `list-unit-files` lines: "unit.service active ..."
//  - a dump of unit files (persistence-systemdlist): "[Unit]\nDescription=...\n"
//    with [Unit]/[Service]/[Install] sections, one service after another.
// Both are handled here. For the unit-file dump each block of sections is one
// service row, and a suspicious ExecStart (base64 decode, curl/wget to an IP,
// /dev/shm staging, bash -c) is flagged so persistence implants are visible
// without opening the file.
const SYSTEMD_SUSPECT_RE = /(base64|curl|wget|nc\b|ncat|\/dev\/shm\/|\/tmp\/|python\s+-c|bash\s+-c|\b\d{1,3}(\.\d{1,3}){3}:\d+|chmod\s+\+x)/i;

async function parseSystemdList(filePath: string, caseId: string, pool: Pool, t: Date, hostname: string, link: TimelineLink = {}): Promise<number> {
  const rows: Row[] = [];
  const isUnitFileDump = (line: string) => /^\s*\[Unit\]/.test(line) || /^\s*\[Service\]/.test(line);

  // Detect the format from the first handful of non-blank lines so the two
  // loops below stay cleanly separated (a unit dump can carry a command-line
  // header before the first [Unit] block, and can contain lines that look like
  // list rows).
  let format: 'list' | 'dump' = 'list';
  let probeCount = 0;
  for await (const probe of readLines(filePath)) {
    if (!probe.trim()) continue;
    if (isUnitFileDump(probe)) { format = 'dump'; break; }
    probeCount += 1;
    // A `systemctl status` output starts with "● unit.service — desc" lines,
    // while a unit dump normally opens with [Unit] within the first few lines.
    // 30 lines covers long command headers without mistaking a list for a dump.
    if (probeCount >= 30) break;
  }

  if (format === 'list') {
    for await (const line of readLines(filePath)) {
      const m1 = /^\s*(\S+\.service)\s+\S+\s+(active|failed)\s+(\S+)\s+(.*)$/.exec(line);
      if (m1) {
        const [, unit, active, sub, desc] = m1;
        rows.push({
          case_id: caseId, timestamp: t,
          artifact_type: 'catscale_persistence', artifact_name: 'Linux Systemd Unit',
          source: 'systemd',
          description: `Service ${active === 'failed' ? '⚠ FAILED' : 'actif'}: ${unit} (${sub}) — ${desc.trim().substring(0, 100)}`,
          raw: { unit, active, sub, description: desc.trim(), host: hostname },
          host_name: hostname,
          timestamp_kind: 'collection', process_name: unit,
        });
        continue;
      }
      const m2 = /^\s*(\S+\.service)\s+(enabled|disabled|masked|static|alias|indirect|generated)\s/.exec(line);
      if (m2) {
        const [, unit, state] = m2;
        if (['masked', 'disabled'].includes(state) && !unit.startsWith('ssh') && !unit.startsWith('cron')) continue; // skip noise
        rows.push({
          case_id: caseId, timestamp: t,
          artifact_type: 'catscale_persistence', artifact_name: 'Linux Systemd Unit',
          source: 'systemd-unit-files',
          description: `Service [${state}]: ${unit}`,
          raw: { unit, state, host: hostname },
          host_name: hostname,
          timestamp_kind: 'collection', process_name: unit,
        });
      }
    }
    return batchInsert(pool, rows, link);
  }

  // ── Unit-file dump: accumulate sections until the next [Unit] starts a new
  //    service, then emit one row carrying its Description + ExecStart lines. ──
  interface UnitBlock { unit: string; description: string; execs: string[]; wantedBy: string; aliases: string[]; }
  let block: UnitBlock | null = null;
  const flush = () => {
    if (!block) return;
    const execStart = block.execs[0] || '';
    const allExec = block.execs.join(' ; ');
    const suspicious = SYSTEMD_SUSPECT_RE.test(allExec);
    const name = block.unit || block.description || 'systemd-unit';
    rows.push({
      case_id: caseId, timestamp: t,
      artifact_type: 'catscale_persistence', artifact_name: 'Linux Systemd Unit',
      source: 'systemd-unit-file',
      description: `${suspicious ? '⚠ SUSPECT ' : ''}Systemd unit: ${name}${block.description ? ' — ' + block.description.substring(0, 80) : ''}${execStart ? ' · ExecStart=' + execStart.substring(0, 120) : ''}`,
      raw: {
        unit: block.unit || null, description: block.description || null,
        exec_start: block.execs, wanted_by: block.wantedBy || null,
        aliases: block.aliases, suspicious, host: hostname,
      },
      host_name: hostname,
      timestamp_kind: 'collection',
      process_name: block.unit || null,
    });
    block = null;
  };

  for await (const line of readLines(filePath)) {
    const sec = /^\s*\[(\w+)\]\s*$/.exec(line);
    if (sec) {
      if (sec[1] === 'Unit' && block) flush();
      if (!block) block = { unit: '', description: '', execs: [], wantedBy: '', aliases: [] };
      continue;
    }
    if (!block) continue;
    const kv = /^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1]; const val = kv[2].trim();
    if (!val) continue;
    if (key === 'Description' && !block.description) block.description = val;
    else if (key === 'ExecStart' || key === 'ExecStartPre' || key === 'ExecStartPost' || key === 'ExecReload') block.execs.push(val);
    else if (key === 'WantedBy' && !block.wantedBy) block.wantedBy = val;
    else if (key === 'Alias') block.aliases.push(val);
    else if (key === 'Unit' && !block.unit) block.unit = val;
  }
  flush();
  return batchInsert(pool, rows, link);
}


// ── full-timeline.csv column mapping ──────────────────────────────────────────
// The exact column layout of CatScale's full-timeline.csv varies between
// versions, so we never trust a fixed schema: the header is read when present,
// and the *content* of the first data rows drives the mapping. A column is the
// path column when most of its values start with '/'; a column is a timestamp
// when most of its values parse as dates; user/perms/size are classified the
// same way. This works for any column order and any naming.
interface TimelineColMap {
  path: number | null;
  mtime: number | null;
  atime: number | null;
  ctime: number | null;
  crtime: number | null;
  user: number | null;
  perms: number | null;
  size: number | null;
  inode: number | null;
  md5: number | null;
}

const TS_KINDS = ['mtime', 'atime', 'ctime', 'crtime'] as const;

function looksLikePath(v: string): boolean {
  return typeof v === 'string' && v.startsWith('/');
}
function looksLikeTs(v: string): boolean {
  return parseFsTs(v) !== null;
}
function looksLikePerms(v: string): boolean {
  // drwxr-xr-x, -rw-r--r--, octal 0644
  return /^[bcdlps-][rwxstST-]{9}([.+]|\s|$)/.test(v) || /^0?[0-7]{3,4}$/.test(v);
}
function looksLikeUser(v: string): boolean {
  // usernames / numeric uid, but not a path, not a date, not perms, not a pure
  // number (pure numbers are size/inode candidates, never usernames).
  return typeof v === 'string' && v.length > 0 && v.length <= 64
    && /^[a-zA-Z0-9_.\-]+$/.test(v)
    && !/^\d+$/.test(v)
    && !looksLikePath(v) && !looksLikeTs(v) && !looksLikePerms(v);
}
function looksLikeSize(v: string): boolean {
  return /^\d{1,20}$/.test(v);
}
function looksLikeMd5(v: string): boolean {
  return /^[0-9a-f]{32}$/i.test(v);
}

// Classify each column. Returns the column map, or null when no column looks
// like a path (nothing we can do).
//
// Three strategies, most reliable first:
//  1. Header mapping — CatScale writes a named header ("Inode,Hard link Count,
//     Full Path,Last Access,Last Modification,Last Status Change,File Creation,
//     User,Group,File Permissions,File Size(bytes)"), so column names pin the
//     exact order with zero guesswork.
//  2. The known positional layout of that same format (path=2, atime=3,
//     mtime=4, ctime=5, crtime=6, user=7, perms=9, size=10, inode=0), validated
//     by content — for collections that stripped the header.
//  3. Content-based detection for unusual layouts.
const POSITIONAL_LAYOUT: { key: keyof TimelineColMap; idx: number }[] = [
  { key: 'inode', idx: 0 },
  { key: 'path', idx: 2 },
  { key: 'atime', idx: 3 },
  { key: 'mtime', idx: 4 },
  { key: 'ctime', idx: 5 },
  { key: 'crtime', idx: 6 },
  { key: 'user', idx: 7 },
  { key: 'perms', idx: 9 },
  { key: 'size', idx: 10 },
];

// Header names as CatScale writes them, lower-cased and trimmed.
const HEADER_COL_MAP: Record<string, keyof TimelineColMap | null> = {
  'inode': 'inode',
  'hard link count': null,
  'full path': 'path',
  'path': 'path',
  'last access': 'atime',
  'atime': 'atime',
  'access': 'atime',
  'last modification': 'mtime',
  'modification': 'mtime',
  'modified': 'mtime',
  'mtime': 'mtime',
  'last status change': 'ctime',
  'status change': 'ctime',
  'ctime': 'ctime',
  'file creation': 'crtime',
  'creation': 'crtime',
  'crtime': 'crtime',
  'user': 'user',
  'group': null,
  'file permissions': 'perms',
  'permissions': 'perms',
  'perms': 'perms',
  'file size(bytes)': 'size',
  'file size': 'size',
  'size': 'size',
  'md5': 'md5',
  'sha256': null,
};

function detectTimelineCols(samples: string[][], header?: string[]): TimelineColMap | null {
  const width = Math.max(...samples.map(r => r.length));
  if (width === 0) return null;
  const n = samples.length;

  const map: TimelineColMap = {
    path: null, mtime: null, atime: null, ctime: null, crtime: null,
    user: null, perms: null, size: null, inode: null, md5: null,
  };

  // 1) Header mapping: exact, no guessing. Only accepted when the header
  //    actually names the path column AND the sampled rows agree the path
  //    column contains paths.
  if (header && header.length >= 3) {
    const named = new Map<string, number>();
    header.forEach((h, i) => {
      // Strip a UTF-8 BOM that some collectors prepend to the first column.
      const k = (HEADER_COL_MAP[String(h).replace(/^\uFEFF/, '').trim().toLowerCase()] as string | null);
      if (k && !named.has(k)) named.set(k, i);
    });
    const pathIdx = named.get('path');
    if (pathIdx !== undefined) {
      let pathOk = 0;
      for (const row of samples) { const v = (row[pathIdx] ?? '').trim(); if (looksLikePath(v)) pathOk += 1; }
      if (pathOk / n >= 0.6) {
        for (const [k, idx] of named) (map as any)[k] = idx;
        return map;
      }
    }
  }

  // 2) Known positional layout (header-less collections), validated by content:
  //    path column = '/'-prefixed values, timestamp columns = parseable dates,
  //    user/perms = plausible strings. A column that fails its check is left
  //    null rather than emitting garbage rows.
  let pathLikeAt2 = 0;
  for (const row of samples) {
    const v2 = (row[2] ?? '').trim();
    if (looksLikePath(v2)) pathLikeAt2 += 1;
  }
  if (pathLikeAt2 / n >= 0.6 && width >= 11) {
    const isTsCol = (idx: number) => {
      let ok = 0;
      for (const row of samples) {
        const v = (row[idx] ?? '').trim();
        if (v && v !== '-' && looksLikeTs(v)) ok += 1;
      }
      return ok / n >= 0.5;
    };
    for (const { key, idx } of POSITIONAL_LAYOUT) {
      if (key === 'path') { (map as any)[key] = idx; continue; }
      if (key === 'mtime' || key === 'atime' || key === 'ctime' || key === 'crtime') {
        if (isTsCol(idx)) (map as any)[key] = idx;
        continue;
      }
      if (key === 'perms') {
        let ok = 0;
        for (const row of samples) { const v = (row[idx] ?? '').trim(); if (v && looksLikePerms(v)) ok += 1; }
        if (ok / n >= 0.4) (map as any)[key] = idx;
        continue;
      }
      if (key === 'user') {
        let ok = 0;
        for (const row of samples) { const v = (row[idx] ?? '').trim(); if (v && looksLikeUser(v)) ok += 1; }
        if (ok / n >= 0.4) (map as any)[key] = idx;
        continue;
      }
      if (key === 'inode' || key === 'size') {
        let ok = 0;
        for (const row of samples) { const v = (row[idx] ?? '').trim(); if (v && /^\d{1,20}$/.test(v)) ok += 1; }
        if (ok / n >= 0.4) (map as any)[key] = idx;
        continue;
      }
    }
    // md5: not in the known layout, fill by content on the rest.
    const taken = new Set(POSITIONAL_LAYOUT.map(p => p.idx));
    for (let i = 0; i < width; i++) {
      if (taken.has(i)) continue;
      let md5V = 0;
      for (const row of samples) {
        const v = (row[i] ?? '').trim();
        if (looksLikeMd5(v)) md5V += 1;
      }
      if (md5V / n >= 0.6 && map.md5 === null) { map.md5 = i; taken.add(i); }
    }
    return map;
  }

  // 2) Fallback: content-based detection for unusual layouts.
  const votes = new Map<string, number[]>();
  const keys: (keyof TimelineColMap)[] = ['path', 'mtime', 'atime', 'ctime', 'crtime', 'user', 'perms', 'size', 'inode', 'md5'];
  keys.forEach(k => votes.set(k, new Array(width).fill(0)));

  for (const row of samples) {
    for (let i = 0; i < width; i++) {
      const v = (row[i] ?? '').trim();
      if (!v) continue;
      if (looksLikePath(v)) (votes.get('path') as number[])[i] += 1;
      if (looksLikeTs(v))   (votes.get('mtime') as number[])[i] += 1; // any ts column
      if (looksLikePerms(v)) (votes.get('perms') as number[])[i] += 1;
      if (looksLikeUser(v)) (votes.get('user') as number[])[i] += 1;
      if (looksLikeSize(v)) (votes.get('size') as number[])[i] += 1;
      if (looksLikeMd5(v))  (votes.get('md5') as number[])[i] += 1;
    }
  }

  const taken = new Set<number>();
  const pickBest = (key: keyof TimelineColMap, threshold = 0.6, exclude: Set<number> = taken) => {
    const arr = votes.get(key) as number[];
    let best = -1, bestV = 0;
    for (let i = 0; i < arr.length; i++) {
      if (exclude.has(i)) continue;
      if (arr[i] > bestV) { bestV = arr[i]; best = i; }
    }
    if (best >= 0 && bestV / n >= threshold) {
      (map as any)[key] = best;
      taken.add(best);
    }
  };

  // Path first — everything else is relative to it.
  pickBest('path', 0.8);
  if (map.path === null) pickBest('path', 0.3); // looser fallback
  if (map.path === null) return null;
  taken.add(map.path);

  // Timestamps: every column that is mostly timestamps, in column order. The
  // first is mtime (CatScale sorts by it and it is the traditional primary),
  // the rest get assigned atime/ctime/crtime in order.
  const tsCols: number[] = [];
  const tsVotes = votes.get('mtime') as number[];
  for (let i = 0; i < tsVotes.length; i++) {
    if (!taken.has(i) && tsVotes[i] / n >= 0.6) tsCols.push(i);
  }
  tsCols.sort((a, b) => a - b);
  TS_KINDS.forEach((k, idx) => {
    if (idx < tsCols.length) {
      (map as any)[k] = tsCols[idx];
      taken.add(tsCols[idx]);
    }
  });

  pickBest('perms');
  pickBest('user');
  pickBest('size');
  pickBest('md5');
  // inode: a pure-number column not already claimed (size may have taken one).
  pickBest('inode', 0.6);

  return map;
}

// Package-managed and pseudo filesystems: rewritten by every apt/snap upgrade,
// forensically inert unless the path is independently suspicious.
// Deliberately NOT '/usr/': that would swallow /usr/local, which is precisely
// where software is installed outside package management — admins and intruders
// alike. Only the package-managed subtrees are inert.
const NOISE_PREFIXES = ['/usr/lib/', '/usr/lib64/', '/usr/share/', '/usr/include/',
  '/usr/src/', '/usr/bin/', '/usr/sbin/', '/lib/', '/lib64/', '/snap/',
  '/var/lib/dpkg/', '/var/lib/apt/', '/var/lib/snapd/', '/var/cache/', '/proc/', '/sys/'];

// Unconditional pass: small, high-value locations where implants actually land.
// '/home/' used to be here and was the single biggest source of noise — on a real
// collection it let 1,091,925 rows through, bypassing even the recency check,
// because a desktop home directory is mostly application data. /home is not
// excluded; it is simply held to the same rules as everywhere else.
const SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/', '/root/', '/etc/'];

// Container overlay layers. Measured at 3,284,093 rows — 75% of everything the
// old filter kept. They are rebuildable from the image, and what actually matters
// forensically (what a container wrote at runtime) is `docker diff`, which the
// Docker artifacts now cover directly.
const CONTAINER_LAYER_PREFIXES = [
  '/var/lib/docker/', '/var/lib/containerd/', '/var/lib/containers/', '/var/lib/flatpak/',
];

// Trees that are caches or reproducible build output. Excluded unless the file
// carries a suspicious extension — dropping them wholesale would hide a payload
// deliberately parked in one.
const REBUILDABLE_RE = /\/(\.cache|node_modules|\.npm|\.steam|__pycache__|\.venv|site-packages|Steam)\/|\/\.git\/objects\//i;
const SUSPICIOUS_EXT_RE = /\.(sh|py|pl|rb|php|jsp|php\d?|cgi|exe|elf|so)$/i;

/** What the noise floor removed, and why. Reported so a 92% reduction is a stated
 *  decision rather than a silent one — an analyst must be able to see the gap. */
export interface FsTimelineFilterStats {
  scanned: number;
  kept: number;
  dropped: {
    container_layer: number;
    rebuildable: number;
    package_tree: number;
    not_relevant: number;
    unparsable: number;
  };
  top_dropped_locations: { path: string; count: number }[];
}

// Two path segments is the useful granularity: '/var/lib/docker', '/home/alice'.
function locationKey(fullPath: string): string {
  const segs = fullPath.split('/').filter(Boolean).slice(0, 3);
  return '/' + segs.slice(0, segs.length > 2 && fullPath.startsWith('/var/lib/') ? 3 : 2).join('/');
}

async function parseFsTimeline(
  filePath: string, caseId: string, pool: Pool, hostname: string, collectedAt: Date,
  link: TimelineLink = {}, stats?: FsTimelineFilterStats, exhaustive = false,
): Promise<number> {
  const rows: Row[] = [];
  let inserted = 0;
  const dropped = new Map<string, number>();
  const note = (reason: keyof FsTimelineFilterStats['dropped'], p?: string) => {
    if (!stats) return;
    stats.dropped[reason] += 1;
    if (p) dropped.set(locationKey(p), (dropped.get(locationKey(p)) ?? 0) + 1);
  };
  // 90 days before the *collection*, not before today: an archive analysed months
  // later must not silently lose every file it recorded.
  const cutoff = new Date(collectedAt.getTime() - 90 * 24 * 60 * 60 * 1000);

  // Two-pass: buffer the first data rows to auto-detect the column layout from
  // their content, then process them plus the rest with the resolved map. The
  // header (if present) is captured for named column mapping.
  const buffered: string[] = [];
  let colMap: TimelineColMap | null = null;
  let headerNames: string[] | null = null;
  const SAMPLE_SIZE = 30;

  const flushBuffered = async () => {
    for (const line of buffered) await processLine(line);
    buffered.length = 0;
  };

  const processLine = async (line: string): Promise<void> => {
    if (stats) stats.scanned += 1;
    const parts = splitCsvLine(line);
    if (parts.length < 2) { note('unparsable'); return; }

    const col = colMap!;
    const at = (idx: number | null) => (idx === null ? undefined : parts[idx]);

    const fullPath = at(col.path);
    const lastMod  = at(col.mtime);
    const atime    = at(col.atime);
    const ctime    = at(col.ctime);
    const crtime   = at(col.crtime);
    const user     = at(col.user);
    const perms    = at(col.perms);
    const size     = at(col.size);
    const inode    = at(col.inode);
    const md5      = at(col.md5);

    if (!fullPath || fullPath === '-') { note('unparsable'); return; }

    // Container layers first, and unconditionally: nothing here is worth a row.
    if (!exhaustive && CONTAINER_LAYER_PREFIXES.some(p => fullPath.startsWith(p))) {
      note('container_layer', fullPath); return;
    }

    const isSuspiciousExt = SUSPICIOUS_EXT_RE.test(fullPath);
    // Caches and build output, unless the name itself is a reason to look.
    if (!exhaustive && !isSuspiciousExt && REBUILDABLE_RE.test(fullPath)) {
      note('rebuildable', fullPath); return;
    }

    const isSuspiciousPath = SUSPICIOUS_PATHS.some(p => fullPath.startsWith(p));
    // A live host churns constantly under its package-managed trees, and on a real
    // collection that noise is ~95% of the rows — it buried 8 auth events under
    // 900k filesystem entries. Nothing here survives on recency or extension alone;
    // only an explicitly suspicious location gets through.
    if (!exhaustive && !isSuspiciousPath && NOISE_PREFIXES.some(p => fullPath.startsWith(p))) {
      note('package_tree', fullPath); return;
    }

    // Parse all available MACB timestamps. mtime is the primary recency signal
    // (the other columns may be absent in older collections); if it is unparsable
    // the row is kept anchored to the collection time, exactly as before.
    const modTs  = lastMod && lastMod !== '-' ? parseFsTs(lastMod) : null;
    const atsTs  = atime   && atime   !== '-' ? parseFsTs(atime)   : null;
    const ctsTs  = ctime   && ctime   !== '-' ? parseFsTs(ctime)   : null;
    const crtTs  = crtime  && crtime  !== '-' ? parseFsTs(crtime)  : null;

    const anyRecent =
      (modTs && modTs >= cutoff) || (atsTs && atsTs >= cutoff)
      || (ctsTs && ctsTs >= cutoff) || (crtTs && crtTs >= cutoff);

    // Only a real, parsed timestamp can be judged "not recent". An unparsable
    // timestamp must not silently discard the row — keep it, anchored to the
    // collection time, exactly like the fallback below.
    if (!exhaustive && modTs && !isSuspiciousPath && !isSuspiciousExt && !anyRecent) {
      note('not_relevant', fullPath); return;
    }
    if (stats) stats.kept += 1;

    const base = {
      case_id: caseId,
      artifact_type: 'catscale_fstimeline', artifact_name: 'Linux Filesystem Timeline',
      source: 'full-timeline.csv',
      raw: {
        path: fullPath, last_modified: lastMod ?? null,
        atime: atime ?? null, ctime: ctime ?? null, crtime: crtime ?? null,
        permissions: perms ?? null, user: user ?? null, size: size ?? null,
        inode: inode ?? null, md5: md5 ?? null, host: hostname,
      },
      host_name: hostname, user_name: user && user !== 'root' ? user : null,
      path: fullPath, ext: extOf(fullPath),
    };

    // MACB: emit one timeline row per distinct, parsable timestamp so every
    // filesystem event becomes searchable. Duplicate timestamps collapse onto
    // one row; when no timestamp parsed at all, a single collection-anchored row
    // keeps the file visible (matching the pre-MACB behaviour).
    const kinds: { kind: string; ts: Date | null }[] = [
      { kind: 'mtime',  ts: modTs },
      { kind: 'atime',  ts: atsTs },
      { kind: 'ctime',  ts: ctsTs },
      { kind: 'crtime', ts: crtTs },
    ];
    const seen = new Set<string>();
    let emitted = 0;
    for (const { kind, ts } of kinds) {
      if (!ts) continue;
      const key = ts.toISOString();
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        ...base,
        timestamp: ts,
        timestamp_kind: kind,
        description: `${perms ?? ''} [${user ?? ''}] ${fullPath} — ${kind.toUpperCase()}`,
      });
      emitted += 1;
    }
    if (emitted === 0) {
      rows.push({
        ...base,
        timestamp: collectedAt,
        timestamp_kind: 'collection',
        description: `${perms ?? ''} [${user ?? ''}] ${fullPath}`,
      });
    }

    if (rows.length >= 1000) {
      // The count of every intermediate flush used to be discarded, so a run that
      // wrote 4,399,750 rows reported "750" — the final partial batch alone. The
      // rows were in the database; the number shown to the analyst was not.
      inserted += await batchInsert(pool, rows.splice(0), link);
    }
  };

  for await (const line of readLines(filePath)) {
    if (!line.trim()) continue;

    if (!headerNames) {
      const probe = splitCsvLine(line);
      // A first line whose path column (index 2) does not start with '/' is the
      // CSV header: keep its column names for the named mapping below. A data
      // row has a '/' at column 2 and is kept and fed to detection.
      if (!(probe[2] && String(probe[2]).trim().startsWith('/'))) {
        headerNames = probe.map(p => String(p).trim());
        continue; // consume the header line
      }
      headerNames = []; // no header: remember we already looked
    }

    if (buffered.length < SAMPLE_SIZE) {
      buffered.push(line);
      continue;
    }
    if (!colMap) {
      const samples = buffered.slice(0, SAMPLE_SIZE).map(l => splitCsvLine(l));
      colMap = detectTimelineCols(samples, headerNames ?? undefined);
      if (!colMap) {
        logger.warn(`[CatScale] full-timeline.csv: cannot detect columns (${samples.length} rows sampled) — 0 rows`);
        buffered.length = 0;
        return 0;
      }
      logger.info(`[CatScale] full-timeline.csv columns: path=${colMap.path} mtime=${colMap.mtime} atime=${colMap.atime} ctime=${colMap.ctime} crtime=${colMap.crtime} user=${colMap.user} perms=${colMap.perms} size=${colMap.size}`);
      await flushBuffered();
    }
    await processLine(line);
  }

  // Handle the tail: remaining buffered lines and the case where the whole file
  // was small enough to fit in the sample buffer.
  if (!colMap) {
    const samples = buffered.slice(0, SAMPLE_SIZE).map(l => splitCsvLine(l));
    colMap = detectTimelineCols(samples, headerNames ?? undefined);
    if (!colMap) {
      logger.warn(`[CatScale] full-timeline.csv: cannot detect columns — 0 rows`);
      buffered.length = 0;
      return 0;
    }
    logger.info(`[CatScale] full-timeline.csv columns: path=${colMap.path} mtime=${colMap.mtime} atime=${colMap.atime} ctime=${colMap.ctime} crtime=${colMap.crtime} user=${colMap.user} perms=${colMap.perms} size=${colMap.size}`);
  }
  await flushBuffered();

  inserted += await batchInsert(pool, rows, link);
  if (stats) {
    stats.top_dropped_locations = [...dropped]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([path, count]) => ({ path, count }));
  }
  return inserted;
}


export interface CatScaleParseResult {
  events: number;
  hostname: string;
  os_info: string;
  collection_time: string;
  artifacts: string[];
  /** Directories the parse could not read. Non-empty means the result is not trustworthy. */
  unreadable: string[];
  /** Everything that failed along the way. Non-empty means the count is incomplete. */
  failures: CatScaleFailure[];
  /** Rows written to catscale_state — inventories that carry no timestamp of their own. */
  state_rows: number;
  /** What the filesystem noise floor removed, and why. Null when the collection
   *  carries no filesystem timeline. Surfacing this is what keeps a 92% reduction
   *  an explicit decision instead of a silent one. */
  fs_filter: FsTimelineFilterStats | null;
}

export async function parseCatScale(
  catscaleRoot: string,
  caseId: string,
  pool: Pool,
  collectionTime: Date,
  emitProgress?: (p: Record<string, unknown>) => void,
  link: TimelineLink = {},
  /** exhaustiveFsTimeline: ingest every parsable filesystem row, noise floor off.
   *  Measured cost on a real host: 4.4M rows instead of 332k. Off by default. */
  options: { exhaustiveFsTimeline?: boolean } = {},
): Promise<CatScaleParseResult> {
  let totalEvents = 0;
  const artifacts: string[] = [];
  const tempDirs: string[] = [];
  const failures: CatScaleFailure[] = [];
  // Carried on `link` so batchInsert can report without a new parameter everywhere.
  link = { ...link, failures };
  const fail = (stage: CatScaleFailure['stage'], target: string) => (e: any) => {
    const reason = e?.message ?? String(e);
    logger.warn(`[CatScale] ${stage} failed on ${path.basename(target)}: ${reason}`);
    failures.push({ stage, target, reason });
    return 0;
  };
  const unreadable = unreadableDirs(catscaleRoot);
  if (unreadable.length) {
    logger.warn(`[CatScale] ${unreadable.length} directory(ies) unreadable (permissions): ${unreadable.slice(0, 5).join(', ')}`);
  }

  const emit = (step: string) =>
    emitProgress?.({ type: 'catscale_step', step, artifact: 'catscale' });

  let hostname = 'linux-host';
  let osInfo = '';
  const sysDir = path.join(catscaleRoot, 'System_Info');
  const dateFile = findArtifactFile(sysDir, 'host-date-timezone');
  if (dateFile) {
    const base = path.basename(dateFile);
    // `date` follows the collected host's locale — a real collection reads
    // "Date : jeu. 30 juil. 2026 12:44:06 +00:00", which new Date() rejects. The
    // previous code silently kept the parse time, anchoring every artifact
    // without its own timestamp days after the facts.
    collectionTime = resolveCollectionTime(fs.readFileSync(dateFile, 'utf8'), base, collectionTime);
    hostname = base.split('-')[0] || hostname;
  }
  const releaseFile = findArtifactFile(sysDir, 'release');
  if (releaseFile) {
    const releaseContent = fs.readFileSync(releaseFile, 'utf8');
    const pretty = /PRETTY_NAME="([^"]+)"/.exec(releaseContent);
    osInfo = pretty?.[1] ?? releaseContent.split('\n')[0] ?? '';
  }

  // Kernel ring buffer — every line carries its own fully-qualified timestamp.
  for (const dmesgFile of findArtifactFiles(sysDir, 'dmesg')) {
    const n = await parseDmesg(dmesgFile, caseId, pool, collectionTime, hostname, link).catch(fail('parse', dmesgFile));
    if (n > 0) { totalEvents += n; artifacts.push(`dmesg:${path.basename(dmesgFile)} (${n})`); }
  }

  emit('auth_logs');
  const logsDir = path.join(catscaleRoot, 'Logs');
  for (const varLogTar of findArtifactFiles(logsDir, 'var-log.tar.gz')) {
    const varLogTmp = path.join(os.tmpdir(), `catscale-varlog-${caseId}-${Date.now()}`);
    tempDirs.push(varLogTmp);
    if (extractTarGz(varLogTar, varLogTmp, failures)) {
      await walkDir(varLogTmp, async (fp) => {
        const base = path.basename(fp);
        if (/^(auth\.log|secure|messages|syslog)(\.1)?$/.test(base)) {
          const n = await parseAuthLog(fp, caseId, pool, hostname, collectionTime, link).catch(fail('parse', fp));
          if (n > 0) { totalEvents += n; artifacts.push(`auth:${base} (${n})`); }
        } else if (/^audit\.log(\.\d+)?$/.test(base)) {
          const n = await parseAuditd(fp, caseId, pool, hostname, link).catch(fail('parse', fp));
          if (n > 0) { totalEvents += n; artifacts.push(`auditd:${base} (${n})`); }
        }
      });
    }
  }

  emit('logon_history');
  // Every wtmp/utmp file, not just the first: Cat-Scale.sh:393-397 walks the
  // filesystem for utmp*/wtmp* and can emit several. 'last-utmpdump' is
  // deliberately excluded — it is a utmpdump dump, not `last` output.
  for (const fp of findArtifactFiles(logsDir, 'last-wtmp', 'last-wtmpx', 'last-utmp')) {
    const n = await parseLastWtmp(fp, caseId, pool, hostname, link).catch(fail('parse', fp));
    if (n > 0) { totalEvents += n; artifacts.push(`logon:${path.basename(fp)} (${n})`); }
  }

  for (const btmpFile of findArtifactFiles(logsDir, 'last-btmp')) {
    const n = await parseLastWtmp(btmpFile, caseId, pool, hostname, link).catch(fail('parse', btmpFile));
    if (n > 0) { totalEvents += n; artifacts.push(`failed_logon:${path.basename(btmpFile)} (${n})`); }
  }

  emit('processes');
  const procDir = path.join(catscaleRoot, 'Process_and_Network');
  // Mutually exclusive formats (Cat-Scale.sh:192-202 is an if/elif chain), so the
  // first one present is the collection's process listing — not one of several.
  const procFile = findArtifactFile(procDir, 'processes-axwwSo', 'processes-auxSww', 'processes-auxww', 'processes-eF', 'processes-ef', 'processes-e');
  if (procFile) {
    const n = await parseProcessList(procFile, caseId, pool, collectionTime, hostname, link).catch(fail('parse', procFile));
    if (n > 0) { totalEvents += n; artifacts.push(`process:${path.basename(procFile)} (${n})`); }
  }

  emit('network');
  // Cat-Scale.sh:269-279 picks ss or one netstat form, but the netstat branch
  // writes both -antup and -an, so several files can legitimately coexist.
  for (const fp of findArtifactFiles(procDir, 'ss-anepo', 'netstat-pvWanoee', 'netstat-pvTanoee', 'netstat-antup', 'netstat-an')) {
    const n = await parseNetworkConnections(fp, caseId, pool, collectionTime, hostname, link).catch(fail('parse', fp));
    if (n > 0) { totalEvents += n; artifacts.push(`network:${path.basename(fp)} (${n})`); }
  }

  emit('history');
  const userFilesDir = path.join(catscaleRoot, 'User_Files');
  const homeTar = path.join(userFilesDir, 'hidden-user-home-dir.tar.gz');
  if (fs.existsSync(homeTar)) {
    const homeTmp = path.join(os.tmpdir(), `catscale-home-${caseId}-${Date.now()}`);
    tempDirs.push(homeTmp);
    if (extractTarGz(homeTar, homeTmp, failures)) {
      await walkDir(homeTmp, async (fp) => {
        const base = path.basename(fp);
        if (/^\.?(bash_history|zsh_history|sh_history|fish_history|ksh_history|history)$/.test(base)) {

          const parts = fp.split(path.sep);
          const username = parts[parts.length - 2] || 'unknown';
          const n = await parseBashHistory(fp, caseId, pool, collectionTime, username, hostname, link).catch(fail('parse', fp));
          if (n > 0) { totalEvents += n; artifacts.push(`history:${username}:${base} (${n})`); }
        }
      });
    }
  }

  emit('persistence');
  const persistDir = path.join(catscaleRoot, 'Persistence');

  for (const cronTabList of findArtifactFiles(persistDir, 'cron-tab-list')) {
    const n = await parseCronTabList(cronTabList, caseId, pool, collectionTime, hostname, link).catch(fail('parse', cronTabList));
    if (n > 0) { totalEvents += n; artifacts.push(`cron:${path.basename(cronTabList)} (${n})`); }
  }

  for (const cronFolderTar of findArtifactFiles(persistDir, 'cron-folder.tar.gz')) {
    const cronTmp = path.join(os.tmpdir(), `catscale-cron-${caseId}-${Date.now()}`);
    tempDirs.push(cronTmp);
    if (extractTarGz(cronFolderTar, cronTmp, failures)) {
      await walkDir(cronTmp, async (fp) => {
        const base = path.basename(fp);
        if (!base.includes('.') || base.endsWith('.txt')) {
          const n = await parseCronTabList(fp, caseId, pool, collectionTime, hostname, link).catch(fail('parse', fp));
          if (n > 0) { totalEvents += n; artifacts.push(`cron:spool:${base} (${n})`); }
        }
      });
    }
  }

  for (const fp of findArtifactFiles(persistDir, 'systemctl-service-status', 'systemctl_service_status', 'systemctl-all', 'systemctl_all', 'systemctl-list-units', 'systemctl-list-unit-files', 'persistence-systemdlist')) {
    const n = await parseSystemdList(fp, caseId, pool, collectionTime, hostname, link).catch(fail('parse', fp));
    if (n > 0) { totalEvents += n; artifacts.push(`systemd:${path.basename(fp)} (${n})`); }
  }

  emit('fstimeline');
  const miscDir = path.join(catscaleRoot, 'Misc');
  let fsFilter: FsTimelineFilterStats | null = null;
  for (const fsTimelineFile of findArtifactFiles(miscDir, 'full-timeline.csv')) {
    fsFilter = fsFilter ?? {
      scanned: 0, kept: 0,
      dropped: { container_layer: 0, rebuildable: 0, package_tree: 0, not_relevant: 0, unparsable: 0 },
      top_dropped_locations: [],
    };
    const n = await parseFsTimeline(fsTimelineFile, caseId, pool, hostname, collectionTime, link,
      fsFilter, options.exhaustiveFsTimeline === true)
      .catch(fail('parse', fsTimelineFile));
    if (n > 0) { totalEvents += n; artifacts.push(`fstimeline:${path.basename(fsTimelineFile)} (${n})`); }
  }
  if (fsFilter) {
    const d = fsFilter.dropped;
    const removed = d.container_layer + d.rebuildable + d.package_tree + d.not_relevant + d.unparsable;
    logger.info(`[CatScale] fs timeline: ${fsFilter.kept} kept of ${fsFilter.scanned} scanned `
      + `(${removed} filtered — containers ${d.container_layer}, rebuildable ${d.rebuildable}, `
      + `packages ${d.package_tree}, not relevant ${d.not_relevant}, unparsable ${d.unparsable})`);
  }

  // ── Host state: Docker, package integrity, kernel modules, /proc/<pid>/exe ──
  // Docker alone is 88 of the 158 files in a real collection and was never opened
  // before. These artifacts are inventories, not events, so they go to
  // catscale_state; only the container lifecycle timestamps reach the timeline.
  emit('host_state');
  let stateRows = 0;
  try {
    const collected = collectStateArtifacts(catscaleRoot, caseId, hostname, collectionTime, failures);
    if (collected.stateRows.length) {
      stateRows = await insertStateRows(pool, caseId, hostname, collectionTime, collected.stateRows, {
        evidence_id: link.evidenceId ?? null,
        result_id: link.resultId ?? null,
      });
      const byKind = collected.stateRows.reduce<Record<string, number>>((acc, r) => {
        acc[r.kind] = (acc[r.kind] ?? 0) + 1; return acc;
      }, {});
      for (const [kind, n] of Object.entries(byKind)) artifacts.push(`state:${kind} (${n})`);
    }
    if (collected.timelineRows.length) {
      const n = await batchInsert(pool, collected.timelineRows as Row[], link);
      if (n > 0) { totalEvents += n; artifacts.push(`docker:lifecycle (${n})`); }
    }
  } catch (e: any) {
    // A state-collection failure must not be reported as "no containers found".
    logger.warn(`[CatScale] host state collection failed: ${e?.message ?? e}`);
    failures.push({ stage: 'parse', target: catscaleRoot, reason: `host state: ${e?.message ?? e}` });
  }

  for (const dir of tempDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }

  logger.info(`[CatScale] ${hostname} (${osInfo || 'Linux'}): ${totalEvents} events, ${stateRows} state rows — ${artifacts.length} sources`);
  return {
    events: totalEvents, hostname, os_info: osInfo,
    collection_time: collectionTime.toISOString(), artifacts, unreadable, failures,
    state_rows: stateRows, fs_filter: fsFilter,
  };
}
