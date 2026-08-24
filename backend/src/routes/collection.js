const express = require('express');
const { execSync, execFileSync, exec, spawnSync, spawn, execFile } = require('child_process');
const { extractArgs, permissionArgs } = require('../services/archiveExtract');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const readline = require('readline');
const { Transform, Writable } = require('stream');
const { pipeline } = require('stream/promises');
const { from: pgCopyFrom } = require('pg-copy-streams');
const { parse } = require('csv-parse/sync');
const { parse: parseStream } = require('csv-parse');
const multer = require('multer');
const { pool, readPool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const esService = require('../services/elasticsearchService');
const { getRedis } = require('../config/redis');
const logger = require('../config/logger').default;
const { matchTags: matchKeywordTags } = require('../services/timelineKeywords');
const { invalidateDetectionCache } = require('../services/detectionExceptions');
const { safeBasename } = require('../services/uploadService');
const { detectMapping, loadMappings } = require('../services/timelineMappings');
const { buildSlimRaw } = require('../services/timelineFieldExtract');
const { buildHayabusaDescription } = require('../services/hayabusaDescription');
const { pushTextFilter, pushSearchFilter, splitSearchTerms } = require('../utils/textFilter');
const { fetchContext, AnchorNotFound } = require('../services/timelineContext');
const { diffTimelines } = require('../services/timelineDiff');
const { stripNullBytes, normalizeTimestamp, extractTimestamp, extractDescription } = require('../services/timelineNormalizeCore');
const { extractForensicFields } = require('../services/timelineForensicFields');
const { importCsvFile } = require('../services/csv/importCsvFile');
const { findCsvFilesRecursive } = require('../services/csv/findCsvFiles');
const { scanCollectionCsvs } = require('../services/csv/scanCollectionCsvs');
const { ZIMMERMAN_DIR, ARTIFACT_PATTERNS, ECS_COLUMNS } = require('../config/artifactPatterns');
const { PARSER_OPTIONS, defaultParserOptions, sanitizeParserOptions, appendCliFlags, buildTimeWindow } = require('../config/parserOptions');
const { purgeFsTimeline, purgeCatScaleState } = require('../services/fsTimelinePurge');
const { parseRule, buildQuery } = require('../services/sigmaService');

const router = express.Router();

// Escape LIKE metacharacters in user input: `%`/`_` are wildcards and `\` is
// PostgreSQL's DEFAULT LIKE escape character. Without this a Windows path like
// `C:\Users\…` only matches when the user doubles every backslash.
const escapeLike = (s) => String(s ?? '').replace(/[%_\\]/g, '\\$&');

const { caseAccessParam } = require('../middleware/caseAccess');
router.use(authenticate);
router.param('caseId', caseAccessParam);

// The collection_timeline DDL used to run here, at module load, as fire-and-forget
// pool.query() calls: Express started serving before they finished and nothing
// awaited their result. It now runs from server.js runMigrations(), under
// lock_timeout, before listen(). See src/config/collectionTimelineDdl.js.

const COLLECTIONS_DIR = '/app/collections';
const TEMP_DIR = '/app/temp';

const WINDOWS_ONLY_PARSERS = new Set([]);

const PYTHON_FALLBACK_PARSERS = new Set(['prefetch', 'srum', 'sqle', 'wxtcmd',
  // Custom Python parsers in /app/parsers (not Zimmerman) — bypass the ZIMMERMAN_DIR tool check.
  // registry is now parsed with parse_registry_full.py (dissect.regf full-hive dump),
  // not RECmd — the RECmd.dll tool check must not skip it.
  'userassist', 'netprofile', 'usb', 'schtasks', 'pwsh', 'dns', 'webcache', 'pcap', 'wmi', 'rdpcache', 'registry',
  'auditd', 'syslog', 'bash_history', 'unified_log']);

const LARGE_CSV_THRESHOLD = 5 * 1024 * 1024;

const UPLOAD_COLLECTION_DIR = '/app/uploads/collections';

async function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const md5    = crypto.createHash('md5');
    const sha1   = crypto.createHash('sha1');
    const sha256 = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => { md5.update(chunk); sha1.update(chunk); sha256.update(chunk); });
    stream.on('end',  () => resolve({ md5: md5.digest('hex'), sha1: sha1.digest('hex'), sha256: sha256.digest('hex') }));
    stream.on('error', reject);
  });
}
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => {
      try {
        fs.mkdirSync(UPLOAD_COLLECTION_DIR, { recursive: true });
        cb(null, UPLOAD_COLLECTION_DIR);
      } catch (err) {
        cb(err);
      }
    },
    filename: (_req, file, cb) => {
      cb(null, `${uuidv4()}-${file.originalname}`);
    },
  }),
});

const MITRE_MAP = {
  mft:       { technique_id: 'T1070.004', technique_name: 'Indicator Removal: File Deletion',               tactic: 'defense-evasion' },
  prefetch:  { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
  lnk:       { technique_id: 'T1547.009', technique_name: 'Boot or Logon Autostart: Shortcut Modification', tactic: 'persistence' },
  jumplist:  { technique_id: 'T1547.009', technique_name: 'Boot or Logon Autostart: Shortcut Modification', tactic: 'persistence' },
  shellbags: { technique_id: 'T1083',     technique_name: 'File and Directory Discovery',                   tactic: 'discovery' },
  amcache:   { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
  appcompat: { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
  evtx:      { technique_id: null,        technique_name: null,                                             tactic: 'discovery' },
  registry:  { technique_id: 'T1547.001', technique_name: 'Boot or Logon Autostart: Registry Run Keys',    tactic: 'persistence' },
  srum:      { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
  sqle:      { technique_id: 'T1217',     technique_name: 'Browser Information Discovery',                 tactic: 'collection' },
  wxtcmd:    { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
  recycle:   { technique_id: 'T1070.004', technique_name: 'Indicator Removal: File Deletion',               tactic: 'defense-evasion' },
  bits:      { technique_id: 'T1197',     technique_name: 'BITS Jobs',                                     tactic: 'persistence' },
  sum:       { technique_id: 'T1021',     technique_name: 'Remote Services',                               tactic: 'lateral-movement' },
  usn:       { technique_id: 'T1070.004', technique_name: 'Indicator Removal: File Deletion',               tactic: 'defense-evasion' },
  indx:      { technique_id: 'T1070.004', technique_name: 'Indicator Removal: File Deletion',               tactic: 'defense-evasion' },
  userassist:{ technique_id: 'T1204',     technique_name: 'User Execution',                                 tactic: 'execution' },
  netprofile:{ technique_id: 'T1016',     technique_name: 'System Network Configuration Discovery',         tactic: 'discovery' },
  usb:       { technique_id: 'T1052.001', technique_name: 'Exfiltration over USB',                          tactic: 'exfiltration' },
  schtasks:  { technique_id: 'T1053.005', technique_name: 'Scheduled Task/Job: Scheduled Task',            tactic: 'persistence' },
  pwsh:      { technique_id: 'T1059.001', technique_name: 'Command and Scripting Interpreter: PowerShell', tactic: 'execution' },
  dns:       { technique_id: 'T1071.004', technique_name: 'Application Layer Protocol: DNS',               tactic: 'command-and-control' },
  webcache:  { technique_id: 'T1217',     technique_name: 'Browser Information Discovery',                 tactic: 'collection' },
  wmi:       { technique_id: 'T1546.003', technique_name: 'Event Triggered Execution: WMI Event Subscription', tactic: 'persistence' },
  rdpcache:  { technique_id: 'T1021.001', technique_name: 'Remote Services: RDP',                          tactic: 'lateral-movement' },
  auditd:    { technique_id: 'T1059.004', technique_name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'execution' },
  syslog:    { technique_id: 'T1562.002', technique_name: 'Impair Defenses: Disable Windows Event Logging', tactic: 'defense-evasion' },
  bash_history: { technique_id: 'T1059.004', technique_name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'execution' },
  unified_log: { technique_id: 'T1059',   technique_name: 'Command and Scripting Interpreter',              tactic: 'execution' },
};

// EVTX per-EventID MITRE override — Windows Security log common events.
const EVTX_MITRE_BY_EID = {
  4624: { technique_id: 'T1078',     technique_name: 'Valid Accounts',                                   tactic: 'defense-evasion' },
  4625: { technique_id: 'T1110',     technique_name: 'Brute Force',                                      tactic: 'credential-access' },
  4688: { technique_id: 'T1059',     technique_name: 'Command and Scripting Interpreter',                tactic: 'execution' },
  1102: { technique_id: 'T1070.001', technique_name: 'Indicator Removal: Clear Windows Event Logs',      tactic: 'defense-evasion' },
  7045: { technique_id: 'T1543.003', technique_name: 'Create or Modify System Process: Windows Service', tactic: 'persistence' },
  4698: { technique_id: 'T1053.005', technique_name: 'Scheduled Task/Job: Scheduled Task',               tactic: 'persistence' },
};

function extractEcsFields(record, artifactType) {
  let mitre = MITRE_MAP[artifactType] || {};
  if (artifactType === 'evtx' || artifactType === 'hayabusa') {
    const eidRaw = record['EventId'] || record['EventID'] || record['event_id'];
    const eid = eidRaw != null && /^\d+$/.test(String(eidRaw).trim()) ? parseInt(eidRaw, 10) : null;
    if (eid !== null && EVTX_MITRE_BY_EID[eid]) mitre = EVTX_MITRE_BY_EID[eid];
  }
  const cols  = ECS_COLUMNS[artifactType] || { host: [], user: [], process: [] };
  const pick  = (candidates) =>
    candidates.reduce((acc, c) => acc || (record[c] || '').trim() || '', '') || null;
  return {
    mitre_technique_id:   mitre.technique_id   || null,
    mitre_technique_name: mitre.technique_name || null,
    mitre_tactic:         mitre.tactic         || null,
    host_name:    pick(cols.host),
    user_name:    pick(cols.user),
    process_name: pick(cols.process),
  };
}

function findFiles(dir, patterns) {
  const results = [];
  if (!fs.existsSync(dir)) return results;

  function matchesPattern(filename, pattern) {
    const parts = pattern.toLowerCase().split('/');
    const rawMatch = parts[parts.length - 1];

    if (rawMatch.startsWith('*.')) {

      return filename.endsWith(rawMatch.substring(1));
    }

    if (rawMatch.includes('*')) {

      const starIdx = rawMatch.indexOf('*');
      const prefix = rawMatch.substring(0, starIdx);
      const suffix = rawMatch.substring(starIdx + 1);

      const stripped = prefix.startsWith('$') ? prefix.substring(1) : null;
      const prefixNoSign = (stripped && stripped.length >= 3) ? stripped : null;
      const matchesPrefix = filename.startsWith(prefix) ||
                            (prefixNoSign !== null && filename.startsWith(prefixNoSign));
      return matchesPrefix && filename.endsWith(suffix);
    }

    return filename === rawMatch;
  }

  const queue = [dir];
  while (queue.length > 0) {
    const currentDir = queue.shift();
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);

        let isDir = entry.isDirectory();
        if (!isDir && entry.isSymbolicLink()) {
          try { isDir = fs.statSync(fullPath).isDirectory(); } catch (_e) {}
        }
        if (isDir) {
          queue.push(fullPath);
        } else {
          const filename = entry.name.toLowerCase();
          for (const pattern of patterns) {
            if (matchesPattern(filename, pattern)) {
              results.push(fullPath);
              break;
            }
          }
        }
      }
    } catch (err) {

      logger.warn(`[findFiles] Cannot read ${currentDir}: ${err.code || err.message}`);
    }
  }

  return [...new Set(results)];
}

function countFilesRecursive(dir) {
  let n = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) stack.push(path.join(d, e.name));
      else n++;
    }
  }
  return n;
}

async function readCsvFile(csvPath) {
  let stat;
  try { stat = fs.statSync(csvPath); } catch { return []; }

  if (stat.size <= LARGE_CSV_THRESHOLD) {

    const content = fs.readFileSync(csvPath, 'utf-8');
    return parse(content, { columns: true, skip_empty_lines: true, relax_column_count: true, relax_quotes: true });
  }

  logger.info(`[parse] Large CSV (${(stat.size / 1024 / 1024).toFixed(0)} MB) — streaming all records: ${path.basename(csvPath)}`);
  const records = [];
  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const done = (err) => { if (!settled) { settled = true; err ? reject(err) : resolve(); } };

      const csvParser = parseStream({
        columns: true,
        skip_empty_lines: true,
        relax_column_count: true,

        encoding: 'utf8',
      });

      csvParser.on('data', (record) => {
        records.push(record);
      });
      csvParser.on('end', () => {
        logger.info(`[readCsvFile] done: ${records.length} records from ${path.basename(csvPath)}`);
        done(null);
      });
      csvParser.on('error', (err) => {
        logger.warn(`[readCsvFile] csvParser error for ${path.basename(csvPath)}: ${err.message?.substring(0, 200)}`);
        done(err);
      });

      const src = fs.createReadStream(csvPath);
      let bomChecked = false;
      src.on('data', (chunk) => {
        if (!bomChecked) {
          bomChecked = true;
          if (chunk[0] === 0xEF && chunk[1] === 0xBB && chunk[2] === 0xBF) chunk = chunk.slice(3);
        }
        if (!csvParser.write(chunk)) {
          src.pause();
          csvParser.once('drain', () => src.resume());
        }
      });
      src.on('end', () => csvParser.end());
      src.on('error', done);
    });
  } catch (err) {
    logger.warn(`[readCsvFile] ${path.basename(csvPath)}: ${err.message?.substring(0, 100)}`);
  }
  return records;
}

const CT_DB_BATCH = 5000;
// Failsafe for a batch insert that wedges (lock wait under DB thrash): client-side
// timeout, then insertRowsResilient splits-and-retries so healthy rows still land.
// Generous (10 min) — a merely slow batch must be allowed to finish.
const BATCH_QUERY_TIMEOUT_MS = parseInt(process.env.PARSE_BATCH_QUERY_TIMEOUT_MS, 10) || 600000;
// All selected parsers start at once by default (runConcurrent caps to the item count).
// Tunable via env if a host needs to throttle CPU. DB writes are bounded separately below.
const PARSE_CONCURRENCY = parseInt(process.env.PARSE_CONCURRENCY, 10) || 99;

// Shared semaphore bounding TOTAL concurrent DB stream-inserts across ALL parsers, so
// launching every parser in parallel can't exhaust the pg pool (max 30). Default 20 leaves
// headroom for other queries. Tunable via DB_WRITE_CONCURRENCY.
const DB_WRITE_CONCURRENCY = parseInt(process.env.DB_WRITE_CONCURRENCY, 10) || 20;
function makeSemaphore(max) {
  let active = 0;
  const waiters = [];
  return {
    async acquire() {
      if (active >= max) await new Promise(res => waiters.push(res));
      active++;
    },
    release() {
      active--;
      const next = waiters.shift();
      if (next) next();
    },
  };
}
const dbWriteSem = makeSemaphore(DB_WRITE_CONCURRENCY);

// In-memory per-case parse progress so the UI can re-attach after navigation.
// Work itself runs detached server-side and survives the page; this just lets a
// returning client poll the current state. Lost on backend restart (acceptable).
const PARSE_PROGRESS = new Map(); // caseId -> { parsers:{key:{status,records,name}}, globalPct, updatedAt }

// Active parse jobs, keyed by `${caseId}::${collDir}`. Prevents launching a
// second analysis on the SAME collection while one is still writing: the new
// job's init transaction deletes the old job's parser_results + timeline rows,
// which would wipe the first job's output mid-write. Different collections of
// the same case may still parse concurrently.
const ACTIVE_PARSE_LOCKS = new Set();
// Per-case in-flight guard for the /hayabusa route. The parse pipeline auto-
// triggers Hayabusa after an EVTX parse (startRunAll) AND the frontend calls
// POST /hayabusa after parse:done — without a lock those two would race,
// each wiping the other's partial stream-insert (initHayabusaRecord deletes
// existing rows first). 409 the loser instead.
const ACTIVE_HAYABUSA_LOCKS = new Set();

// Parser outcomes that map to a finished (green) state in the cockpit — the
// parse loop emits 'success' for Windows parsers but 'ok' for pcap/rdpcache/
// CatScale and 'degraded' for empty-but-valid runs.
const DONE_STATUSES = new Set(['success', 'ok', 'degraded']);

// Durable progress mirror. The in-memory PARSE_PROGRESS map is fast for live
// polls but vanishes on a backend restart; every throttled write here snapshots
// it into the active UnifiedTimeline parser_results row so a returning client
// (or a restarted backend) can still re-attach the cockpit.
const progressPersistTimers = new Map(); // caseId -> setTimeout handle
function persistParseProgress(caseId, entry) {
  if (progressPersistTimers.has(caseId)) return; // one scheduled write is enough
  progressPersistTimers.set(caseId, setTimeout(() => {
    progressPersistTimers.delete(caseId);
    pool.query(
      `UPDATE parser_results
          SET output_data = $1,
              updated_at = NOW()
        WHERE case_id = $2 AND parser_name = 'UnifiedTimeline'
          AND output_data->>'status' = 'parsing'`,
      [JSON.stringify({
        status: 'parsing',
        progress: {
          globalPct: entry.globalPct,
          parsers: entry.parsers,
          updatedAt: entry.updatedAt || Date.now(),
        },
      }), caseId]
    ).catch((err) => logger.warn('[parse-progress] persist error:', err.message));
  }, 2000));
}

function updateParseProgress(caseId, validTypes, data) {
  if (!caseId) return;
  let e = PARSE_PROGRESS.get(caseId);
  if (data.type === 'start' || !e) {
    e = {
      parsers: Object.fromEntries((validTypes || []).map(k => [k, { status: 'queued', records: 0, name: ARTIFACT_PATTERNS[k]?.name || k }])),
      globalPct: 0,
      updatedAt: Date.now(),
    };
    PARSE_PROGRESS.set(caseId, e);
  }
  // Heartbeat: a long-running phase (a multi-30-min EVTX/MFT/USN tool run, a
  // slow stream insert) produces no artifact_start/artifact_done events, which
  // used to let the wedged-parse detector in /parse-progress declare a LIVE
  // parse dead after 30 min. Refreshing updatedAt (and the durable snapshot)
  // on a timer keeps the cockpit honest without touching parser state.
  if (data.type === 'heartbeat') {
    e.updatedAt = Date.now();
    persistParseProgress(caseId, e);
    return;
  }
  if (data.type === 'artifact_start' && data.artifact) {
    if (!e.parsers[data.artifact]) e.parsers[data.artifact] = { status: 'queued', records: 0, name: data.name || data.artifact };
    e.parsers[data.artifact].status = 'parsing';
  }
  if (data.type === 'artifact_done' && data.artifact) {
    const st = DONE_STATUSES.has(data.status) ? 'done' : data.status === 'skipped' ? 'skipped' : 'error';
    e.parsers[data.artifact] = { ...(e.parsers[data.artifact] || { name: data.name || data.artifact }), status: st, records: data.records ?? 0 };
  }
  // Live streaming progress: emitted per batch from streamNormalizeToDB so the
  // cockpit records/throughput advance during the long CSV phase, not only at
  // artifact_done (which is what made a healthy parse look frozen at a multiple
  // of 5000 records). `fraction` = bytes consumed / file size for this artifact.
  // Falls through to the globalPct recompute below so the % moves too.
  if (data.type === 'artifact_progress' && data.artifact) {
    const st = e.parsers[data.artifact];
    if (st && st.status === 'parsing') {
      if (typeof data.records === 'number') st.records = data.records;
      if (typeof data.fraction === 'number') st.fraction = data.fraction;
    }
    e.updatedAt = Date.now();
  }
  // Global % from the COUNT of finished parsers — robust to parallel start order.
  // (The event `current` is a start index, not a completion count, so it can't drive %.)
  // In-progress artifacts contribute their bytes-fraction so the % moves during
  // long streams instead of staying pinned until the artifact fully completes.
  // An in-progress fraction is capped below 1.0: bytesRead counts bytes FED to
  // the CSV parser, which races ahead of the actual row inserts — a fraction of
  // 1.0 with status still 'parsing' used to light the cockpit at 100% while the
  // last batches were still landing. 100% is only ever reached when every
  // artifact has actually finished (done/skipped/error).
  const states = Object.values(e.parsers);
  let weighted = 0;
  for (const p of states) {
    if (p.status === 'done' || p.status === 'skipped' || p.status === 'error') weighted += 1;
    else if (p.status === 'parsing' && typeof p.fraction === 'number') weighted += Math.min(0.99, Math.max(0, p.fraction));
  }
  e.globalPct = states.length ? Math.round((weighted / states.length) * 100) : 0;
  e.updatedAt = Date.now();
  persistParseProgress(caseId, e);
}

async function runConcurrent(items, fn, concurrency) {
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
}
function tsInWindow(iso, timeWindow) {
  if (!timeWindow || (!timeWindow.since && !timeWindow.until)) return true;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return true;
  if (timeWindow.since && t < timeWindow.since.getTime()) return false;
  if (timeWindow.until && t > timeWindow.until.getTime()) return false;
  return true;
}

async function streamNormalizeToDB(csvPath, caseId, resultId, artifactType, config, evidenceId = null, sourceDevice = null, timeWindow = null, onProgress = null) {
  let csvSize = 0;
  try { csvSize = fs.statSync(csvPath).size; } catch { return { rawCount: 0, normalized: 0, columns: [] }; }

  let batch = [];
  let rawCount = 0;
  let normalized = 0;
  let columns = [];
  const benchStart = Date.now();
  let pgMs = 0;
  let insertFailedRows = 0;
  let firstInsertError = null;
  // Live progress: the artifact_done event only fires once the whole CSV is
  // streamed, which froze the cockpit (records, %, throughput) for the 30+ min
  // a big EVTX/MFT/USN CSV takes. Report running records + bytes-fraction on a
  // throttle so the UI advances continuously instead of "stuck at 15 000".
  let bytesRead = 0;
  let lastProgressAt = 0;
  let lastAliveLogAt = 0;
  const maybeProgress = (final = false) => {
    const now = Date.now();
    if (!onProgress) return;
    if (!final && now - lastProgressAt < 2000) return;
    lastProgressAt = now;
    try {
      onProgress({
        records: normalized,
        rawCount,
        fraction: csvSize > 0 ? Math.min(1, bytesRead / csvSize) : 0,
        bytesRead,
        size: csvSize,
      });
    } catch (_e) {}
  };
  const maybeAliveLog = () => {
    const now = Date.now();
    if (now - lastAliveLogAt < 60000) return;
    lastAliveLogAt = now;
    const s = Math.round((now - benchStart) / 1000);
    logger.info(`[stream] ${artifactType} ${path.basename(csvPath)}: ${normalized} rows inserted in ${s}s (${bytesRead}/${csvSize} bytes) — still running`);
  };
  // Rows with no parseable timestamp are kept (searchable) and anchored here.
  const fallbackTs = new Date().toISOString();

  // USN rename pairing: the journal writes RenameOldName + RenameNewName as two
  // back-to-back records for the same file identity (EntryNumber|SequenceNumber).
  // Keep a bounded map of the latest record per identity so the second record of
  // the pair can carry the previous name: "new.txt (renamed from: old.txt)".
  const usnRenameMap = new Map();
  const USN_RENAME_MAP_MAX = 20000;

  const insertBatch = async (rows) => {
    if (rows.length === 0) return;
    const caseIds = [], resultIds = [], evidenceIds = [], timestamps = [], artTypes = [];
    const artNames = [], descriptions = [], sources = [], raws = [];
    const hostNames = [], userNames = [], processNames = [];
    const mitreTechIds = [], mitreTechNames = [], mitreTactics = [], sourceDevices = [];
    // v2.23 unified forensic columns
    const tools = [], tsKinds = [], detailsArr = [], paths = [], exts = [];
    const eventIds = [], fileSizes = [], srcIps = [], dstIps = [], sha1s = [], dedupeHashes = [];
    const tagsArr = [];
    const detectionsArr = []; // v2.26 — per-row threat engine hits (jsonb[])

    // De-dup inside the batch so the unique (case_id, dedupe_hash) partial index
    // doesn't raise on a single INSERT affecting the same target row twice.
    const seen = new Set();
    for (const rec of rows) {
      if (rec.dedupe_hash) {
        if (seen.has(rec.dedupe_hash)) continue;
        seen.add(rec.dedupe_hash);
      }
      caseIds.push(caseId);         resultIds.push(resultId);
      evidenceIds.push(evidenceId); timestamps.push(rec.timestamp);
      artTypes.push(rec.artifact_type);   artNames.push(rec.artifact_name);
      descriptions.push(rec.description); sources.push(rec.source);
      raws.push(JSON.stringify(rec.raw));
      hostNames.push(rec.host_name    || sourceDevice || null);
      userNames.push(rec.user_name    || null);
      processNames.push(rec.process_name || null);
      mitreTechIds.push(rec.mitre_technique_id   || null);
      mitreTechNames.push(rec.mitre_technique_name || null);
      mitreTactics.push(rec.mitre_tactic           || null);
      sourceDevices.push(sourceDevice              || null);
      tools.push(rec.tool              || null);
      tsKinds.push(rec.timestamp_kind  || null);
      detailsArr.push(rec.details      || null);
      paths.push(rec.path              || null);
      exts.push(rec.ext                || null);
      eventIds.push(rec.event_id == null ? null : rec.event_id);
      fileSizes.push(rec.file_size == null ? null : rec.file_size);
      srcIps.push(rec.src_ip           || null);
      dstIps.push(rec.dst_ip           || null);
      sha1s.push(rec.sha1              || null);
      dedupeHashes.push(rec.dedupe_hash || null);
      tagsArr.push(JSON.stringify(Array.isArray(rec.tags) ? rec.tags : []));
      detectionsArr.push(Array.isArray(rec.detections) && rec.detections.length
        ? JSON.stringify(rec.detections)
        : null);
    }

    const t0 = Date.now();
    // Plain single-statement insert (autocommit). The write pool deliberately
    // has no server-side statement_timeout, and a 5000-row UNNEST against 15
    // indexes can legitimately take a while on a small DB — a merely slow batch
    // must be allowed to finish. BUT a batch that waits on a lock forever (DB
    // thrashing, autovacuum canceled, a stuck peer) used to freeze the whole
    // CSV stream at that batch boundary (progress stuck at a multiple of 5000).
    // A generous client-side query_timeout fires only on a genuinely wedged
    // query; insertRowsResilient then splits-and-retries the batch, so healthy
    // rows still land and the stream keeps moving.
    const r = await pool.query(
      {
        text: `INSERT INTO collection_timeline
         (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
          host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic, source_device,
          tool, timestamp_kind, details, "path", ext, event_id, file_size, src_ip, dst_ip, sha1, dedupe_hash, tags, detections)
       SELECT u.case_id, u.result_id, u.evidence_id, u.ts, u.art_type, u.art_name, u.descr, u.src, u.rw,
              u.hn, u.un, u.pn, u.mti, u.mtn, u.mt, u.sd,
              u.tl, u.tk, u.dt, u.pth, u.ex, u.eid, u.fs, u.sip, u.dip, u.s1, u.dh,
              COALESCE(ARRAY(SELECT jsonb_array_elements_text(u.tg)), '{}')::text[],
              u.det
         FROM UNNEST(
           $1::uuid[], $2::uuid[], $3::uuid[], $4::timestamptz[], $5::text[], $6::text[], $7::text[], $8::text[], $9::jsonb[],
           $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[],
           $17::text[], $18::text[], $19::text[], $20::text[], $21::text[], $22::int[], $23::bigint[], $24::inet[], $25::inet[], $26::text[], $27::text[],
           $28::jsonb[], $29::jsonb[]
         ) AS u(case_id, result_id, evidence_id, ts, art_type, art_name, descr, src, rw,
                hn, un, pn, mti, mtn, mt, sd,
                tl, tk, dt, pth, ex, eid, fs, sip, dip, s1, dh, tg, det)
       ON CONFLICT DO NOTHING`,
        query_timeout: BATCH_QUERY_TIMEOUT_MS,
      },
      [caseIds, resultIds, evidenceIds, timestamps, artTypes, artNames, descriptions, sources, raws,
       hostNames, userNames, processNames, mitreTechIds, mitreTechNames, mitreTactics, sourceDevices,
       tools, tsKinds, detailsArr, paths, exts, eventIds, fileSizes, srcIps, dstIps, sha1s, dedupeHashes, tagsArr,
       detectionsArr],
    );
    pgMs += Date.now() - t0;
    return r;
  };

  // Split-and-retry insert. A single malformed row (bad ip/event_id/timestamp)
  // or a transient DB error used to reject the whole 5k-row UNNEST batch; the
  // .catch(done) then dropped the remainder of the CSV and froze the artifact
  // count at the last clean batch (e.g. 5 000 / 10 000). Halve the batch until
  // only the offending row(s) fail, so the healthy majority still lands.
  async function insertRowsResilient(rows, attempt = 0) {
    if (rows.length === 0) return { inserted: 0, error: null };
    try {
      const res = await insertBatch(rows);
      // rowCount = rows ACTUALLY inserted. ON CONFLICT DO NOTHING silently
      // skips rows whose (case_id, dedupe_hash) already exists — e.g. the same
      // hive collected live AND from a VSS shadow copy yields identical rows
      // with the same hash. Counting rows.length here (as before) made the
      // parse cockpit report ~2x the real timeline rows (1 M instead of 512 k).
      return { inserted: res && Number.isFinite(res.rowCount) ? res.rowCount : rows.length, error: null };
    } catch (err) {
      // Deadlock (40P01) / serialization (40001) are transient and not caused by
      // a bad row — retry the same batch briefly. Every other error (data/type)
      // halves below to isolate the offending row(s). The write pool sets no
      // statement timeout and insertBatch holds no lock_timeout, so 57014/55P03
      // cannot fire here.
      const transient = ['40P01', '40001'].includes(err.code);
      if (transient && attempt < 2) {
        await new Promise(r => setTimeout(r, 300 * (2 ** attempt)));
        return insertRowsResilient(rows, attempt + 1);
      }
      if (rows.length === 1) return { inserted: 0, error: err };
      const mid = Math.ceil(rows.length / 2);
      const left  = await insertRowsResilient(rows.slice(0, mid));
      const right = await insertRowsResilient(rows.slice(mid));
      return {
        inserted: left.inserted + right.inserted,
        error: left.error || right.error,
      };
    }
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err) => {
      if (!settled) {
        settled = true;
        if (err) reject(err);
        else {
          // New timeline rows → cached detection results are stale.
          if (normalized > 0) invalidateDetectionCache(caseId);
          resolve({ rawCount, normalized, columns, insertFailedRows, firstInsertError });
        }
      }
    };

    const csvParser = parseStream({
      columns: true,
      skip_empty_lines: true,
      relax_column_count: true,
      encoding: 'utf8',
    });

    // Between flushes the stream processes up to CT_DB_BATCH rows back-to-back,
    // each doing per-row enrichment (keyword gates, threat engine, JSON, hashing)
    // synchronously in the event loop. On MFT/USN/EVTX that is millions of rows;
    // without a periodic yield, HTTP (parse-progress polls, socket.io, auth) can
    // stall for minutes. Every YIELD_EVERY_ROWS rows we defer resume() to the
    // next loop tick so pending I/O gets served while the parse keeps going.
    let rowsSinceYield = 0;
    const YIELD_EVERY_ROWS = 250;

    csvParser.on('data', (rawRecord) => {
      csvParser.pause();
      rawCount++;
      if (columns.length === 0) columns = Object.keys(rawRecord);

      const clean = stripNullBytes(rawRecord);
      const tsResult = extractTimestamp(clean, config.timestampColumns);
      // Rows without a parseable timestamp were silently dropped; keep them
      // searchable by anchoring them to ingest time with a null timestamp_kind.
      const tsCol = tsResult ? tsResult.column : null;
      const tsIso = tsResult ? tsResult.timestamp : fallbackTs;
      if (tsResult && !tsInWindow(tsIso, timeWindow)) { csvParser.resume(); return; }

      const slimRaw = buildSlimRaw(clean, artifactType);

      const ecs = extractEcsFields(clean, artifactType);
      let baseDesc = extractDescription(clean, config.descriptionColumns);
      // AmcacheParser KeyName format: "ProgramName|hexhash" — strip the hash suffix
      if (artifactType === 'amcache' && baseDesc && /\|[0-9a-f]{8,}$/i.test(baseDesc)) {
        baseDesc = baseDesc.replace(/\|[0-9a-f]{8,}$/i, '').trim();
      }
      // USN: extractDescription returns only the FIRST of ['Name','UpdateReasons']
      // (usually just the file name), hiding why the journal entry happened. Keep
      // both: "file.txt | FileCreate|DataOverwrite|…". For rename records, pair
      // the RenameOldName/RenameNewName records of the same file identity so the
      // new-name record shows the old one: "Backup.7z (renamed from: Old.7z)".
      if (artifactType === 'usn') {
        const usnName   = (clean['Name'] || '').toString().trim();
        const usnReason = (clean['UpdateReasons'] || '').toString().trim();
        const usnEntry  = String(clean['EntryNumber'] || '').trim();
        const usnSeq    = String(clean['SequenceNumber'] || '').trim();
        const usnId     = (usnEntry && usnSeq) ? `${usnEntry}|${usnSeq}` : null;
        let renameNote  = '';
        if (usnId) {
          const prev = usnRenameMap.get(usnId);
          if (/RenameNewName/i.test(usnReason) && prev
              && /RenameOldName/i.test(prev.reasons) && prev.name && prev.name !== usnName) {
            renameNote = ` (renamed from: ${prev.name})`;
          }
          // Track the latest record per identity so the pair is captured in either
          // journal order, and keep the map bounded.
          if (/RenameOldName|RenameNewName/i.test(usnReason)) {
            usnRenameMap.set(usnId, { name: usnName, reasons: usnReason });
            if (usnRenameMap.size > USN_RENAME_MAP_MAX) {
              const firstKey = usnRenameMap.keys().next().value;
              if (firstKey !== undefined) usnRenameMap.delete(firstKey);
            }
          }
        }
        if (usnName && usnReason) baseDesc = `${usnName}${renameNote} | ${usnReason}`;
        else if (usnReason)       baseDesc = usnReason;
      }
      let baseSource = clean[config.sourceColumn] || '';
      // amcache ShortCuts CSV has no ProgramName — fall back to LnkName path
      if (artifactType === 'amcache' && !baseSource && clean['LnkName']) {
        baseSource = clean['LnkName'];
      }
      const forensic = extractForensicFields(clean, artifactType, config, tsCol, tsIso, baseDesc, baseSource);
      batch.push({
        timestamp:     tsIso,
        artifact_type: artifactType,
        artifact_name: config.name,
        description:   baseDesc,
        source:        baseSource,
        raw:           slimRaw,
        ...ecs,
        ...forensic,
      });

      if (artifactType === 'prefetch') {
        const execName = clean['ExecutableName'] || baseDesc;
        for (let pi = 0; pi <= 6; pi++) {
          const prevVal = clean[`PreviousRun${pi}`];
          if (!prevVal || !prevVal.trim()) continue;
          const prevTs = normalizeTimestamp(prevVal.trim());
          if (!prevTs || !tsInWindow(prevTs, timeWindow)) continue;
          const prevDesc = `${execName} [previous run]`;
          const prevForensic = extractForensicFields(clean, 'prefetch', config, `PreviousRun${pi}`, prevTs, prevDesc, baseSource);
          batch.push({
            timestamp:     prevTs,
            artifact_type: 'prefetch',
            artifact_name: config.name,
            description:   prevDesc,
            source:        baseSource,
            raw:           slimRaw,
            ...ecs,
            ...prevForensic,
          });
        }
      }

      if (batch.length >= CT_DB_BATCH) {
        const toFlush = batch;
        batch = [];
        rowsSinceYield = 0;

        insertRowsResilient(toFlush)
          .then(({ inserted, error }) => {
            normalized += inserted;
            if (error) {
              insertFailedRows += toFlush.length - inserted;
              firstInsertError = firstInsertError || error;
              logger.warn(`[parse] ${artifactType} partial insert: ${inserted}/${toFlush.length} rows | first error: ${error.message || error}`);
            }
            esService.bulkIndex(caseId, toFlush, resultId, evidenceId).catch(e =>
              logger.warn(`[ES] bulkIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
            maybeProgress();
            maybeAliveLog();
            csvParser.resume();
          })
          .catch(done);
      } else if (++rowsSinceYield >= YIELD_EVERY_ROWS) {
        // Yield to the event loop so HTTP/socket traffic is served mid-stream.
        rowsSinceYield = 0;
        setImmediate(() => csvParser.resume());
      } else {
        csvParser.resume();
      }
    });

    csvParser.on('end', () => {
      const toFlush = batch;
      batch = [];
      insertRowsResilient(toFlush)
        .then(({ inserted, error }) => {
          normalized += inserted;
          if (error) {
            insertFailedRows += toFlush.length - inserted;
            firstInsertError = firstInsertError || error;
            logger.warn(`[parse] ${artifactType} partial insert: ${inserted}/${toFlush.length} rows | first error: ${error.message || error}`);
          }
          esService.bulkIndex(caseId, toFlush, resultId, evidenceId).catch(e =>
            logger.warn(`[ES] bulkIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
          maybeProgress(true);
          const totalMs = Date.now() - benchStart;
          const rowsPerSec = totalMs > 0 ? Math.round(normalized / (totalMs / 1000)) : 0;
          logger.info(`[BENCH] ${artifactType} ${path.basename(csvPath)}: ${rawCount} raw → ${normalized} rows | total ${totalMs}ms | pg ${pgMs}ms | ${rowsPerSec} rows/s`);
          done(null);
        })
        .catch(done);
    });

    csvParser.on('error', (err) => {
      logger.warn(`[streamNorm] csvParser error in ${path.basename(csvPath)}: ${err.message?.substring(0, 200)}`);
      done(err);
    });

    const src = fs.createReadStream(csvPath);
    let bomChecked = false;
    src.on('data', (chunk) => {
      if (!bomChecked) {
        bomChecked = true;
        if (chunk[0] === 0xEF && chunk[1] === 0xBB && chunk[2] === 0xBF) chunk = chunk.slice(3);
      }
      bytesRead += chunk.length;
      if (!csvParser.write(chunk)) {
        src.pause();
        csvParser.once('drain', () => src.resume());
      }
    });
    src.on('end',   () => csvParser.end());
    src.on('error', done);
  });
}

function escShell(p) {
  return p.replace(/\$/g, '\\$');
}

const _binaryAvailable = (() => {
  const cache = {};
  return (name) => {
    if (name in cache) return cache[name];
    try { execFileSync('which', [name], { stdio: 'ignore' }); cache[name] = true; }
    catch { cache[name] = false; }
    return cache[name];
  };
})();

const _pythonModuleAvailable = (() => {
  const { spawnSync } = require('child_process');
  const cache = {};
  return (mod) => {
    if (mod in cache) return cache[mod];
    try {
      cache[mod] = spawnSync('python3', ['-c', `import ${mod}`], { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch { cache[mod] = false; }
    return cache[mod];
  };
})();

function spawnTool(args, options = {}) {
  const [binary, ...rest] = args;
  const timeoutMs = options.timeout || 600000;
  return new Promise((resolve, reject) => {
    const child = spawn(binary, rest, {
      cwd:   options.cwd,
      env:   options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    // Callers only ever read the LAST ~1500 chars of stdout (toolStdout) and the
    // FIRST ~800 chars of stderr (error message). A chatty tool (MFTECmd prints
    // per-entry progress) can otherwise accumulate unbounded strings — O(n²)
    // concatenation and memory blowup that starves the event loop mid-parse.
    // Keep a bounded rolling tail for stdout and a bounded head for stderr.
    const TOOL_OUTPUT_CAP = 16 * 1024 * 1024; // 16 MB
    child.stdout.on('data', (d) => {
      stdout += d.toString();
      if (stdout.length > TOOL_OUTPUT_CAP) stdout = stdout.slice(-TOOL_OUTPUT_CAP);
    });
    child.stderr.on('data', (d) => {
      if (stderr.length < TOOL_OUTPUT_CAP) stderr += d.toString().slice(0, TOOL_OUTPUT_CAP - stderr.length);
    });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`spawnTool timeout after ${timeoutMs}ms: ${binary}`));
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      const combined = stdout + stderr;
      if (code !== 0) {
        const err = new Error(combined.substring(0, 600) || `exit code ${code}`);
        err.status = code;
        err.stderr = stderr;
        err.stdout = stdout;
        reject(err);
      } else {
        resolve(combined);
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Which OS each detected artifact type belongs to. Mirrors, key-for-key, the
// `platform` field already carried by every entry of the ARTIFACTS map in
// frontend/src/components/collection/CollectionImportPanel.jsx — the existing
// UI-facing source of truth for "which platform does this artifact type
// belong to". Moved to services/artifactPlatform.js (Task 3 of
// docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-honest-counts.md)
// so threatHunting.ts can derive the set of platforms present in a case's
// timeline from the same table instead of maintaining a second copy.
const { ARTIFACT_TYPE_PLATFORM } = require('../services/artifactPlatform');

// The collection's platform: the one OS every *detected* artifact type agrees
// on. `detectedArtifacts` is keyed by artifact type, each entry optionally
// carrying its own `platform` (CatScale already sets one on itself; the
// non-CatScale detection loop below sets one from ARTIFACT_TYPE_PLATFORM).
// `catscale_error` (written when CatScale detection throws) carries no
// `platform` and is correctly ignored here.
//
// Rule, deliberately strict: any disagreement between detected artifact
// types, or nothing recognisable detected at all, resolves to NULL — never a
// default, never a majority vote. A wrong platform recorded against evidence
// is worse than an absent one.
function detectCollectionPlatform(detectedArtifacts) {
  const platforms = new Set(
    Object.values(detectedArtifacts)
      .map((artifact) => artifact && artifact.platform)
      .filter(Boolean)
  );
  return platforms.size === 1 ? [...platforms][0] : null;
}

router.post('/:caseId/import', authenticate, upload.single('collection'), async (req, res) => {
  const { caseId } = req.params;

  const socketId = req.body?.socketId || null;
  const io = req.app.locals.io;
  const collectionDir = path.join(COLLECTIONS_DIR, `case-${caseId}-${uuidv4()}`);
  // Optional password for encrypted .zip / .7z archives (kept out of logs).
  const archivePassword = (typeof req.body?.password === 'string' && req.body.password.trim())
    ? req.body.password
    : null;

  try {

    const caseResult = await pool.query('SELECT id FROM cases WHERE id = $1', [caseId]);
    if (caseResult.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });

    if (!req.file) return res.status(400).json({ error: 'Aucun fichier uploadé' });

    const ext = path.extname(req.file.originalname).toLowerCase();
    const RAW_ARTIFACT_EXTS = ['.evtx', '.pf', '.lnk', '.dat', '.hve', '.db', '.sqlite', '.pcap', '.pcapng', '.cap'];
    const isRawArtifact = RAW_ARTIFACT_EXTS.includes(ext);
    if (!['.zip', '.tar', '.gz', '.tgz', '.7z'].includes(ext) && !isRawArtifact) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
      return res.status(400).json({ error: 'Format non supporté. Utilisez .zip, .tar.gz ou .7z (ou déposez directement un fichier .evtx, .pf, .lnk, .dat, .pcap…)' });
    }

    fs.mkdirSync(collectionDir, { recursive: true });
    const uploadedPath = req.file.path;
    const originalFilename = req.file.originalname;
    const userId = req.user.id;
    const userIp = req.ip;

    res.json({
      collection_dir: collectionDir,
      filename: originalFilename,
      status: 'extracting',
    });

    (async () => {
      try {

        let fileHashes = { md5: null, sha1: null, sha256: null };
        try {
          fileHashes = await hashFile(uploadedPath);
          logger.info(`[collection] hashes computed: SHA-256=${fileHashes.sha256.substring(0, 16)}…`);
        } catch (e) {
          logger.warn('[collection] hash computation failed:', e.message);
        }

        if (isRawArtifact) {
          // Single raw artifact file — copy directly into collectionDir, no extraction needed
          const destPath = path.join(collectionDir, safeBasename(req.file.originalname));
          fs.copyFileSync(uploadedPath, destPath);
          logger.info(`[collection] raw artifact copied: ${req.file.originalname} → ${destPath}`);
        } else {
          const extractArgsList = extractArgs(ext, uploadedPath, collectionDir, archivePassword);
          try {
            await spawnTool(extractArgsList, { timeout: 3600000 });
          } catch (extractErr) {
            // unzip chokes on some encryptions/compressions even with the right
            // password — fall back to 7z (which also accepts -p<password>).
            logger.warn(`[collection] extraction failed (${extractErr.message}), retrying with 7z`);
            const sevenArgs = ['7z', 'x', uploadedPath, `-o${collectionDir}`, '-y'];
            if (archivePassword) sevenArgs.push(`-p${archivePassword}`);
            await spawnTool(sevenArgs, { timeout: 3600000 });
          }
        }

        // Belt and braces: unzip and 7z have their own opinions about stored modes,
        // and a directory without the traversal bit is unreadable even by its owner.
        // Guarantee the backend can walk what it just extracted.
        try {
          const [cmd, ...cargs] = permissionArgs(collectionDir);
          const r = spawnSync(cmd, cargs, { timeout: 300000 });
          if (r.status !== 0) logger.warn(`[collection] could not normalise permissions: ${r.stderr?.toString().trim()}`);
        } catch (e) { logger.warn('[collection] permission normalisation skipped:', e.message); }

        try { fs.unlinkSync(uploadedPath); } catch (_) {}

        if (socketId && io) io.to(socketId).emit('collection:progress', { type: 'extracted' });

        const detectedArtifacts = {};

        let isCatScale = false;
        try {
          const { findCatScaleRoot } = require('../services/catscaleService');
          const catscaleRoot = findCatScaleRoot(collectionDir);
          if (catscaleRoot) {
            isCatScale = true;

            let csFileCount = 0;
            try { csFileCount = fs.readdirSync(catscaleRoot).length; } catch (_e) {}
            detectedArtifacts['catscale'] = {
              files: [catscaleRoot],
              count: csFileCount,
              toolAvailable: true,
              name: 'CatScale Linux IR',
              platform: 'linux',
            };
            logger.info(`[CatScale] Detected at import: ${catscaleRoot}`);
          }
        } catch (e) {
          logger.error('[CatScale] detection at import failed:', e.message);
          detectedArtifacts['catscale_error'] = { name: 'CatScale detection failed', error: e.message, files: [], n: 0 };
        }

        if (!isCatScale) {
          for (const [artifactType, config] of Object.entries(ARTIFACT_PATTERNS)) {
            const found = findFiles(collectionDir, config.patterns);
            if (found.length > 0) {
              detectedArtifacts[artifactType] = {
                files: found,
                count: found.length,
                toolAvailable: fs.existsSync(path.join(ZIMMERMAN_DIR, config.tool)),
                name: config.name,
                platform: ARTIFACT_TYPE_PLATFORM[artifactType] || null,
              };
            }
          }
        }

        const collectionPlatform = detectCollectionPlatform(detectedArtifacts);

        // Anti-duplication: drop prior import rows whose extracted collection dir no longer
        // exists on disk (orphans from re-imports) so they stop inflating the synthesis count.
        try {
          const priorImports = await pool.query(
            `SELECT id, input_file FROM parser_results WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'`, [caseId]);
          const orphanIds = priorImports.rows.filter(r => !r.input_file || !fs.existsSync(r.input_file)).map(r => r.id);
          if (orphanIds.length) {
            await pool.query('DELETE FROM parser_results WHERE id = ANY($1::uuid[])', [orphanIds]);
            logger.info(`[import] cleaned ${orphanIds.length} orphan import rows for case ${caseId}`);
          }
        } catch (e) { logger.warn('[import] orphan cleanup failed:', e.message); }

        const collectionResult = await pool.query(
          `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by, platform)
           VALUES ($1, 'MagnetRESPONSE_Import', '1.0', $2, $3, 0, $4, $5) RETURNING id`,
          [caseId, collectionDir, JSON.stringify({ status: 'imported', detected: detectedArtifacts }), userId, collectionPlatform]
        );

        const totalFiles = Object.values(detectedArtifacts).reduce((s, a) => s + a.count, 0);

        let collectionDirSize = 0;
        try {
          const duResult = spawnSync('du', ['-sb', collectionDir], { encoding: 'utf8', timeout: 30000 });
          if (duResult.status === 0 && duResult.stdout) {
            collectionDirSize = parseInt(duResult.stdout.split('\t')[0], 10) || 0;
          }
        } catch (_e) {}

        const evidenceResult = await pool.query(
          `INSERT INTO evidence (case_id, name, original_filename, file_path, evidence_type, notes, added_by, metadata,
                                 hash_md5, hash_sha1, hash_sha256, file_size)
           VALUES ($1, $2, $3, $4, 'collection', $5, $6, $7, $8, $9, $10, $11)
           RETURNING id`,
          [caseId, 'Collecte: ' + originalFilename, originalFilename, collectionDir,
           'Import collecte forensique - ' + Object.keys(detectedArtifacts).length + ' types, ' + totalFiles + ' fichiers',
           userId, JSON.stringify({ detected: detectedArtifacts, total_files: totalFiles }),
           fileHashes.md5, fileHashes.sha1, fileHashes.sha256, collectionDirSize]
        );

        await pool.query(
          `INSERT INTO timeline_events (case_id, event_time, event_type, title, description, source, created_by)
           VALUES ($1, NOW(), 'analysis', $2, $3, 'Collection Import', $4)`,
          [caseId, 'Import collecte: ' + originalFilename,
           'Collecte importee: ' + Object.keys(detectedArtifacts).join(', ') + ' (' + totalFiles + ' fichiers)',
           userId]
        );

        await auditLog(userId, 'import_collection', 'collection', collectionResult.rows[0].id,
          { filename: originalFilename, artifacts_detected: Object.keys(detectedArtifacts) }, userIp);

        if (socketId && io) {
          io.to(socketId).emit('collection:import:done', {
            id: collectionResult.rows[0].id,
            evidence_id: (evidenceResult && evidenceResult.rows[0] && evidenceResult.rows[0].id) || null,
            collection_dir: collectionDir,
            filename: originalFilename,
            detected_artifacts: detectedArtifacts,
            total_artifact_types: Object.keys(detectedArtifacts).length,
            total_files: totalFiles,
            hashes: fileHashes,
          });
        } else {
          logger.warn('[collection] import done but no socketId — client will not be notified');
        }
      } catch (err) {
        logger.error('[collection] async import error:', err.message);
        try { fs.unlinkSync(uploadedPath); } catch (_) {}
        if (socketId && io) {
          io.to(socketId).emit('collection:import:error', {
            error: 'Erreur extraction de la collecte',
            details: err.message,
          });
        }
      }
    })();

  } catch (err) {

    logger.error('[collection] import error:', err.message);
    res.status(500).json({ error: 'Erreur import de la collecte', details: err.message });
  }
});

// Current parse progress for a case — lets the UI re-attach the monitor after
// navigation or a full page refresh. Served from the in-memory map when the
// parse lives in this process, and from the durable DB snapshot otherwise, so
// progress survives a backend restart as well.
router.get('/:caseId/parse-progress', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const e = PARSE_PROGRESS.get(caseId);
  if (e && !e.done && e.globalPct < 100) {
    const age = Date.now() - e.updatedAt;
    // A wedged parse (no progress event for 30 min) is terminal — report it as
    // an error instead of serving a frozen 'active' cockpit forever.
    if (age > 30 * 60 * 1000) {
      return res.json({ active: false, done: true, outcome: 'error', globalPct: e.globalPct, parsers: e.parsers, error: 'Analyse bloquée (aucune progression depuis 30 min)', updatedAt: e.updatedAt });
    }
    return res.json({ active: true, live: age < 15000, globalPct: e.globalPct, parsers: e.parsers });
  }
  if (e && e.done) {
    // Terminal in this process: hand back the final snapshot + outcome so the
    // UI renders 'done (N erreurs)' or the error instead of a blank void.
    return res.json({ active: false, done: true, outcome: e.outcome || 'success', globalPct: e.globalPct, parsers: e.parsers, error: e.error || null, updatedAt: e.updatedAt });
  }
  // Durable fallback: progress is snapshotted into the UnifiedTimeline row.
  // Unlike the old status='parsing'-only query, this also resolves terminal
  // rows so a client that missed the socket events still gets the outcome.
  try {
    const { rows } = await pool.query(
      `SELECT output_data FROM parser_results
        WHERE case_id = $1 AND parser_name = 'UnifiedTimeline'
        ORDER BY created_at DESC LIMIT 1`, [caseId]);
    if (rows.length) {
      const od = rows[0].output_data || {};
      const p = od.progress || {};
      const isParsing = od.status === 'parsing';
      if (isParsing && p.updatedAt && Date.now() - p.updatedAt <= 30 * 60 * 1000) {
        return res.json({ active: true, live: false, globalPct: p.globalPct || 0, parsers: p.parsers || {} });
      }
      if (!isParsing || (p.updatedAt && Date.now() - p.updatedAt > 30 * 60 * 1000)) {
        const hasResults = !!od.parse_results;
        return res.json({
          active: false, done: true,
          outcome: hasResults ? 'success' : 'error',
          globalPct: p.globalPct || (hasResults ? 100 : 0),
          parsers: p.parsers || {},
          error: hasResults ? null : 'Analyse terminée en erreur (voir les logs)',
          updatedAt: p.updatedAt || null,
        });
      }
    }
  } catch (err) {
    logger.warn('[parse-progress] DB fallback error:', err.message);
  }
  res.json({ active: false, done: false, live: false, globalPct: 0, parsers: {} });
});

// Latest completed parse result for a case. Lets a client that missed the
// collection:parse:done socket event (page refresh or reconnect mid-parse)
// still retrieve the final per-artifact results and totals.
router.get('/:caseId/parse-result', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { rows } = await pool.query(
      `SELECT output_data, record_count
         FROM parser_results
        WHERE case_id = $1 AND parser_name = 'UnifiedTimeline'
        ORDER BY created_at DESC LIMIT 1`, [caseId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Aucun résultat de parse' });
    const od = rows[0].output_data || {};
    const results = od.parse_results || null;
    res.json({
      results,
      artifact_types: od.artifact_types || [],
      total_records: (od.total_records != null ? od.total_records : rows[0].record_count) || 0,
      record_count: rows[0].record_count || 0,
      // The error/crash path marks the row terminal but never writes parse_results.
      failed: !results,
    });
  } catch (err) {
    logger.error('Parse result error:', err);
    res.status(500).json({ error: 'Erreur récupération du résultat de parse' });
  }
});

// Event-density histogram of the case timeline — buckets for the live parsing sparkline.
// Bounds are clamped to a sane window so forensic junk timestamps (year 2069…) don't skew it.
// The histogram aggregates the WHOLE case timeline (millions of rows) and is
// polled every ~10s during parsing. Caching it with a short TTL keeps the
// sparkline live (rows land continuously anyway) while cutting the aggregate
// load on Postgres from every-poll to once per TTL — searches and parses share
// the same DB, so this directly relieves the pressure the user sees.
const histogramCache = new Map(); // caseId -> { at, buckets, total, lo, hi }
const HISTOGRAM_TTL_MS = 8000;

router.get('/:caseId/timeline-histogram', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const N = Math.min(80, Math.max(12, parseInt(req.query.buckets, 10) || 48));
  const now = Date.now();
  const cached = histogramCache.get(caseId);
  if (cached && cached.n === N && now - cached.at < HISTOGRAM_TTL_MS) {
    return res.json({ buckets: cached.buckets, total: cached.total, lo: cached.lo, hi: cached.hi });
  }
  // This sparkline aggregates the whole case timeline (can be millions of rows)
  // and is polled live every ~10s during parsing. It must NEVER take a write-pool
  // connection (pool.connect() outside try/catch threw an unhandled rejection
  // when the pool saturated under the parse's batch inserts — which killed the
  // whole backend and the parse with it). Read pool + full try/catch so a slow
  // or starved run just yields empty buckets.
  let client = null;
  try {
    client = await readPool.connect();
    await client.query("SET statement_timeout = '8000'");
    const r = await client.query(
      `WITH b AS (
         SELECT MIN(timestamp) lo, MAX(timestamp) hi FROM collection_timeline
         WHERE case_id = $1 AND timestamp BETWEEN '1990-01-01' AND '2100-01-01'
       )
       SELECT width_bucket(EXTRACT(EPOCH FROM ct.timestamp),
                           EXTRACT(EPOCH FROM b.lo), EXTRACT(EPOCH FROM b.hi) + 1, $2) AS bkt,
              COUNT(*)::int AS n
         FROM collection_timeline ct, b
        WHERE ct.case_id = $1 AND ct.timestamp BETWEEN b.lo AND b.hi
        GROUP BY bkt ORDER BY bkt`, [caseId, N]);
    const bnd = await client.query(
      `SELECT MIN(timestamp) lo, MAX(timestamp) hi, COUNT(*)::int total FROM collection_timeline
        WHERE case_id = $1 AND timestamp BETWEEN '1990-01-01' AND '2100-01-01'`, [caseId]);
    const buckets = new Array(N).fill(0);
    for (const row of r.rows) { const i = (row.bkt || 1) - 1; if (i >= 0 && i < N) buckets[i] = row.n; }
    const payload = { buckets, total: bnd.rows[0]?.total || 0, lo: bnd.rows[0]?.lo || null, hi: bnd.rows[0]?.hi || null };
    histogramCache.set(caseId, { at: Date.now(), n: N, ...payload });
    if (histogramCache.size > 200) {
      for (const [k, v] of histogramCache) if (Date.now() - v.at > HISTOGRAM_TTL_MS * 4) histogramCache.delete(k);
    }
    res.json(payload);
  } catch (err) {
    logger.warn('[timeline-histogram]', err.message);
    res.json({ buckets: [], total: 0, lo: null, hi: null });
  } finally {
    if (client) {
      // Clear the timeout before returning the connection to the pool so it
      // doesn't leak onto the next query that borrows this client.
      await client.query('RESET statement_timeout').catch(() => {});
      client.release();
    }
  }
});

// RDP bitmap-cache reconstructed images — list + serve (path-traversal guarded).
router.get('/:caseId/rdp-cache', authenticate, async (req, res) => {
  const dir = path.join(COLLECTIONS_DIR, 'rdp-cache', req.params.caseId);
  try {
    const images = fs.existsSync(dir) ? fs.readdirSync(dir).filter(f => /\.(bmp|png)$/i.test(f)).sort() : [];
    res.json({ images });
  } catch { res.json({ images: [] }); }
});

router.get('/:caseId/rdp-cache/:name', authenticate, async (req, res) => {
  const { name } = req.params;
  if (!/^[\w.-]+\.(bmp|png)$/i.test(name)) return res.status(400).end();
  const base = path.join(COLLECTIONS_DIR, 'rdp-cache', req.params.caseId);
  const fp = path.join(base, name);
  if (!fp.startsWith(base + path.sep) || !fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', name.toLowerCase().endsWith('.png') ? 'image/png' : 'image/bmp');
  res.sendFile(fp);
});

// ── Parser configuration schema ──────────────────────────────────────────────
// Exposes the knobs each parser supports so the import UI can render a
// configuration panel instead of hardcoding a tool invocation per artifact.
router.get('/:caseId/parser-options', authenticate, async (_req, res) => {
  res.json({ options: PARSER_OPTIONS, defaults: defaultParserOptions() });
});

// ── Original collection files browser ────────────────────────────────────────
// Lets an analyst navigate and read the extracted files that produced the
// timeline, instead of only seeing the normalized rows. All paths are resolved
// against the case's collection root with traversal (incl. symlink) guards.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function resolveCollectionRoot(caseId, { evidence_id, collection_dir } = {}) {
  const candidates = [];
  if (collection_dir && typeof collection_dir === 'string') candidates.push(collection_dir);
  if (evidence_id && typeof evidence_id === 'string') {
    if (!UUID_RE.test(evidence_id)) return null;
    try {
      const row = await pool.query('SELECT file_path FROM evidence WHERE id = $1 AND case_id = $2', [evidence_id, caseId]);
      if (row.rows.length && row.rows[0].file_path) candidates.push(row.rows[0].file_path);
    } catch (_e) {}
  }
  try {
    const latest = await pool.query(
      `SELECT input_file FROM parser_results WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import' ORDER BY created_at DESC LIMIT 1`,
      [caseId]);
    if (latest.rows.length && latest.rows[0].input_file) candidates.push(latest.rows[0].input_file);
  } catch (_e) {}

  const base = path.resolve(COLLECTIONS_DIR) + path.sep;
  for (const c of candidates) {
    if (!c || !fs.existsSync(c)) continue;
    let abs;
    try { abs = path.resolve(c); } catch { continue; }
    if (!(abs === path.resolve(COLLECTIONS_DIR) || abs.startsWith(base))) continue;
    try { if (fs.statSync(abs).isDirectory()) return abs; } catch (_e) {}
  }
  return null;
}

// Resolve a relative path inside a root; refuse escapes (both lexical and via symlinks).
function safeJoin(root, rel) {
  const rootAbs = path.resolve(root);
  const target = path.resolve(rootAbs, rel == null || rel === '' ? '.' : String(rel));
  if (target !== rootAbs && !target.startsWith(rootAbs + path.sep)) return null;
  return target;
}

function realpathContained(root, target) {
  const rootAbs = path.resolve(root);
  let real;
  try { real = fs.realpathSync(target); } catch { return null; }
  if (real !== rootAbs && !real.startsWith(rootAbs + path.sep)) return null;
  return real;
}

function listDir(root, dirAbs) {
  const entries = [];
  const names = fs.readdirSync(dirAbs, { withFileTypes: true });
  for (const d of names) {
    const full = path.join(dirAbs, d.name);
    let type = d.isDirectory() ? 'dir' : 'file';
    let size = null;
    let mtime = null;
    try {
      const st = fs.statSync(full);
      if (st.isDirectory()) type = 'dir';
      else if (!st.isFile()) continue; // sockets/devices etc.
      size = st.size;
      mtime = st.mtime ? st.mtime.toISOString() : null;
    } catch (_e) {
      // Broken symlink or unreadable entry — keep it as a non-expandable file.
      try { const lst = fs.lstatSync(full); if (lst.isSymbolicLink()) type = 'file'; else continue; } catch { continue; }
    }
    entries.push({
      name: d.name,
      path: path.relative(root, full).split(path.sep).join('/'),
      type,
      size,
      mtime,
    });
  }
  // Directories first, then files, case-insensitive alphabetical.
  entries.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) : a.type === 'dir' ? -1 : 1));
  return entries;
}

router.get('/:caseId/files', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const dirAbs = safeJoin(root, req.query.path);
  if (!dirAbs) return res.status(400).json({ error: 'Chemin invalide' });
  const real = realpathContained(root, dirAbs);
  if (!real) return res.status(403).json({ error: 'Chemin hors de la collecte' });
  if (!fs.statSync(real).isDirectory()) return res.status(400).json({ error: 'Ce chemin n\'est pas un répertoire' });

  const MAX_ENTRIES = 2000;
  const all = listDir(root, real);
  const truncated = all.length > MAX_ENTRIES;
  res.json({
    root: path.basename(root),
    path: path.relative(root, real).split(path.sep).join('/'),
    parent: real === root ? null : path.relative(root, path.dirname(real)).split(path.sep).join('/'),
    truncated,
    entries: truncated ? all.slice(0, MAX_ENTRIES) : all,
  });
});

const TEXT_PREVIEW_MAX = 1024 * 1024;  // 1 MB of decoded text per request
const HEX_PREVIEW_MAX = 4096;          // binary preview is a hex dump, keep it small

function looksBinary(buf) {
  const sample = buf.subarray(0, 8192);
  if (sample.includes(0)) return true;
  let nonPrintable = 0;
  for (const b of sample) {
    if (b < 0x09 || (b > 0x0d && b < 0x20) || b === 0x7f) nonPrintable++;
  }
  return sample.length > 0 && nonPrintable / sample.length > 0.3;
}

function toHexDump(buf) {
  const hex = buf.toString('hex');
  const ascii = buf.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
  return { hex, ascii };
}

router.get('/:caseId/file/content', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const target = safeJoin(root, req.query.path);
  if (!target) return res.status(400).json({ error: 'Chemin invalide' });
  const real = realpathContained(root, target);
  if (!real) return res.status(403).json({ error: 'Chemin hors de la collecte' });
  if (!fs.statSync(real).isFile()) return res.status(400).json({ error: 'Ce chemin n\'est pas un fichier' });

  const size = fs.statSync(real).size;
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

  // Peek the first bytes to decide text vs binary before reading a (possibly
  // huge) preview window.
  const probeLen = Math.min(size, 8192);
  const probeFd = fs.openSync(real, 'r');
  const probe = Buffer.alloc(probeLen);
  const probeRead = fs.readSync(probeFd, probe, 0, probeLen, 0);
  fs.closeSync(probeFd);
  const binary = looksBinary(probe.subarray(0, probeRead));

  if (binary) {
    const len = Math.min(HEX_PREVIEW_MAX, Math.max(0, size - offset));
    const fd = fs.openSync(real, 'r');
    const buf = Buffer.alloc(len);
    const n = fs.readSync(fd, buf, 0, len, offset);
    fs.closeSync(fd);
    return res.json({ name: path.basename(real), path: path.relative(root, real).split(path.sep).join('/'), size, offset, length: n, truncated: offset + n < size, binary: true, ...toHexDump(buf.subarray(0, n)) });
  }

  const limit = Math.min(TEXT_PREVIEW_MAX, Math.max(1, parseInt(req.query.limit, 10) || 262144));
  const len = Math.min(limit, Math.max(0, size - offset));
  const fd = fs.openSync(real, 'r');
  const buf = Buffer.alloc(len);
  const n = fs.readSync(fd, buf, 0, len, offset);
  fs.closeSync(fd);
  const text = buf.subarray(0, n).toString('utf8');
  res.json({ name: path.basename(real), path: path.relative(root, real).split(path.sep).join('/'), size, offset, length: n, truncated: offset + n < size, binary: false, text });
});

router.get('/:caseId/file/download', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const target = safeJoin(root, req.query.path);
  if (!target) return res.status(400).json({ error: 'Chemin invalide' });
  const real = realpathContained(root, target);
  if (!real) return res.status(403).json({ error: 'Chemin hors de la collecte' });
  if (!fs.statSync(real).isFile()) return res.status(400).json({ error: 'Ce chemin n\'est pas un fichier' });

  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(real).replace(/"/g, '')}"`);
  res.sendFile(real);
});

// ── Registry hive browser ────────────────────────────────────────────────────
// Browse one hive file (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, UsrClass.dat, …) key
// by key in the Files view. RECmd's batch files only extract a curated subset of
// keys, so the analyst needs a way to walk the whole hive (e.g. WinSCP sessions
// that live outside the batch's key list). Uses dissect.regf via a small Python
// helper — pure Python, already installed, no Windows DLLs.
router.get('/:caseId/file/hive', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const target = safeJoin(root, req.query.path);
  if (!target) return res.status(400).json({ error: 'Chemin invalide' });
  const real = realpathContained(root, target);
  if (!real) return res.status(403).json({ error: 'Chemin hors de la collecte' });
  try {
    if (!fs.statSync(real).isFile()) return res.status(400).json({ error: 'Ce chemin n\'est pas un fichier' });
  } catch (_e) {
    return res.status(404).json({ error: 'Fichier introuvable' });
  }

  const keyPath = String(req.query.key || '').slice(0, 2048);
  const search = String(req.query.search || '').trim().slice(0, 256);
  // Python parsers live in /app/parsers (bundled in the image), not under src/.
  const script = '/app/parsers/parse_hive_browse.py';
  try {
    // spawnSync (not spawnTool): dissect.regf logs hive-integrity warnings to
    // stderr (dirty hive, open transaction), and mixing stderr into the JSON
    // payload would break JSON.parse. Parse stdout only; the exit status and
    // stderr still surface in the error path.
    const run = spawnSync(
      'python3',
      [script, '-f', real,
        ...(search ? ['--search', search] : []),
        ...(!search && keyPath ? ['-p', keyPath] : []),
        '--limit', '500'],
      { encoding: 'utf8', timeout: 60000, maxBuffer: 64 * 1024 * 1024 }
    );
    if (run.error) throw run.error;
    if (run.status !== 0) {
      const stderr = String(run.stderr || '').trim().slice(0, 500);
      logger.warn(`[hive-browse] script exit ${run.status}: ${stderr}`);
      return res.status(500).json({ error: 'Impossible de lire ce hive (fichier corrompu ou non registre ?)' });
    }
    const data = JSON.parse(String(run.stdout || '').trim() || '{}');
    if (data.error) return res.status(400).json({ error: data.error });
    // A readable hive always returns values/subkeys (browse) or matches (search).
    // An empty {} means the helper produced no output at all — surface it as a
    // real error instead of silently rendering a blank panel.
    if (!Array.isArray(data.values) && !Array.isArray(data.subkeys) && !Array.isArray(data.matches)) {
      const stderr = String(run.stderr || '').trim().slice(0, 300);
      logger.warn(`[hive-browse] empty output for ${path.basename(real)} (exit ${run.status}): ${stderr || 'no stderr'}`);
      return res.status(500).json({ error: 'Impossible de lire ce hive (sortie vide du parseur)' });
    }
    res.json(data);
  } catch (e) {
    logger.warn(`[hive-browse] ${path.basename(real)}: ${String(e.message).substring(0, 200)}`);
    return res.status(500).json({ error: 'Impossible de lire ce hive (fichier corrompu ou non registre ?)' });
  }
});

// ── Export all recovered MFT resident files as a single ZIP ──────────────────
// The parse step (--dr) copies carved resident files into <coll>/_mft_resident,
// optionally under one subdir per $MFT source. This endpoint zips that tree and
// streams it so the analyst can take the whole set away in one click.

router.get('/:caseId/mft-resident/export', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const residentDir = path.join(root, '_mft_resident');
  try {
    if (!fs.existsSync(residentDir) || !fs.statSync(residentDir).isDirectory()) {
      return res.status(404).json({ error: 'Aucun fichier resident récupéré. Activez « Récupérer les fichiers residents » puis re-parsez le $MFT.' });
    }
  } catch (_e) {
    return res.status(404).json({ error: 'Aucun fichier resident récupéré. Activez « Récupérer les fichiers residents » puis re-parsez le $MFT.' });
  }

  const fileCount = countFilesRecursive(residentDir);
  if (fileCount === 0) {
    return res.status(404).json({ error: 'Aucun fichier resident à exporter.' });
  }

  const zipPath = path.join(TEMP_DIR, `mft_resident_${caseId}_${Date.now()}.zip`);
  try {
    // 7z (p7zip-full) with cwd=residentDir zips the contents with relative paths
    // (per-source subdirs preserved, no `_mft_resident/` wrapper). 7za is the
    // fallback in case only the standalone variant is on PATH.
    try {
      await spawnTool(['7z', 'a', '-tzip', '-y', '-bso0', '-bsp0', zipPath, '.'], { cwd: residentDir, timeout: 600000 });
    } catch (e7z) {
      await spawnTool(['7za', 'a', '-tzip', '-y', '-bso0', '-bsp0', zipPath, '.'], { cwd: residentDir, timeout: 600000 });
    }
  } catch (err) {
    fs.rmSync(zipPath, { force: true });
    logger.error('MFT resident export error:', err.message);
    return res.status(500).json({ error: "Erreur lors de la création de l'archive ZIP" });
  }

  res.download(zipPath, `mft_resident_${fileCount}.zip`, (dlErr) => {
    fs.rmSync(zipPath, { force: true });
    if (dlErr && !res.headersSent) {
      logger.error('MFT resident download error:', dlErr.message);
    }
  });
});

// ── Full-text search across the collection's files ───────────────────────────
// Keyword (case-insensitive substring) or regex search over every text file
// under the given directory (default: collection root). Bounded so a huge
// collection can't starve the backend: max files walked, max bytes read per
// file, max matches per file and per run. Binary files are detected from the
// header and skipped.
const FILE_SEARCH_MAX_FILE = 2 * 1024 * 1024;        // skip files larger than this
const FILE_SEARCH_MAX_FILES = 2000;                  // stop walking after this many files
const FILE_SEARCH_MAX_FILES_MATCHED = 200;           // stop collecting after this many hits
const FILE_SEARCH_MAX_MATCHES_PER_FILE = 10;
const FILE_SEARCH_LINE_MAX = 300;

router.get('/:caseId/files/search', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const rawQ = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : '';
  if (!rawQ.trim()) return res.status(400).json({ error: 'Paramètre q manquant' });
  const isRegex = req.query.regex === '1' || req.query.regex === 'true';

  let re;
  try {
    re = isRegex
      ? new RegExp(rawQ, 'gi')
      : new RegExp(rawQ.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  } catch (_e) {
    return res.status(400).json({ error: 'Expression régulière invalide' });
  }

  const root = await resolveCollectionRoot(caseId, req.query);
  if (!root) return res.status(404).json({ error: 'Répertoire de collecte introuvable' });

  const dirAbs = safeJoin(root, req.query.path);
  if (!dirAbs) return res.status(400).json({ error: 'Chemin invalide' });
  const real = realpathContained(root, dirAbs);
  if (!real) return res.status(403).json({ error: 'Chemin hors de la collecte' });
  if (!fs.statSync(real).isDirectory()) return res.status(400).json({ error: 'Ce chemin n\'est pas un répertoire' });

  const hits = [];
  let scanned = 0;
  const queue = [real];
  while (queue.length > 0 && hits.length < FILE_SEARCH_MAX_FILES_MATCHED) {
    if (scanned >= FILE_SEARCH_MAX_FILES) break;
    const current = queue.shift();
    let names;
    try { names = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
    for (const d of names) {
      if (scanned >= FILE_SEARCH_MAX_FILES || hits.length >= FILE_SEARCH_MAX_FILES_MATCHED) break;
      const full = path.join(current, d.name);
      let st;
      try { st = fs.statSync(full); } catch { continue; }
      if (st.isDirectory()) { queue.push(full); continue; }
      if (!st.isFile()) continue;
      scanned++;
      if (st.size > FILE_SEARCH_MAX_FILE) continue;

      const probe = Buffer.alloc(Math.min(st.size, 8192));
      let fd;
      try { fd = fs.openSync(full, 'r'); } catch { continue; }
      const n = fs.readSync(fd, probe, 0, probe.length, 0);
      fs.closeSync(fd);
      if (looksBinary(probe.subarray(0, n))) continue;

      let text;
      try { text = fs.readFileSync(full, 'utf8'); } catch { continue; }
      const matches = [];
      const lines = text.split('\n');
      for (let i = 0; i < lines.length && matches.length < FILE_SEARCH_MAX_MATCHES_PER_FILE; i++) {
        re.lastIndex = 0;
        if (re.test(lines[i])) {
          matches.push({ line: i + 1, text: lines[i].slice(0, FILE_SEARCH_LINE_MAX) });
        }
      }
      if (matches.length > 0) {
        hits.push({
          path: path.relative(root, full).split(path.sep).join('/'),
          name: d.name,
          size: st.size,
          matches,
        });
      }
    }
  }

  res.json({
    query: rawQ,
    regex: isRegex,
    scanned,
    truncated: scanned >= FILE_SEARCH_MAX_FILES || hits.length >= FILE_SEARCH_MAX_FILES_MATCHED,
    matched_files: hits.length,
    files: hits,
  });
});

router.post('/:caseId/parse', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const { collection_dir, artifact_types, types, evidence_id: bodyEvidenceId } = req.body;

  // Per-parser configuration (validated against the schema in parserOptions.js).
  const parserOptions = sanitizeParserOptions(req.body?.parser_options);
  const timeWindow = buildTimeWindow(parserOptions);

  const requestedTypes = artifact_types || types;

  let collDir = collection_dir;
  let evidenceIdFromBody = null;

  if (bodyEvidenceId) {
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(bodyEvidenceId)) {
      return res.status(400).json({ error: 'evidence_id invalide' });
    }
    const evRow = await pool.query(
      `SELECT id, file_path FROM evidence WHERE id = $1 AND case_id = $2`,
      [bodyEvidenceId, caseId]
    );
    if (evRow.rows.length === 0) {
      return res.status(403).json({ error: 'Collecte introuvable ou accès refusé' });
    }
    evidenceIdFromBody = evRow.rows[0].id;
    if (!collDir || !fs.existsSync(collDir)) collDir = evRow.rows[0].file_path;
  }

  if (!collDir || !fs.existsSync(collDir)) {
    try {
      const latest = await pool.query(
        `SELECT output_data->>'collection_dir' as dir, input_file FROM parser_results
         WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import' ORDER BY created_at DESC LIMIT 1`, [caseId]);
      if (latest.rows.length > 0) {
        collDir = latest.rows[0].dir || latest.rows[0].input_file;
      }
    } catch (e) {}
  }

  if (!collDir || !fs.existsSync(collDir)) {
    return res.status(400).json({ error: 'Repertoire de collecte invalide. Importez une collecte d\'abord.' });
  }

  // Guard against launching a second analysis on the same collection while one
  // is still running. The lock is taken synchronously here (before any await);
  // it is released in the job's finally below (and on the init-error path).
  const lockKey = `${caseId}::${collDir}`;
  if (ACTIVE_PARSE_LOCKS.has(lockKey)) {
    return res.status(409).json({
      error: 'Une analyse est déjà en cours pour cette collecte',
      details: 'Attendez la fin de l\'analyse en cours avant d\'en lancer une autre sur la même collecte.',
    });
  }
  ACTIVE_PARSE_LOCKS.add(lockKey);

  const typesToParse = requestedTypes === 'all'
    ? Object.keys(ARTIFACT_PATTERNS)
    : (Array.isArray(requestedTypes) ? requestedTypes : [requestedTypes]);

  // A partial re-parse re-runs only a SUBSET of the artifact types of a
  // collection. In that case the other types' timeline rows and their
  // parse_results must survive: deleting the whole result row (the legacy
  // full-reparse path) would cascade-delete EVTX/MFT/… that were not selected.
  // When no explicit subset is given the legacy "replace everything" semantics
  // are preserved so the existing Re-parser button keeps its behaviour.
  const allTypeKeys = Object.keys(ARTIFACT_PATTERNS);
  const isPartialReparse = Array.isArray(requestedTypes)
    && requestedTypes.length > 0
    && requestedTypes.some(t => ARTIFACT_PATTERNS[t])
    && requestedTypes.length < allTypeKeys.length;

  const io       = req.app.locals.io;
  const socketId = req.body.socketId || null;
  const validTypes = typesToParse.filter(t => ARTIFACT_PATTERNS[t]);
  const totalTypes = validTypes.length;
  let   currentType = 0;

  function emitProgress(data) {
    if (socketId && io) io.to(socketId).emit('collection:progress', data);
    // Mirror into the in-memory store so a returning client can re-attach the live view.
    try { updateParseProgress(caseId, validTypes, data); } catch (_e) {}
  }
  emitProgress({ type: 'start', total: totalTypes, artifacts: validTypes });

  const results = {};
  let totalRecords = 0;

  // Read-only lookups — no concurrency risk, done before the transaction
  let evidenceId = evidenceIdFromBody;
  if (!evidenceId) {
    try {
      const evRow = await pool.query(
        `SELECT id FROM evidence WHERE case_id = $1 AND file_path = $2 LIMIT 1`,
        [caseId, collDir]
      );
      if (evRow.rows.length > 0) evidenceId = evRow.rows[0].id;
    } catch (_e) {}
  }
  // Last-resort linkage: when no evidence is bound by body or exact file_path
  // (e.g. a re-parse from a view that does not carry evidence_id), attach the
  // case's most-populated evidence so inserted rows are NEVER orphaned — rows
  // with NULL evidence_id show up in the SuperTimeline but are invisible in the
  // per-evidence menu, which is how the two totals drift apart.
  if (!evidenceId) {
    try {
      const topEv = await pool.query(
        `SELECT evidence_id AS id
           FROM collection_timeline
          WHERE case_id = $1 AND evidence_id IS NOT NULL
          GROUP BY evidence_id
          ORDER BY COUNT(*) DESC
          LIMIT 1`, [caseId]);
      if (topEv.rows.length > 0) evidenceId = topEv.rows[0].id;
    } catch (_e) {}
  }

  let sourceDevice = null;
  try {
    if (evidenceId) {
      const evNameRow = await pool.query(`SELECT name FROM evidence WHERE id = $1`, [evidenceId]);
      if (evNameRow.rows.length > 0) {
        const evName = path.basename(evNameRow.rows[0].name || '').replace(/\.(zip|tar\.gz|7z|tgz|gz)$/i, '');
        const m = evName.match(/^([A-Za-z0-9][-A-Za-z0-9]{2,})/);
        if (m) sourceDevice = m[1].toUpperCase();
      }
    }
    if (!sourceDevice && collDir) {
      const dirBasename = path.basename(collDir);
      const m = dirBasename.match(/^([A-Za-z0-9][-A-Za-z0-9]{2,})/);
      if (m && !m[1].startsWith('case-')) sourceDevice = m[1].toUpperCase();
    }
  } catch (_e) {}

  // Atomic: lock previous results → delete stale data → insert new result record.
  // FOR UPDATE prevents two concurrent re-parsings from both deleting and double-inserting.
  //
  // Two modes:
  //  - FULL re-parse (no subset, or the whole catalog): the legacy behaviour —
  //    drop the previous result row (cascading its timeline rows) and start a
  //    fresh UnifiedTimeline row.
  //  - PARTIAL re-parse (explicit subset of types): keep the previous result
  //    row and only delete the timeline rows of the re-run types. The new
  //    parse_results are merged back into that same row so the per-evidence
  //    counts and the parser-log view stay consistent.
  let oldResultIds = [];
  let oldParsedResults = null;
  let oldRecordCount = 0;
  let reusedResultRow = null;
  let resultId;
  {
    let dbClient;
    try {
      dbClient = await pool.connect();
      await dbClient.query('BEGIN');
      const oldPrRows = await dbClient.query(
        `SELECT id, parser_name, output_data, record_count
         FROM parser_results
         WHERE case_id = $1 AND input_file = $2 AND parser_name != 'MagnetRESPONSE_Import'
         FOR UPDATE`,
        [caseId, collDir]
      );
      oldResultIds = oldPrRows.rows.map(r => r.id);

      if (isPartialReparse && oldPrRows.rows.length > 0) {
        // Reuse the existing UnifiedTimeline result row so the untouched types
        // keep their parse_results; delete only the rows of the types being
        // re-run. (Other parser rows — Hayabusa, … — are left untouched.)
        const unifiedRow = oldPrRows.rows.find(r => r.parser_name === 'UnifiedTimeline');
        if (unifiedRow) {
          reusedResultRow = unifiedRow;
          oldParsedResults = (unifiedRow.output_data && unifiedRow.output_data.parse_results) || null;
          oldRecordCount = unifiedRow.record_count || 0;
          resultId = unifiedRow.id;
          await dbClient.query(
            `DELETE FROM collection_timeline
              WHERE result_id = $1 AND artifact_type = ANY($2::text[])`,
            [resultId, validTypes]
          );
          // Reset the reused row to the 'parsing' state. Without this the old
          // output_data (status 'done' + stale parse_results) survives into the
          // new run: the /parse-progress durable fallback would then report a
          // terminal 'terminé' state right away (and the persisted progress
          // snapshot would never write), so the cockpit never appears until a
          // manual refresh. The old parse_results are already captured above
          // (oldParsedResults) and are merged back at finalization.
          await dbClient.query(
            `UPDATE parser_results
                SET output_data = '{"status":"parsing"}'::jsonb
              WHERE id = $1`,
            [resultId]
          );
        }
      }

      if (!reusedResultRow) {
        if (isPartialReparse) {
          // Partial re-parse with no prior UnifiedTimeline row: nothing to merge
          // into, so just start a fresh row without touching other parsers
          // (Hayabusa, …) that may share this collection.
          const prRow = await dbClient.query(
            `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
             VALUES ($1, $2, 'UnifiedTimeline', '2.0', $3, '{"status":"parsing"}'::jsonb, 0, $4) RETURNING id`,
            [caseId, evidenceId || null, collDir, req.user.id]
          );
          resultId = prRow.rows[0].id;
        } else {
          // Full re-parse: replace the previous results entirely.
          if (oldResultIds.length > 0) {
            await dbClient.query(
              `DELETE FROM collection_timeline WHERE result_id = ANY($1::uuid[])`,
              [oldResultIds]
            );
            await dbClient.query(
              `DELETE FROM parser_results WHERE id = ANY($1::uuid[])`,
              [oldResultIds]
            );
          }
          const prRow = await dbClient.query(
            `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
             VALUES ($1, $2, 'UnifiedTimeline', '2.0', $3, '{"status":"parsing"}'::jsonb, 0, $4) RETURNING id`,
            [caseId, evidenceId || null, collDir, req.user.id]
          );
          resultId = prRow.rows[0].id;
        }
      }
      await dbClient.query('COMMIT');
    } catch (initErr) {
      if (dbClient) {
        await dbClient.query('ROLLBACK').catch(() => {});
        dbClient.release();
      }
      ACTIVE_PARSE_LOCKS.delete(lockKey);
      return res.status(500).json({ error: 'Erreur initialisation DB', details: initErr.message });
    }
    if (dbClient) dbClient.release();
  }

    res.json({ id: resultId, status: 'parsing' });

    (async () => {
      let parseJobOutcome = 'success';
      let parseJobError = null;
      try {

        // ES cleanup deferred OUT of the request path so /parse returns
        // immediately (the re-parser button no longer waits on a slow
        // deleteByQuery). It runs at the start of the job, before the parse
        // loop, so it always completes before the end-of-parse re-index — safe
        // for both full and partial re-parses. Best-effort: errors are logged.
        if (isPartialReparse) {
          // Remove only the re-run types' documents; untouched types stay in ES.
          if (evidenceId) {
            await esService.deleteByEvidenceAndTypes(caseId, evidenceId, validTypes).catch(e =>
              logger.warn(`[ES] deleteByEvidenceAndTypes warn (${caseId}/${evidenceId}): ${String(e.message).substring(0, 100)}`));
          }
        } else if (oldResultIds.length > 0) {
          for (const rid of oldResultIds) {
            await esService.deleteByResultId(caseId, rid).catch(e =>
              logger.warn(`[ES] deleteByResultId warn (${caseId}/${rid}): ${String(e.message).substring(0, 100)}`));
          }
        } else {
          await esService.ensureIndex(caseId).catch(e =>
            logger.warn(`[ES] ensureIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
        }

  // Liveness heartbeat: the heavy artifacts (EVTX over 100+ files, MFT, USN)
  // spend 30+ min in the tool phase with no artifact_start/artifact_done
  // events. Without a periodic updatedAt refresh the wedged-parse detector in
  // /parse-progress would declare a live parse "Analyse bloquée" at the 30-min
  // mark. One cheap map write + one throttled DB snapshot every 15s.
  const progressHeartbeat = setInterval(() => {
    try { updateParseProgress(caseId, validTypes, { type: 'heartbeat' }); } catch (_e) {}
  }, 15000);

  await runConcurrent(typesToParse, async (artifactType) => {
    const config = ARTIFACT_PATTERNS[artifactType];
    if (!config) return;

    const myProgress = ++currentType;
    emitProgress({ type: 'artifact_start', artifact: artifactType, name: config.name, current: myProgress, total: totalTypes });

    if (WINDOWS_ONLY_PARSERS.has(artifactType)) {
      results[artifactType] = { status: 'skipped', reason: 'Non supporté sur Linux (librairies Windows natives requises)', name: config.name };
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: 'skipped', records: 0, current: myProgress, total: totalTypes });
      return;
    }

    const toolPath = path.join(ZIMMERMAN_DIR, config.tool);
    logger.info(`[loop] ${artifactType}: toolPath=${toolPath} exists=${fs.existsSync(toolPath)}`);

    if (!PYTHON_FALLBACK_PARSERS.has(artifactType) && !fs.existsSync(toolPath)) {
      results[artifactType] = { status: 'skipped', reason: 'Tool not installed', name: config.name };
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: 'skipped', records: 0, current: myProgress, total: totalTypes });
      return;
    }

    const files = findFiles(collDir, config.patterns);
    logger.info(`[detect] ${artifactType}: ${files.length} file(s) found`);
    if (files.length === 0) {
      results[artifactType] = { status: 'skipped', reason: 'No files found', name: config.name };
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: 'skipped', records: 0, current: myProgress, total: totalTypes });
      return;
    }

    const outputDir = path.join(TEMP_DIR, `parse-${caseId}-${artifactType}-${uuidv4()}`);
    fs.mkdirSync(outputDir, { recursive: true });

    try {

      const inputPath = files.length === 1 ? files[0] : path.dirname(files[0]);
      const isDirectory = files.length > 1 || fs.statSync(inputPath).isDirectory();

      const DIRECTORY_MODE_PARSERS = ['evtx', 'prefetch', 'lnk', 'jumplist', 'shellbags', 'recycle'];

      const SKIP_USER_DIRS = ['default', 'public', 'wsiaccount', 'wsiuser', 'guest', 'administrator'];
      function pickBestFile(fileList) {
        if (fileList.length === 1) return fileList[0];
        const real = fileList.filter(f => {
          const lf = f.toLowerCase();
          return !SKIP_USER_DIRS.some(u => lf.includes(`/users/${u}/`) || lf.includes(`\\users\\${u}\\`));
        });
        return real.length > 0 ? real[0] : fileList[0];
      }

      let toolArgs = null;
      let toolEnv = null;
      let toolError = null;
      let toolStdout = '';

      if (artifactType === 'prefetch') {

        const pfDir = files.length > 0 ? (fs.statSync(files[0]).isDirectory() ? files[0] : path.dirname(files[0])) : collDir;
        const pecmdDll = path.join(ZIMMERMAN_DIR, 'PECmd.dll');
        const engine = parserOptions?.prefetch?.engine || 'auto';
        const pyAvail = _pythonModuleAvailable('libscca') || _pythonModuleAvailable('pyscca');
        const dotnetAvail = fs.existsSync(pecmdDll);
        const usePython = engine === 'python'
          || (engine === 'auto' && (pyAvail || !dotnetAvail))
          || (engine === 'dotnet' && !dotnetAvail);

        if (usePython) {
          if (engine === 'dotnet' && !dotnetAvail) {
            logger.warn('[parse] prefetch: engine=dotnet demandé mais PECmd.dll absent — fallback Python');
          } else if (engine === 'python') {
            logger.info('[parse] prefetch: moteur Python forcé (parse_prefetch.py)');
          }
          toolArgs = ['python3', '/app/parsers/parse_prefetch.py', '-d', pfDir, '--csv', outputDir, '--csvf', 'prefetch_results.csv'];
        } else {
          if (engine === 'dotnet') logger.info('[parse] prefetch: moteur .NET forcé (PECmd.dll)');
          toolArgs = ['dotnet', pecmdDll, '-d', pfDir, '--csv', outputDir, '--csvf', 'prefetch_results.csv', '-q'];
        }
      } else if (artifactType === 'srum') {

        const systemHives = findFiles(collDir, ['**/config/SYSTEM', '**/config/system']);
        const systemHive = systemHives.length > 0 ? systemHives[0] : null;
        const srumArgs = ['python3', '/app/parsers/parse_srum.py', '-f', files[0], '--csv', outputDir, '--csvf', 'srum_results.csv'];
        if (systemHive) srumArgs.push('-r', systemHive);
        toolArgs = srumArgs;
      } else if (artifactType === 'wxtcmd') {

        const wxtDir = files.length > 0 ? path.dirname(path.dirname(files[0])) : collDir;
        toolArgs = ['python3', '/app/parsers/parse_wxtcmd.py', '-d', wxtDir, '--csv', outputDir, '--csvf', 'wxtcmd_results.csv'];
      } else if (artifactType === 'sqle') {

        toolArgs = ['python3', '/app/parsers/parse_sqle.py', '-d', collDir, '--csv', outputDir, '--csvf', 'sqle_results.csv'];
      } else if (artifactType === 'schtasks') {

        toolArgs = ['python3', '/app/parsers/parse_schtasks.py', '-d', collDir, '--csv', outputDir, '--csvf', 'schtasks_results.csv'];
      } else if (artifactType === 'pwsh') {

        toolArgs = ['python3', '/app/parsers/parse_pwsh_history.py', '-d', collDir, '--csv', outputDir, '--csvf', 'pwsh_history_results.csv'];
      } else if (artifactType === 'dns') {

        toolArgs = ['python3', '/app/parsers/parse_dns.py', '-d', collDir, '--csv', outputDir, '--csvf', 'dns_results.csv'];
      } else if (artifactType === 'wmi') {

        const repoDir = files.length ? path.dirname(files[0]) : collDir;
        toolArgs = ['python3', '/app/parsers/parse_wmi.py', '-d', repoDir, '--csv', outputDir, '--csvf', 'wmi_results.csv'];
      } else if (artifactType === 'pcap') {

        // PCAP feeds network_connections (the network map), not the timeline.
        let inserted = 0;
        try {
          const pcapArgs = ['/app/parsers/parse_pcap.py', '-d', collDir, '--csv', outputDir, '--csvf', 'pcap_results.csv'];
          const displayFilter = (parserOptions?.pcap?.display_filter || '').trim();
          if (displayFilter) { pcapArgs.push('--filter', displayFilter); logger.info(`[parse] pcap display filter: ${displayFilter}`); }
          // Async spawn (not spawnSync): a big PCAP can run 30 min — a sync call
          // would freeze the event loop and stall every other parser's DB writes.
          try {
            const out = await spawnTool(['python3', ...pcapArgs], { timeout: 1800000 });
            toolStdout = out.slice(0, 1500);
          } catch (spawnErr) {
            toolStdout = String(spawnErr.stdout || spawnErr.stderr || spawnErr.message || '').slice(0, 1500);
          }
          const csvPath = path.join(outputDir, 'pcap_results.csv');
          if (fs.existsSync(csvPath)) {
            const rows = fs.readFileSync(csvPath, 'utf8').split('\n').filter(Boolean);
            rows.shift(); // header
            const toInt = v => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : 0; };
            // Batch the per-row inserts into UNNEST-sized chunks instead of one
            // round-trip per packet (thousands of packets = thousands of queries).
            const vals = [];
            for (const line of rows) {
              const c = line.split(',');
              if (c.length < 10 || !c[0] || !c[2]) continue;
              vals.push([c[0], c[1] || null, c[2], c[3] || null, c[4] || null, toInt(c[5]), toInt(c[6]), toInt(c[7]), c[8] || null, c[9] || null]);
            }
            const PCAP_INSERT_BATCH = 1000;
            for (let i = 0; i < vals.length; i += PCAP_INSERT_BATCH) {
              const chunk = vals.slice(i, i + PCAP_INSERT_BATCH);
              const params = [];
              const placeholders = chunk.map((v, ri) => {
                const base = ri * 10;
                params.push(...v);
                return `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10})`;
              }).join(',');
              if (!placeholders) continue;
              await pool.query(
                `INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen)
                 VALUES ${placeholders}`,
                [caseId, ...params]
              );
              inserted += chunk.length;
            }
          }
        } catch (e) { logger.warn('[pcap] insert error:', e.message); }
        results[artifactType] = { status: inserted > 0 ? 'ok' : 'empty', name: config?.name || 'PCAP', records: inserted };
        toolArgs = null;
      } else if (artifactType === 'rdpcache') {

        // RDP bitmap cache → reconstructed PNG tiles in a served per-case dir (not the timeline).
        const RDP_BASE = path.join(COLLECTIONS_DIR, 'rdp-cache', caseId);
        let count = 0;
        try {
          fs.mkdirSync(RDP_BASE, { recursive: true });
          const cacheDir = files.length ? path.dirname(files[0]) : collDir;
          // Async spawn — bmc-tools can run 10 min; spawnSync would block all
          // other parsers' DB writes for the whole duration.
          try {
            const out = await spawnTool(['python3', '/app/tools/bmc-tools.py', '-s', cacheDir, '-d', RDP_BASE, '-b'], { timeout: 600000 });
            toolStdout = out.slice(0, 1500);
          } catch (spawnErr) {
            toolStdout = String(spawnErr.stdout || spawnErr.stderr || spawnErr.message || '').slice(0, 1500);
          }
          count = fs.existsSync(RDP_BASE) ? fs.readdirSync(RDP_BASE).filter(f => /\.(bmp|png)$/i.test(f)).length : 0;
        } catch (e) { logger.warn('[rdpcache]', e.message); }
        results[artifactType] = { status: count > 0 ? 'ok' : 'empty', name: config?.name || 'RDP Bitmap Cache', records: count };
        toolArgs = null;
      } else if (isDirectory && DIRECTORY_MODE_PARSERS.includes(artifactType)) {

        let dirInput = path.dirname(files[0]);
        if (['shellbags', 'recycle'].includes(artifactType) && files.length > 1) {
          const allDirs = files.map(f => path.dirname(f));
          let candidate = allDirs[0];
          while (candidate !== path.dirname(candidate)) {
            if (allDirs.every(d => d.startsWith(candidate + path.sep) || d === candidate)) break;
            candidate = path.dirname(candidate);
          }
          dirInput = candidate;
        }

        if (artifactType === 'lnk') {
          // LNK shortcuts live scattered across many folders (Recent, Desktop,
          // Startup, AppData…). Parsing only ONE directory (the old
          // dirname(files[0]) / first "recent" dir) silently dropped every
          // .lnk elsewhere. Run LECmd -d per unique parent directory, each into
          // its own output subdir, so ALL found shortcuts are parsed.
          // Recycle-bin LNKs stay excluded (junk + noise).
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
          const allLnkDirs = [...new Set(files.map(f => path.dirname(f)))];
          let lnkDirs = allLnkDirs.filter(d => !d.toLowerCase().includes('recycle'));
          // Recycle-only collection (rare): keep the recycle dirs so we still
          // parse something instead of zero.
          if (lnkDirs.length === 0) lnkDirs = allLnkDirs;
          // LECmd -d recurses: drop any dir nested inside another kept dir
          // so we never parse the same subtree twice.
          lnkDirs = lnkDirs.filter(d => !allLnkDirs.some(o => o !== d && d.startsWith(o + path.sep)));
          const lnkLines = [];
          for (let li = 0; li < lnkDirs.length; li++) {
            emitProgress({ type: 'artifact_progress', artifact: artifactType, name: config.name, records: 0, fraction: lnkDirs.length > 1 ? li / lnkDirs.length : 0 });
            const subOut = path.join(outputDir, `lnk_${li}`);
            fs.mkdirSync(subOut, { recursive: true });
            const lnkArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'LECmd.dll'), '-d', lnkDirs[li], '--csv', subOut, '--csvf', 'lnk_results.csv', ...appendCliFlags(artifactType, parserOptions)];
            const label = path.basename(lnkDirs[li]) || lnkDirs[li];
            try {
              const lo = await spawnTool(lnkArgs, { timeout: 3600000, maxBuffer: 1024 * 1024 * 512, cwd: outputDir, env: toolEnv || undefined });
              lnkLines.push(`${label}: ${(lo || '').trim().split('\n').slice(-1)[0]?.substring(0, 120) || 'ok'}`);
            } catch (le) {
              const lmsg = ((le.stderr || '') + (le.stdout || '') + (le.message || '')).toString().substring(0, 150);
              lnkLines.push(`${label}: ERR ${lmsg}`);
            }
          }
          toolArgs = null;
          toolStdout = lnkLines.join(' | ').slice(0, 1500);
        } else if (artifactType === 'evtx') {

          let mapsDir = null;
          const mapsBase = path.join(ZIMMERMAN_DIR, 'Maps');
          if (fs.existsSync(mapsBase)) {
            const hasDirect = fs.readdirSync(mapsBase).some(f => f.endsWith('.map') || f.endsWith('.json'));
            const subDir    = path.join(mapsBase, 'Maps');
            const hasSub    = fs.existsSync(subDir) && fs.readdirSync(subDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            // Zimmerman layout: Maps/EvtxeCmd/Maps/*.map
            const evtxSubDir = path.join(mapsBase, 'EvtxeCmd', 'Maps');
            const hasEvtxSub = fs.existsSync(evtxSubDir) && fs.readdirSync(evtxSubDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            if (hasDirect)   mapsDir = mapsBase;
            else if (hasSub) mapsDir = subDir;
            else if (hasEvtxSub) mapsDir = evtxSubDir;
          }
          const mapsFlag = mapsDir ? ` --maps "${mapsDir}"` : '';
          logger.info(`[parse] evtx maps: ${mapsDir || 'none found'}`);

          const evtxDirArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'EvtxECmd.dll'), '-d', dirInput, '--csv', '.'];
          if (mapsDir) evtxDirArgs.push('--maps', mapsDir);
          toolArgs = evtxDirArgs;
          toolEnv = { ...process.env, DOTNET_SYSTEM_THREADING_THREADPOOL_MINTHREADS: '4', DOTNET_SYSTEM_THREADING_THREADPOOL_MINCOMPLETIONPORTTHREADS: '4' };
        } else {
          // Generic Zimmerman-style invocation — append any schema-declared CLI
          // flags the operator enabled for this artifact type (e.g. MFTECmd
          // --dr/--ir/--rs). appendCliFlags only emits flags owned by
          // `artifactType` and vetted against the tool's real help.
          toolArgs = [...config.argsBuilder(dirInput, outputDir), ...appendCliFlags(artifactType, parserOptions)];
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
        }
      } else {

        const bestFile = pickBestFile(files);
        if (artifactType === 'registry') {

          // Full-hive dump with dissect.regf (same coverage as the hive explorer):
          // RECmd's curated batch files only extract a subset of keys, so keys
          // outside the batch list (WinSCP sessions, …) never made it to the
          // timeline even though the explorer shows them. The dissect-based
          // parser emits one CSV row per value, reusing the RECmd column schema
          // (HivePath/KeyPath/ValueName/…/LastWriteTimestamp) the pipeline below
          // already consumes unchanged.
          //
          // The same hive is usually collected TWICE — the live file
          // (…\Windows\System32\config\SOFTWARE) plus VSS shadow copies
          // (@GMT-…\Windows\System32\config\SOFTWARE). Parsing both doubles
          // the rows for zero new information, the identical values collide on
          // the dedupe_hash (and are silently dropped by ON CONFLICT while the
          // counter still counted them → the cockpit showed 1 M instead of
          // 512 k). Content-hash dedupe keeps exactly one copy per distinct
          // hive, so the dump, the timeline and the search index all agree.
          const seenHiveHashes = new Set();
          const uniqueFiles = [];
          for (const hive of files) {
            let h = null;
            try {
              h = crypto.createHash('md5').update(fs.readFileSync(hive)).digest('hex');
            } catch (_e) { /* unreadable — keep it, the parser will surface the error */ }
            if (h && seenHiveHashes.has(h)) {
              logger.info(`[parse] registry: skip duplicate hive ${hive} (identical content)`);
              continue;
            }
            if (h) seenHiveHashes.add(h);
            uniqueFiles.push(hive);
          }
          const regLines = [];
          for (let ri = 0; ri < uniqueFiles.length; ri++) {
            const hive = uniqueFiles[ri];
            const hname = path.basename(hive).replace(/[^a-zA-Z0-9._-]/g, '_');
            const csvf = `reg_${ri}_${hname}.csv`;
            try {
              const ro = await spawnTool(['python3', '/app/parsers/parse_registry_full.py', '-f', hive, '--csv', path.join(outputDir, csvf)], { timeout: 900000, maxBuffer: 1024 * 1024 * 128, cwd: outputDir });
              regLines.push(`${hname}: ${(ro || '').trim().split('\n').slice(-1)[0]?.substring(0, 120) || 'ok'}`);
            } catch (re) {
              const rmsg = ((re.stderr || '') + (re.stdout || '') + (re.message || '')).toString().substring(0, 150);
              regLines.push(`${hname}: ERR ${rmsg}`);
            }
            // records stays 0 during extraction: the count shown is rows actually
            // inserted in the timeline (the stream phase below), NOT values
            // written to the temp CSV — reporting the dump total here made the
            // cockpit jump from ~175 000 (extracted) back to 5 000 (first insert
            // batch). The per-hive fraction keeps the % moving instead.
            emitProgress({ type: 'artifact_progress', artifact: artifactType, name: config.name, records: 0, fraction: uniqueFiles.length > 0 ? (ri + 1) / uniqueFiles.length : 0 });
          }

          toolArgs = null;

          toolStdout = regLines.join(' | ').slice(0, 1500);
        } else if (artifactType === 'evtx') {

          let mapsDir = null;
          const mapsBase = path.join(ZIMMERMAN_DIR, 'Maps');
          if (fs.existsSync(mapsBase)) {
            const hasDirect = fs.readdirSync(mapsBase).some(f => f.endsWith('.map') || f.endsWith('.json'));
            const subDir    = path.join(mapsBase, 'Maps');
            const hasSub    = fs.existsSync(subDir) && fs.readdirSync(subDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            // Zimmerman layout: Maps/EvtxeCmd/Maps/*.map
            const evtxSubDir = path.join(mapsBase, 'EvtxeCmd', 'Maps');
            const hasEvtxSub = fs.existsSync(evtxSubDir) && fs.readdirSync(evtxSubDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            if (hasDirect)   mapsDir = mapsBase;
            else if (hasSub) mapsDir = subDir;
            else if (hasEvtxSub) mapsDir = evtxSubDir;
          }
          const mapsFlag = mapsDir ? ` --maps "${mapsDir}"` : '';
          logger.info(`[parse] evtx single-file maps: ${mapsDir || 'none found'}`);
          const evtxFileArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'EvtxECmd.dll'), '-f', bestFile, '--csv', '.'];
          if (mapsDir) evtxFileArgs.push('--maps', mapsDir);
          toolArgs = evtxFileArgs;
          toolEnv = { ...process.env, DOTNET_SYSTEM_THREADING_THREADPOOL_MINTHREADS: '4', DOTNET_SYSTEM_THREADING_THREADPOOL_MINCOMPLETIONPORTTHREADS: '4' };
        } else if (artifactType === 'mft') {
          // A collection can hold one $MFT per volume / VSS snapshot. Carve and
          // parse every copy — pickBestFile used to silently drop the others,
          // losing the resident files (and CSV rows) of those volumes. Each $MFT
          // writes to its own subdir so the CSVs and the Resident dump never
          // overwrite one another.
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
          const mftLines = [];
          for (let mi = 0; mi < files.length; mi++) {
            const mftFile = files[mi];
            const subOut = path.join(outputDir, `mft_${mi}`);
            fs.mkdirSync(subOut, { recursive: true });
            const mftArgs = [
              'dotnet', path.join(ZIMMERMAN_DIR, 'MFTECmd.dll'),
              '-f', mftFile, '--csv', subOut, '--csvf', `mft_${mi}_results.csv`,
              ...appendCliFlags(artifactType, parserOptions),
            ];
            const label = path.basename(mftFile);
            try {
              const mo = await spawnTool(mftArgs, { timeout: 3600000, maxBuffer: 1024 * 1024 * 512, cwd: outputDir, env: toolEnv || undefined });
              mftLines.push(`${label}: ${(mo || '').trim().split('\n').slice(-1)[0]?.substring(0, 120) || 'ok'}`);
            } catch (me) {
              const mmsg = ((me.stderr || '') + (me.stdout || '') + (me.message || '')).toString().substring(0, 150);
              mftLines.push(`${label}: ERR ${mmsg}`);
            }
          }
          toolArgs = null;
          toolStdout = mftLines.join(' | ').slice(0, 1500);
        } else if (artifactType === 'usn') {
          // One $J per volume / VSS snapshot: parse every copy into its own subdir
          // (the old single-file path silently dropped all but the first, losing
          // whole volumes of journal records). Parent-path resolution needs the
          // sibling $MFT (-m): look for a $MFT near the $J, walking up a couple of
          // levels (same volume dir).
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
          const usnLines = [];
          for (let ui = 0; ui < files.length; ui++) {
            emitProgress({ type: 'artifact_progress', artifact: artifactType, name: config.name, records: 0, fraction: files.length > 1 ? ui / files.length : 0 });
            const usnFile = files[ui];
            const subOut  = path.join(outputDir, `usn_${ui}`);
            fs.mkdirSync(subOut, { recursive: true });
            const usnArgs = [
              'dotnet', path.join(ZIMMERMAN_DIR, 'MFTECmd.dll'),
              '-f', usnFile, '--csv', subOut, '--csvf', `usn_${ui}_results.csv`,
              ...appendCliFlags(artifactType, parserOptions),
            ];
            let mftForUsn = null;
            let probe = path.dirname(usnFile);
            for (let up = 0; up < 3 && probe && probe !== path.dirname(probe); up++) {
              const cand = path.join(probe, '$MFT');
              if (fs.existsSync(cand)) { mftForUsn = cand; break; }
              probe = path.dirname(probe);
            }
            if (mftForUsn) {
              usnArgs.push('-m', mftForUsn);
              logger.info(`[parse] usn: sibling MFT for parent paths: ${mftForUsn}`);
            }
            const label = path.basename(usnFile);
            try {
              const uo = await spawnTool(usnArgs, { timeout: 3600000, maxBuffer: 1024 * 1024 * 512, cwd: outputDir, env: toolEnv || undefined });
              usnLines.push(`${label}: ${(uo || '').trim().split('\n').slice(-1)[0]?.substring(0, 120) || 'ok'}`);
            } catch (ue) {
              const umsg = ((ue.stderr || '') + (ue.stdout || '') + (ue.message || '')).toString().substring(0, 150);
              usnLines.push(`${label}: ERR ${umsg}`);
            }
          }
          toolArgs = null;
          toolStdout = usnLines.join(' | ').slice(0, 1500);
        } else {
          // See directory-mode branch: schema-declared CLI flags (mft --dr etc.).
          toolArgs = [...config.argsBuilder(bestFile, outputDir), ...appendCliFlags(artifactType, parserOptions)];
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
        }
      }

      if (toolArgs !== null) {

      const requiredBinary = toolArgs[0];
      if ((requiredBinary === 'python3' || requiredBinary === 'dotnet') && !_binaryAvailable(requiredBinary)) {
        logger.warn(`[parse] ${artifactType} skipped — '${requiredBinary}' not available`);
        results[artifactType] = { status: 'skipped', name: config?.name || artifactType, records: 0, reason: `${requiredBinary} not installed` };
        emitProgress({ type: 'artifact_done', artifact: artifactType, status: 'skipped', records: 0, current: ++currentType, total: totalTypes });
        return;
      }
      logger.info(`[parse] ${artifactType} args: ${toolArgs.join(' ').substring(0, 300)}`);
      const toolT0 = Date.now();
      try {
        const toolOut = await spawnTool(toolArgs, {
          timeout: 3600000,
          maxBuffer: 1024 * 1024 * 512,
          cwd: outputDir,
          env: toolEnv || undefined,
        });
        logger.info(`[BENCH] ${artifactType} tool: ${Date.now() - toolT0}ms`);

        toolStdout = (toolOut || '').slice(-1500);
        if (toolOut) {
          const lastLines = toolOut.trim().split('\n').slice(-4).join(' | ');
          if (lastLines) logger.info(`[parse] ${artifactType} tool stdout: ${lastLines.substring(0, 600)}`);
        }
      } catch (execErr) {
        const stderr = execErr.stderr ? execErr.stderr.toString().substring(0, 800) : '';
        const stdout = execErr.stdout ? execErr.stdout.toString().substring(0, 400) : '';
        toolError = (stderr || stdout || execErr.message || '').substring(0, 600);
        toolStdout = toolError;
        logger.warn(`[parse] ${artifactType} tool error (exit ${execErr.status}): ${toolError}`);
      }

      if (artifactType === 'evtx') {
        const allInOutput = [];
        (function listAll(d) {
          try { for (const e of fs.readdirSync(d, { withFileTypes: true })) {
            const f = path.join(d, e.name);
            if (e.isDirectory()) listAll(f);
            else {
              const sz = fs.statSync(f).size;
              allInOutput.push(`${f.replace(outputDir, '.')} (${sz}B)`);
            }
          }} catch {}
        })(outputDir);
        logger.info(`[parse] evtx outputDir (${allInOutput.length} files): ${allInOutput.slice(0, 30).join(', ') || 'EMPTY'}`);

        const firstCsv = findCsvFilesRecursive(outputDir)[0];
        if (firstCsv) {
          try {

            const fd  = fs.openSync(firstCsv, 'r');
            const buf = Buffer.alloc(4096);
            const n   = fs.readSync(fd, buf, 0, 4096, 0);
            fs.closeSync(fd);
            const head = buf.slice(0, n).toString('utf-8').split('\n').slice(0, 2);
            logger.info(`[parse] evtx csv head[0] (${head[0]?.length} chars): ${head[0]?.substring(0, 200)}`);
            logger.info(`[parse] evtx csv head[1] (${head[1]?.length} chars): ${head[1]?.substring(0, 200)}`);
          } catch (e) { logger.info(`[parse] evtx csv read error: ${e.message}`); }
        }

        try {
          const zimmCsvs = fs.readdirSync(ZIMMERMAN_DIR).filter(f => f.toLowerCase().endsWith('.csv'));
          if (zimmCsvs.length > 0) logger.info(`[parse] evtx ZIMMERMAN_DIR csvs (unexpected): ${zimmCsvs.join(', ')}`);
        } catch {}
      }
      }

      const csvFiles = findCsvFilesRecursive(outputDir);
      let csvRawCount = 0, csvNormCount = 0, csvFailedRows = 0, firstCols = [];

      const csvT0 = Date.now();
      // Per-artifact CSV file concurrency. Kept LOW deliberately: each stream
      // holds a full CT_DB_BATCH (5000) in-flight in memory and the global
      // dbWriteSem bounds TOTAL concurrent inserts. MFT+USN+EVTX already run in
      // parallel with every other parser, so per-artifact parallelism above 3
      // only multiplies memory + pg contention for no throughput gain (the
      // writes were already overlapping across parsers).
      //
      // The CSV streams run in PARALLEL and each reports its OWN cumulative
      // counter. Emitting them raw would overwrite the single per-artifact
      // records slot, making the cockpit jump between the parallel files'
      // values (175 000 → 5 000 → …). Aggregate per-file counters into the
      // artifact's TRUE total (sum of inserted rows, sum of bytes) so the
      // number only ever climbs to the final csvNormCount.
      const csvProgressAgg = {}; // csvPath -> { records, bytesRead, size }
      await runConcurrent(csvFiles, async (csvFilePath) => {
        // Global DB-write semaphore: bounds total concurrent inserts across all parsers.
        await dbWriteSem.acquire();
        try {
          const r = await streamNormalizeToDB(
            csvFilePath, caseId, resultId, artifactType, config, evidenceId, sourceDevice, timeWindow,
            // Live per-batch progress → socket + durable store. Kept cheap (2s
            // throttle inside streamNormalizeToDB) so the cockpit moves while
            // a 30+ min EVTX/MFT/USN CSV streams instead of freezing at the
            // last batch boundary.
            (p) => {
              csvProgressAgg[csvFilePath] = { records: p.records || 0, bytesRead: p.bytesRead || 0, size: p.size || 0 };
              let aggRecords = 0, aggBytes = 0, aggSize = 0;
              for (const v of Object.values(csvProgressAgg)) {
                aggRecords += v.records;
                aggBytes   += v.bytesRead;
                aggSize    += v.size;
              }
              emitProgress({
                type: 'artifact_progress', artifact: artifactType, name: config.name,
                records: aggRecords,
                fraction: aggSize > 0 ? Math.min(1, aggBytes / aggSize) : 0,
              });
            }
          );
          csvRawCount  += r.rawCount;
          csvNormCount += r.normalized;
          csvFailedRows += (r.insertFailedRows || 0);
          if (firstCols.length === 0) firstCols = r.columns;
        } catch (streamErr) {
          // Full error inline so winston actually surfaces it (pg errors carry code/detail/where).
          logger.warn(`[parse] Stream insert error ${artifactType}/${path.basename(csvFilePath)}: ` +
            `${streamErr.message || streamErr} | code=${streamErr.code || '?'}` +
            `${streamErr.detail ? ' | detail=' + String(streamErr.detail).slice(0, 200) : ''}` +
            `${streamErr.where ? ' | where=' + String(streamErr.where).slice(0, 150) : ''}`);
        } finally {
          dbWriteSem.release();
        }
      }, 3);
      const csvMs = Date.now() - csvT0;
      const rps = csvMs > 0 ? Math.round(csvNormCount / (csvMs / 1000)) : 0;
      logger.info(`[BENCH] ${artifactType} CSV→DB: ${csvFiles.length} files, ${csvRawCount} raw → ${csvNormCount} rows in ${csvMs}ms (${rps} rows/s, batch=${CT_DB_BATCH})`);

      const artifactStatus = (toolError && csvNormCount === 0)
        ? 'error'
        : ((csvNormCount === 0 && !toolError) || csvFailedRows > 0)
          ? 'degraded'
          : 'success';
      results[artifactType] = {
        status: artifactStatus,
        name: config.name,
        files_processed: files.length,
        raw_records: csvRawCount,
        normalized_records: csvNormCount,
        columns: firstCols,
        ...(toolError && csvNormCount === 0 ? { error: toolError } : {}),
        ...(artifactStatus === 'degraded' && csvNormCount === 0 ? { warning: '0 événements parsés (fichier vide ou format non reconnu)' } : {}),
        ...(csvFailedRows > 0 ? { warning: `${csvFailedRows} ligne(s) non insérée(s) — erreur DB, voir les logs` } : {}),
        ...(csvNormCount === 0 && toolStdout ? { tool_output: toolStdout.trim().split('\n').slice(-6).join(' | ').substring(0, 500) } : {}),
      };
      logger.info(`[parse] ${artifactType}: files=${files.length} csv_raw=${csvRawCount} normalized=${csvNormCount}`);
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: results[artifactType].status, records: csvNormCount, current: myProgress, total: totalTypes });

      totalRecords += csvNormCount;

      // MFTECmd --dr carves resident files into each <mft subdir>/Resident.
      // Merge them into the collection (before the temp outputDir is wiped) so
      // the analyst can browse the recovered files. Multiple $MFT sources are
      // kept under per-source subdirs so EntryNumber collisions across volumes
      // / VSS snapshots never silently overwrite each other.
      if (artifactType === 'mft' && parserOptions?.mft?.resident_files === true) {
        const residentDst = path.join(collDir, '_mft_resident');
        const sources = [];
        for (let mi = 0; mi < files.length; mi++) {
          const r = path.join(outputDir, `mft_${mi}`, 'Resident');
          if (fs.existsSync(r)) sources.push({ src: r, sub: files.length > 1 ? `mft_${mi}` : '' });
        }
        if (sources.length === 0) {
          const legacy = path.join(outputDir, 'Resident');
          if (fs.existsSync(legacy)) sources.push({ src: legacy, sub: '' });
        }
        if (sources.length > 0) {
          try {
            fs.rmSync(residentDst, { recursive: true, force: true });
            let carved = 0;
            for (const { src, sub } of sources) {
              const dst = sub ? path.join(residentDst, sub) : residentDst;
              fs.cpSync(src, dst, { recursive: true, force: true });
              carved += countFilesRecursive(dst);
            }
            if (results[artifactType]) results[artifactType].resident_files = carved;
            logger.info(`[parse] mft: ${carved} resident file(s) recovered from ${sources.length} $MFT source(s) → ${residentDst}`);
          } catch (e) { logger.warn('[parse] mft resident copy failed:', e.message); }
        }
      }

      fs.rmSync(outputDir, { recursive: true, force: true });
    } catch (err) {
      results[artifactType] = { status: 'error', name: config.name, error: err.message };
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: 'error', records: 0, current: myProgress, total: totalTypes });
      if (fs.existsSync(outputDir)) fs.rmSync(outputDir, { recursive: true, force: true });
    }
  }, PARSE_CONCURRENCY);

  try {
    const { findCatScaleRoot, parseCatScale } = require('../services/catscaleService');
    const catscaleRoot = findCatScaleRoot(collDir);
    if (catscaleRoot) {
      emitProgress({ type: 'artifact_start', artifact: 'catscale', name: 'CatScale Linux IR', current: totalTypes + 1, total: totalTypes + 1 });
      const collectionTime = new Date();
      try {
        const mtime = fs.statSync(catscaleRoot).mtime;
        if (mtime && mtime < new Date()) Object.assign(collectionTime, mtime) || (collectionTime.setTime(mtime.getTime()));
      } catch (_e) {}
      // Opt-in exhaustive filesystem timeline: 4.4M rows instead of 332k on a real
      // host. Off unless the caller asks, and reversible via DELETE
      // /api/collection/:caseId/fs-timeline.
      const exhaustiveFsTimeline = (parserOptions?.catscale?.exhaustive_fs_timeline === true)
        || req.body?.exhaustive_fs_timeline === true
        || req.body?.exhaustive_fs_timeline === 'true';
      const csResult = await parseCatScale(catscaleRoot, caseId, pool, collectionTime, (p) => {
        if (socketId && io) io.to(socketId).emit('collection:progress', { ...p, artifact: 'catscale' });
      }, { resultId, evidenceId }, { exhaustiveFsTimeline });
      // A permission-denied collection reads as an empty one: findFiles/walkDir
      // return [] on EACCES. Reporting that as a successful parse of 0 events is
      // how an analyst ends up concluding a host is clean when nothing was read.
      const blocked = (csResult.unreadable || []).length > 0 && csResult.events === 0;
      const failures = csResult.failures || [];
      const degraded = failures.length > 0;
      results['catscale'] = {
        status: (blocked || degraded) ? 'error' : 'ok',
        name: 'CatScale Linux IR',
        records: csResult.events,
        hostname: csResult.hostname,
        artifacts: csResult.artifacts,
        failures,
        state_rows: csResult.state_rows,
        // What the noise floor removed and why. Surfaced so the analyst can see
        // the gap instead of trusting a number that silently dropped 92% of the
        // filesystem timeline.
        fs_filter: csResult.fs_filter,
        exhaustive_fs_timeline: exhaustiveFsTimeline,
        ...(blocked ? {
          error: `Collection unreadable: ${csResult.unreadable.length} directory(ies) denied (EACCES). `
               + `Cat-Scale writes its output as root; grant the backend user read access before parsing. `
               + `First: ${csResult.unreadable.slice(0, 3).join(', ')}`,
        } : degraded ? {
          // The count is real but incomplete — say so rather than let an analyst
          // read a partial parse as the whole picture.
          error: `Parsed with ${failures.length} failure(s): `
               + failures.slice(0, 3).map(f => `${f.stage} on ${require('path').basename(f.target)} (${f.reason})`).join(' · ')
               + (failures.length > 3 ? ` … +${failures.length - 3}` : ''),
        } : {}),
      };
      if (blocked) logger.error(`[CatScale] parse aborted — ${csResult.unreadable.length} unreadable directory(ies)`);
      else if (degraded) logger.error(`[CatScale] parse incomplete — ${failures.length} failure(s)`);
      totalRecords += csResult.events;
      emitProgress({ type: 'artifact_done', artifact: 'catscale', name: 'CatScale Linux IR', status: (blocked || degraded) ? 'error' : 'ok', records: csResult.events, current: totalTypes + 1, total: totalTypes + 1 });
      logger.info(`[CatScale] Detected and parsed: ${csResult.events} events from ${csResult.hostname}`);
    }
  } catch (e) {
    // Without an entry here the UI shows nothing at all about CatScale, exactly as
    // if the archive had never been a Linux collection.
    logger.error('[CatScale] detection/parse error:', e.message);
    results['catscale'] = {
      status: 'error', name: 'CatScale Linux IR', records: 0,
      error: `CatScale parsing failed: ${e.message}`,
    };
    // Emit the terminal progress event even on a hard error — otherwise the
    // artifact_start above leaves 'catscale' stuck in 'parsing' and the global
    // % freezes at N/(N+1) (e.g. 94%) forever.
    emitProgress({ type: 'artifact_done', artifact: 'catscale', name: 'CatScale Linux IR', status: 'error', records: 0, current: totalTypes + 1, total: totalTypes + 1 });
  }

  // CSVs are claimed by no ARTIFACT_PATTERNS entry, so without this step they
  // are silently dropped on the floor. `results` now holds every native
  // artifact type's outcome (including pcap/rdpcache/catscale's differently
  // shaped entries) — planCsvIngestion (inside scanCollectionCsvs) already
  // knows how to read all of those shapes, so it is passed unchanged.
  // scanCollectionCsvs never rejects (it swallows its own errors, matching the
  // CatScale block above: a bug here must not cost a collection parse that
  // already succeeded for every raw artifact) — the try/catch is defense in
  // depth only.
  try {
    const csvScan = await scanCollectionCsvs(pool, { collDir, caseId, evidenceId, resultId, nativeResults: results });
    if (csvScan.files.length) {
      results.__csv = csvScan;
      totalRecords += csvScan.files.reduce((sum, d) => sum + (d.inserted || 0), 0);
    }
  } catch (e) {
    logger.warn('[csv] collection scan error:', e.message);
  }

  emitProgress({ type: 'saving', message: 'Finalisation des métadonnées…' });

  try {
    // Partial re-parse: merge the freshly re-run types into the previous
    // parse_results (the untouched types' entries are preserved) and re-sum the
    // record count so the per-evidence badge reflects ALL types, not just the
    // subset that was re-run.
    let finalParseResults = results;
    let finalRecordCount = totalRecords;
    let finalArtifactTypes = typesToParse;
    if (isPartialReparse && reusedResultRow) {
      finalParseResults = { ...(oldParsedResults || {}), ...results };
      finalArtifactTypes = Array.from(new Set([
        ...(reusedResultRow.output_data?.artifact_types || []),
        ...typesToParse,
      ])).filter(t => ARTIFACT_PATTERNS[t] || t === 'catscale');
      try {
        const totalRes = await pool.query(
          `SELECT COUNT(*)::int AS total FROM collection_timeline WHERE evidence_id = $1`,
          [evidenceId]
        );
        finalRecordCount = totalRes.rows[0]?.total ?? (oldRecordCount + totalRecords);
      } catch (_e) {
        finalRecordCount = oldRecordCount + totalRecords;
      }
    }

    await pool.query(
      `UPDATE parser_results
         SET output_data   = $1,
             record_count  = $2,
             updated_at    = NOW()
       WHERE id = $3`,
      [
        JSON.stringify({ parse_results: finalParseResults, artifact_types: finalArtifactTypes, total_records: finalRecordCount, parser_options: parserOptions }),
        finalRecordCount,
        resultId,
      ]
    );

    try {
      const redis = getRedis();
      if (redis) {

        const keys = await redis.keys(`timeline:aggs:${caseId}:*`);
        if (keys.length) await redis.del(...keys);
      }
    } catch (_e) {}

    await auditLog(req.user.id, 'parse_collection', 'collection', resultId,
      { artifact_types: typesToParse, total_records: totalRecords }, req.ip);

    const evtRows = await pool.query(
      `SELECT timestamp, artifact_type, artifact_name, description, source
         FROM collection_timeline
        WHERE case_id = $1
        ORDER BY timestamp
        LIMIT 2000`,
      [caseId]
    );
    const tlBatchSize = 200;
    for (let i = 0; i < evtRows.rows.length; i += tlBatchSize) {
      const batch = evtRows.rows.slice(i, i + tlBatchSize);
      const values = [];
      const params = [];
      let idx = 1;
      for (const rec of batch) {
        values.push(`($${idx++}, $${idx++}, 'analysis', $${idx++}, $${idx++}, $${idx++}, $${idx++})`);
        params.push(
          caseId, rec.timestamp,
          '[' + (rec.artifact_name || rec.artifact_type) + '] ' + (rec.description || '').substring(0, 200),
          '',
          rec.source || rec.artifact_type || 'collection',
          req.user.id
        );
      }
      if (values.length > 0) {
        try {
          await pool.query(
            `INSERT INTO timeline_events (case_id, event_time, event_type, title, description, source, created_by)
             VALUES ${values.join(',')}`,
            params
          );
        } catch (e) {}
      }
    }

    await pool.query(
      `INSERT INTO timeline_events (case_id, event_time, event_type, title, description, source, created_by)
       VALUES ($1, NOW(), 'analysis', $2, $3, 'Zimmerman Parsers', $4)`,
      [caseId,
       'Parsing termine: ' + totalRecords + ' enregistrements',
       'Types: ' + typesToParse.join(', '),
       req.user.id]
    );

    try {
      const { correlateCaseAsync } = require('../services/taxiiService');
      correlateCaseAsync(caseId, pool);
    } catch (e) {
      logger.warn('[ThreatIntel] correlateCase require error:', e.message);
    }

    try {
      const { runSoarAsync } = require('../services/soarService');
      runSoarAsync(caseId, pool, 'auto', io);
    } catch (e) {
      logger.warn('[SOAR] trigger error:', e.message);
    }

    try {
      const { autoTriageArtifact } = require('../services/autoTriageService');
      autoTriageArtifact({
        pool, caseId, resultId,
        artifactTypes: typesToParse,
        totalRecords,
        userId: req.user.id,
        io,
      });
    } catch (e) {
      logger.warn('[auto-triage] trigger error:', e.message);
    }

    // Auto-run all detection engines in the background now that parsing is done.
    try {
      const { startRunAll } = require('../services/runAllService');
      startRunAll(caseId, req.user, 'auto');
      if (io) io.to(`user:${req.user.id}`).emit('notification:job_done', {
        type: 'detection', caseId, status: 'started',
        message: 'Détection automatique lancée en arrière-plan',
      });
    } catch (e) {
      logger.warn('[run-all] auto-trigger error:', e.message);
    }

    if (io) {
      const donePayload = {
        id: resultId,
        results,
        total_records: totalRecords,
        unified_timeline_count: totalRecords,
      };
      if (socketId) io.to(socketId).emit('collection:parse:done', donePayload);
      else logger.warn('[collection] parse done but no socketId — client will not be notified');
      // Broadcast to every client viewing this case (not just the initiating
      // socket) so all open tabs refresh their results when the parse ends.
      io.to(caseId).emit('collection:parse:done', donePayload);

      io.to(`user:${req.user.id}`).emit('notification:job_done', {
        type: 'parse',
        caseId,
        status: 'done',
        message: `Parsing terminé : ${totalRecords.toLocaleString('fr-FR')} événements indexés`,
        total_records: totalRecords,
      });
    }

    // ES is indexed fire-and-forget during the parse; if its document count
    // drifted from PG (duplicates, a timed-out delete, an interrupted bulk),
    // rebuild the case index from PG so the SuperTimeline and the per-evidence
    // menu always show the same total.
    try {
      const { rebuildEsFromPg } = require('../services/esRebuild');
      rebuildEsFromPg(caseId).catch(e =>
        logger.warn(`[ES] rebuild after parse failed (${caseId}): ${String(e.message).substring(0, 150)}`));
    } catch (e) {
      logger.warn('[ES] rebuild require error:', e.message);
    }
  } catch (dbErr) {
    parseJobOutcome = 'error';
    parseJobError = dbErr;
    logger.error('[collection] parse DB error:', dbErr.message);
    if (io) {
      if (socketId) io.to(socketId).emit('collection:parse:error', {
        error: 'Erreur stockage résultats',
        details: dbErr.message,
      });
      io.to(caseId).emit('collection:parse:error', {
        error: 'Erreur stockage résultats',
        details: dbErr.message,
      });
      io.to(`user:${req.user.id}`).emit('notification:job_done', {
        type: 'parse',
        caseId,
        status: 'error',
        message: `Erreur stockage résultats : ${dbErr.message.substring(0, 120)}`,
      });
    }
  }

      } catch (parseErr) {
        parseJobOutcome = 'error';
        parseJobError = parseErr;
        logger.error('[collection] async parse error:', parseErr.message);
        if (io) {
          if (socketId) io.to(socketId).emit('collection:parse:error', {
            error: 'Erreur parsing',
            details: parseErr.message,
          });
          io.to(caseId).emit('collection:parse:error', {
            error: 'Erreur parsing',
            details: parseErr.message,
          });
          io.to(`user:${req.user.id}`).emit('notification:job_done', {
            type: 'parse',
            caseId,
            status: 'error',
            message: `Erreur parsing : ${parseErr.message.substring(0, 120)}`,
          });
        }
      } finally {
        // Stop the liveness heartbeat — the parse has settled.
        clearInterval(progressHeartbeat);
        // The job has settled (done / DB-error / crash) — mark the progress
        // entry terminal with its outcome so /parse-progress hands the UI a
        // real terminal state (success / error + message) instead of a blank
        // 'nothing active' void.
        const e = PARSE_PROGRESS.get(caseId);
        if (e) {
          e.done = true;
          e.outcome = parseJobOutcome;
          e.updatedAt = Date.now();
          if (parseJobOutcome === 'error') e.error = (parseJobError && parseJobError.message) || 'Erreur de parsing';
        }
        // Free the per-collection lock so the same collection can be re-parsed.
        ACTIVE_PARSE_LOCKS.delete(lockKey);
        // Also mark the durable DB record terminal so a backend-restart fallback
        // never resurrects a finished/crashed parse as "still running".
        pool.query(
          `UPDATE parser_results
              SET output_data = jsonb_set(COALESCE(output_data, '{}'::jsonb), '{status}', '"done"', true),
                  updated_at = NOW()
            WHERE case_id = $1 AND parser_name = 'UnifiedTimeline'
              AND output_data->>'status' = 'parsing'`,
          [caseId]
        ).catch(() => {});
      }
    })();
});

// v2.24 — hydrate forensic columns from raw JSON when ES/PG docs predate v2.23.
// Pure in-memory; doesn't mutate storage. Keeps ES-first path fast while the
// timeline grid gets populated tool / event_id / ext / path / host / user cells.
const _TOOL_BY_ARTIFACT = {
  evtx: 'EvtxECmd', mft: 'MFTECmd', prefetch: 'PECmd', lnk: 'LECmd',
  jumplist: 'JLECmd', shellbags: 'SBECmd', amcache: 'AmcacheParser',
  appcompat: 'AppCompatCacheParser', registry: 'RECmd', srum: 'SrumECmd',
  sqle: 'SQLECmd', wxtcmd: 'WxTCmd', recycle: 'RBCmd', bits: 'BitsParser',
  sum: 'SumECmd', hayabusa: 'Hayabusa',
};
function _pickStr(raw, keys) {
  if (!raw) return null;
  for (const k of keys) {
    const v = raw[k];
    if (v !== null && v !== undefined && String(v).trim() !== '') return String(v).trim();
  }
  return null;
}
function hydrateTimelineRow(r) {
  if (!r) return r;
  const raw = r.raw || {};
  const at = r.artifact_type;
  if (!r.tool)        r.tool = _TOOL_BY_ARTIFACT[at] || at;
  if (r.event_id == null) {
    const eidRaw = _pickStr(raw, ['EventId', 'EventID', 'event_id']);
    if (eidRaw && /^\d+$/.test(eidRaw)) r.event_id = parseInt(eidRaw, 10);
  }
  if (!r.host_name)
    r.host_name = _pickStr(raw, (ECS_COLUMNS[at] && ECS_COLUMNS[at].host) || ['Computer', 'ComputerName']);
  if (!r.user_name)
    r.user_name = _pickStr(raw, (ECS_COLUMNS[at] && ECS_COLUMNS[at].user) || ['UserName']);
  // process_name: for AppCompat we explicitly want NO process (path-only), skip if empty
  if (!r.process_name && at !== 'appcompat' && at !== 'mft') {
    r.process_name = _pickStr(raw, (ECS_COLUMNS[at] && ECS_COLUMNS[at].process) || []);
  }
  if (!r.path)
    r.path = _pickStr(raw, ['FolderPath', 'FullPath', 'TargetPath', 'SourceFilename', 'Path']);
  if (!r.ext) {
    const nameForExt = _pickStr(raw, ['FileName', 'ExecutableName', 'TargetFilename', 'Path', 'FullPath']) || r.source || '';
    const m = /\.([A-Za-z0-9]{1,10})$/.exec(nameForExt);
    if (m) r.ext = '.' + m[1].toLowerCase();
  }
  if (!r.timestamp_kind) r.timestamp_kind = _pickStr(raw, ['TimeCreated', 'LastModified', 'Created0x10', 'Created0x30']);
  // EVTX / Hayabusa per-EventID MITRE override when empty
  if (!r.mitre_technique_id && (at === 'evtx' || at === 'hayabusa') && r.event_id != null) {
    const m = EVTX_MITRE_BY_EID[r.event_id];
    if (m) {
      r.mitre_technique_id = m.technique_id;
      r.mitre_technique_name = m.technique_name;
      r.mitre_tactic = m.tactic;
    }
  }
  return r;
}

// Sigma hunt pivot predicate resolution — shared by GET /timeline and GET
// /timeline/groups so a hunt-scoped fetch means the same restriction in
// every view that accepts hunt_id, not just the one it shipped on first.
// "click a match, land on the SuperTimeline filtered to it" needs the FULL
// matched set, not the 50-row sample stored on
// sigma_hunt_results.matched_events. Rather than ship a 5 342-id array
// through the wire and have the caller filter on `id = ANY(...)` (still a
// de-facto id list, just moved from the URL to a request the size of the id
// list), this re-parses the rule that produced the hunt and hands back its
// predicate for the caller to AND into its own `conditions` — the same
// "replay, don't read the sample" approach as GET
// /sigma/hunt/:caseId/:huntId/timeline-ids in threatHunting.ts.
const HUNT_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// A hunt-scoped fetch that yields zero rows must say so explicitly — zero
// here almost always means the matched rows were removed from
// collection_timeline since the hunt ran, not that the filter was ignored.
const HUNT_EMPTY_MESSAGE = 'Aucun événement de la timeline ne correspond actuellement à cette chasse — ils ont peut-être été supprimés depuis.';

async function resolveHuntPredicate(caseId, huntId) {
  if (!HUNT_UUID_RE.test(huntId)) {
    return { ok: false, status: 400, error: 'Paramètre hunt_id invalide' };
  }
  const huntRow = await pool.query(
    `SELECT r.content
       FROM sigma_hunt_results h
       JOIN sigma_rules r ON r.id = h.rule_id
      WHERE h.id = $1 AND h.case_id = $2`,
    [huntId, caseId],
  );
  if (huntRow.rows.length === 0) {
    return { ok: false, status: 404, error: 'Chasse introuvable pour ce cas.' };
  }
  const huntParsed = parseRule(huntRow.rows[0].content);
  if (!huntParsed.valid || !huntParsed.parsed) {
    return { ok: false, status: 500, error: `Règle invalide au moment du pivot : ${huntParsed.error}` };
  }
  const { where, params } = buildQuery(huntParsed.parsed);
  return { ok: true, where, params };
}

// huntPredicate.where numbers its own placeholders from $1 — shift them onto
// the next free slot (`nextParamIndex`) in the caller's own params array,
// the same renumbering `shiftedWhere` does in threatHunting.ts.
function shiftHuntPredicate(where, nextParamIndex) {
  return where.replace(/\$(\d+)/g, (_m, n) => `$${parseInt(n, 10) + nextParamIndex - 1}`);
}

// ── Artifact browser ──────────────────────────────────────────────────────
// Per-artifact-type data browser (registry hives, $MFT, EVTX, prefetch…)
// separate from the merged timeline. Rows carry the full `raw` CSV columns so
// each type is inspected with its own native fields rather than only the
// normalized timeline projection.

const ARTIFACT_TYPE_RE = /^[a-z][a-z0-9_]{0,31}$/;
const UUID_RE_G = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Raw-column filters for the artifact browser. `filters` arrives as a JSON
// array of { col, op, value } applied against `raw->>'col'`:
//   eq        exact match
//   neq       exact non-match
//   contains  case-insensitive substring
//   in        comma-separated value list (e.g. EventId "4624,4625")
// Column names are whitelisted (identifier charset) before interpolation so
// the filter can never inject SQL. Values are always parameterized.
const ARTIFACT_FILTER_COL_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const ARTIFACT_FILTER_OPS = new Set(['eq', 'neq', 'contains', 'in']);

function parseArtifactFilters(rawFilters) {
  if (!rawFilters || typeof rawFilters !== 'string') return null;
  let arr;
  try { arr = JSON.parse(rawFilters); } catch { return null; }
  if (!Array.isArray(arr)) return null;
  const out = [];
  for (const f of arr.slice(0, 12)) {
    if (!f || typeof f !== 'object') continue;
    const col = String(f.col || '');
    const op = String(f.op || '');
    if (!ARTIFACT_FILTER_COL_RE.test(col)) continue;
    if (!ARTIFACT_FILTER_OPS.has(op)) continue;
    if (op === 'in') {
      const vals = String(f.value == null ? '' : f.value).split(',').map(s => s.trim()).filter(Boolean).slice(0, 100);
      if (vals.length === 0) continue;
      out.push({ col, op: 'in', value: vals });
    } else {
      const value = String(f.value == null ? '' : f.value).slice(0, 200);
      if (value === '') continue;
      out.push({ col, op, value });
    }
  }
  return out;
}

// Filterable columns per artifact type, exposed as facets (distinct values +
// counts) so the UI can render dropdowns. Empty for types with no facets.
const ARTIFACT_FACET_COLUMNS = {
  evtx: ['EventId', 'Channel', 'Level', 'Computer', 'Provider'],
};

router.get('/:caseId/artifacts', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id } = req.query;
    const params = [caseId];
    let evidenceFilter = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) {
        return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      }
      evidenceFilter = 'AND evidence_id = $2';
      params.push(evidence_id);
    }
    const { rows } = await pool.query(
      `SELECT artifact_type, MAX(artifact_name) AS artifact_name, COUNT(*)::int AS cnt
         FROM collection_timeline
        WHERE case_id = $1 ${evidenceFilter}
        GROUP BY artifact_type
        ORDER BY cnt DESC, artifact_type`, params);
    res.json({ artifacts: rows });
  } catch (err) {
    logger.error('Artifact summary error:', err);
    res.status(500).json({ error: "Erreur récupération des types d'artefacts" });
  }
});

// Live per-evidence timeline row counts for the evidence cards' artifact
// badge. Reads collection_timeline directly — never the parser_results
// snapshot, which goes stale mid-parse (and stays stale if the job crashes
// before finalization) — so the badge converges with the artifacts browser
// and the timeline as rows stream in.
router.get('/:caseId/evidence-counts', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { rows } = await pool.query(
      `SELECT evidence_id, COUNT(*)::int AS cnt
         FROM collection_timeline
        WHERE case_id = $1 AND evidence_id IS NOT NULL
        GROUP BY evidence_id`, [caseId]);
    const counts = {};
    for (const r of rows) counts[r.evidence_id] = r.cnt;
    res.json({ counts });
  } catch (err) {
    logger.error('Evidence counts error:', err);
    res.status(500).json({ error: 'Erreur comptage evidences' });
  }
});

// Multi-artifact search: one keyword/regex across every artifact type in the
// collection, returning per-type counts plus a bounded sample of matching rows.
// Registered before /artifacts/:type so "search" is never captured as a type.
router.get('/:caseId/artifacts/search', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id, q = '', regex = '0', start_time, end_time } = req.query;
    const query = String(q).trim().slice(0, 500);
    if (!query) return res.status(400).json({ error: 'Paramètre q manquant' });
    const isRegex = regex === '1' || regex === 'true';

    if (isRegex) {
      try { new RegExp(query); } catch (_e) { return res.status(400).json({ error: 'Expression régulière invalide' }); }
    }

    const conditions = ['case_id = $1'];
    const params = [caseId];
    let pi = 2;
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      conditions.push(`evidence_id = $${pi++}`);
      params.push(evidence_id);
    }
    if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time); }
    // Multi-keyword 'contains' via the shared builder (space-separated terms,
    // AND semantics, quoted phrases kept whole). Regex stays single-pattern.
    pi = pushSearchFilter(query, isRegex ? 'regex' : 'contains', pi, conditions, params);
    const where = conditions.join(' AND ');

    const countsRes = await pool.query(
      `SELECT artifact_type, COUNT(*)::int AS cnt
         FROM collection_timeline WHERE ${where}
        GROUP BY artifact_type ORDER BY cnt DESC, artifact_type`, params);

    const rowsRes = await pool.query(
      `SELECT id, timestamp, artifact_type, description, details, source, host_name, raw
         FROM collection_timeline WHERE ${where}
        ORDER BY timestamp DESC, id DESC LIMIT 200`, params);

    const total = countsRes.rows.reduce((s, r) => s + r.cnt, 0);

    res.json({
      query,
      regex: isRegex,
      total,
      truncated: total > rowsRes.rows.length,
      types: countsRes.rows,
      records: rowsRes.rows,
    });
  } catch (err) {
    if (err && (err.code === '2201B' || /invalid regular expression/i.test(err.message || ''))) {
      return res.status(400).json({ error: 'Expression régulière invalide' });
    }
    logger.error('Artifact search error:', err);
    res.status(500).json({ error: "Erreur de recherche d'artefacts" });
  }
});

router.get('/:caseId/artifacts/:type', authenticate, async (req, res) => {
  try {
    const { caseId, type } = req.params;
    if (!ARTIFACT_TYPE_RE.test(type || '')) {
      return res.status(400).json({ error: "Type d'artefact invalide" });
    }
    const { evidence_id, search = '', search_op = 'contains', sort_dir = 'asc', start_time, end_time } = req.query;
    const pg = Math.max(1, parseInt(req.query.page) || 1);
    const lim = Math.min(500, Math.max(1, parseInt(req.query.limit) || 100));
    const offset = (pg - 1) * lim;
    const direction = sort_dir === 'desc' ? 'DESC' : 'ASC';

    const conditions = ['case_id = $1', 'artifact_type = $2'];
    const params = [caseId, type];
    let pi = 3;
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) {
        return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      }
      conditions.push(`evidence_id = $${pi++}`);
      params.push(evidence_id);
    }
    if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time); }
    if (search) {
      const isRegex = search_op === 'regex';
      if (isRegex) {
        try { new RegExp(String(search)); } catch (_e) { return res.status(400).json({ error: 'Expression régulière invalide' }); }
        pi = pushSearchFilter(String(search).slice(0, 500), 'regex', pi, conditions, params);
      } else {
        pi = pushSearchFilter(String(search).slice(0, 500), search_op, pi, conditions, params);
      }
    }
    const filters = parseArtifactFilters(req.query.filters);
    if (filters) {
      for (const f of filters) {
        if (f.op === 'eq') {
          conditions.push(`raw->>'${f.col}' = $${pi++}`);
          params.push(f.value);
        } else if (f.op === 'neq') {
          conditions.push(`raw->>'${f.col}' <> $${pi++}`);
          params.push(f.value);
        } else if (f.op === 'contains') {
          conditions.push(`raw->>'${f.col}' ILIKE $${pi++}`);
          params.push(`%${escapeLike(f.value)}%`);
        } else if (f.op === 'in') {
          conditions.push(`raw->>'${f.col}' = ANY($${pi++}::text[])`);
          params.push(f.value);
        }
      }
    }
    const where = conditions.join(' AND ');

    const totalRes = await pool.query(
      `SELECT COUNT(*)::int AS total FROM collection_timeline WHERE ${where}`, params);
    const total = totalRes.rows[0].total;

    const rowsRes = await pool.query(
      `SELECT id, timestamp, artifact_type, artifact_name, description, details, source,
              host_name, user_name, process_name, "path", ext, event_id, file_size,
              src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, raw
         FROM collection_timeline
        WHERE ${where}
        ORDER BY timestamp ${direction}, id ${direction}
        LIMIT $${pi} OFFSET $${pi + 1}`, [...params, lim, offset]);

    const colSet = new Set();
    for (const r of rowsRes.rows) {
      if (r.raw && typeof r.raw === 'object') {
        for (const k of Object.keys(r.raw)) colSet.add(k);
      }
    }

    res.json({
      records: rowsRes.rows,
      total,
      page: pg,
      limit: lim,
      total_pages: Math.ceil(total / lim),
      columns: [...colSet],
    });
  } catch (err) {
    if (err && (err.code === '2201B' || /invalid regular expression/i.test(err.message || ''))) {
      return res.status(400).json({ error: 'Expression régulière invalide' });
    }
    logger.error('Artifact rows error:', err);
    res.status(500).json({ error: "Erreur récupération des données d'artefact" });
  }
});

// Distinct values (with counts) for the filterable columns of a type — feeds
// the EVTX filter dropdowns in the artifact browser.

router.get('/:caseId/artifacts/:type/facets', authenticate, async (req, res) => {
  try {
    const { caseId, type } = req.params;
    if (!ARTIFACT_TYPE_RE.test(type || '')) {
      return res.status(400).json({ error: "Type d'artefact invalide" });
    }
    const cols = ARTIFACT_FACET_COLUMNS[type] || [];
    if (cols.length === 0) return res.json({ facets: {} });

    const { evidence_id } = req.query;
    const params = [caseId, type];
    let ev = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      ev = 'AND evidence_id = $3';
      params.push(evidence_id);
    }

    const facets = {};
    for (const col of cols) {
      if (!ARTIFACT_FILTER_COL_RE.test(col)) continue;
      const { rows } = await pool.query(
        `SELECT raw->>'${col}' AS value, COUNT(*)::int AS cnt
           FROM collection_timeline
          WHERE case_id = $1 AND artifact_type = $2 ${ev}
            AND raw->>'${col}' IS NOT NULL AND raw->>'${col}' <> ''
          GROUP BY 1 ORDER BY cnt DESC, value LIMIT 60`, params);
      facets[col] = rows;
    }
    res.json({ facets });
  } catch (err) {
    logger.error('Artifact facets error:', err);
    res.status(500).json({ error: 'Erreur récupération des facettes' });
  }
});

// Hierarchical artifact types that get a tree view in the artifact browser.
// `pathExpr` is the raw column holding the tree path (split on '\'), `select`
// the per-row leaf fields, `valueRow` their projection to a leaf entry.
// `groupExpr` is the raw column used to split a type into separate trees
// (one hive for registry, one explorer hive per user for shellbags); when
// null the whole type is a single tree (e.g. $MFT).
const TREE_TYPES = {
  registry: {
    needsGroup: true,
    groupExpr: "COALESCE(raw->>'HivePath','?')",
    groupLabel: 'hive',
    pathExpr: "raw->>'KeyPath'",
    orderBy: "raw->>'KeyPath'",
    select: "raw->>'KeyPath' AS keypath, raw->>'ValueName' AS vname, raw->>'ValueData' AS vdata, raw->>'ValueType' AS vtype, timestamp",
    valueRow: (r) => ({ name: r.vname, data: r.vdata, type: r.vtype, last_write: r.timestamp }),
  },
  shellbags: {
    needsGroup: true,
    groupExpr: "COALESCE(raw->>'HivePath','?')",
    groupLabel: 'user',
    pathExpr: "raw->>'AbsolutePath'",
    orderBy: "raw->>'AbsolutePath'",
    select: "raw->>'AbsolutePath' AS keypath, description, source, timestamp",
    // Each shellbag row is one folder entry; its leaf name is the path basename.
    valueRow: (r) => {
      const segs = (r.keypath || '').split('\\').filter(Boolean);
      return { name: segs.length ? segs[segs.length - 1] : r.keypath, description: r.description, last_write: r.timestamp };
    },
  },
  mft: {
    needsGroup: false,
    groupExpr: null,
    groupLabel: null,
    pathExpr: "raw->>'ParentPath'",
    orderBy: "raw->>'ParentPath'",
    select: "raw->>'ParentPath' AS keypath, COALESCE(raw->>'FileName', description) AS vname, description, file_size, timestamp,"
      + " raw->>'Extension' AS ext, raw->>'IsDirectory' AS is_dir, raw->>'InUse' AS in_use,"
      + " raw->>'Created0x10' AS created0x10, raw->>'Created0x30' AS created0x30,"
      + " raw->>'LastModified0x10' AS modified0x10, raw->>'LastModified0x30' AS modified0x30,"
      + " raw->>'LastAccess0x20' AS access0x20, raw->>'ObjectID' AS object_id",
    // Rich per-file facts feed the inline details panel of the tree browser
    // (copy-path + file details) without a second round-trip per row. The
    // extra fields are short scalars, so the payload stays lean even at the
    // 50k-row cap.
    valueRow: (r) => ({
      name: r.vname, description: r.description, size: r.file_size, last_write: r.timestamp,
      details: {
        extension: r.ext, is_directory: r.is_dir, in_use: r.in_use,
        created: r.created0x10, created_fn: r.created0x30,
        modified: r.modified0x10, modified_fn: r.modified0x30,
        last_access: r.access0x20, object_id: r.object_id,
      },
    }),
  },
};

// Group list (hives / users / …) for tree-capable artifact types.
// Each group is one independent tree rendered by the artifact browser.

router.get('/:caseId/artifacts/:type/groups', authenticate, async (req, res) => {
  try {
    const { caseId, type } = req.params;
    const cfg = TREE_TYPES[type];
    if (!cfg) return res.status(400).json({ error: "Type non pris en charge pour l'arborescence" });
    if (!cfg.needsGroup) return res.json({ needs_group: false, groups: [] });
    const { evidence_id } = req.query;
    const params = [caseId, type];
    let ev = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      ev = 'AND evidence_id = $3';
      params.push(evidence_id);
    }
    const { rows } = await pool.query(
      `SELECT ${cfg.groupExpr} AS grp,
              COUNT(*)::int AS value_count,
              COUNT(DISTINCT ${cfg.pathExpr})::int AS key_count
         FROM collection_timeline
        WHERE case_id = $1 AND artifact_type = $2 ${ev}
        GROUP BY 1 ORDER BY value_count DESC, grp`, params);
    res.json({ needs_group: true, groups: rows.map(r => ({ group: r.grp, value_count: r.value_count, key_count: r.key_count })) });
  } catch (err) {
    logger.error('Artifact groups error:', err);
    res.status(500).json({ error: 'Erreur récupération des groupes' });
  }
});

router.get('/:caseId/artifacts/:type/tree', authenticate, async (req, res) => {
  try {
    const { caseId, type } = req.params;
    const cfg = TREE_TYPES[type];
    if (!cfg) return res.status(400).json({ error: "Type non pris en charge pour l'arborescence" });
    const { evidence_id, group, search = '' } = req.query;
    const params = [caseId, type];
    let pi = 3;
    let extra = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      extra += ` AND evidence_id = $${pi++}`;
      params.push(evidence_id);
    }
    if (cfg.needsGroup) {
      if (!group) return res.status(400).json({ error: 'Paramètre group manquant' });
      extra += ` AND ${cfg.groupExpr} = $${pi++}`;
      params.push(String(group).slice(0, 255));
    }
    const q = String(search).trim().slice(0, 200);
    if (q) {
      // Multi-keyword tree search: every term must match the path or the raw
      // JSON — `Windows System32` narrows to paths containing both.
      for (const term of splitSearchTerms(q)) {
        extra += ` AND (${cfg.pathExpr} ILIKE $${pi} OR raw::text ILIKE $${pi})`;
        params.push('%' + escapeLike(term) + '%');
        pi++;
      }
    }
    const { rows } = await pool.query(
      `SELECT ${cfg.select}
         FROM collection_timeline
        WHERE case_id = $1 AND artifact_type = $2${extra}
        ORDER BY ${cfg.orderBy}
        LIMIT 50000`, params);

    const makeNode = (name) => ({ name, values: [], children: new Map() });
    const roots = new Map();
    const rootValues = [];
    for (const r of rows) {
      const segs = (r.keypath || '').split('\\').filter(Boolean);
      if (segs.length === 0) {
        rootValues.push(cfg.valueRow(r));
        continue;
      }
      let level = roots;
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i];
        if (!level.has(seg)) level.set(seg, makeNode(seg));
        const n = level.get(seg);
        if (i === segs.length - 1) n.values.push(cfg.valueRow(r));
        level = n.children;
      }
    }
    const toArr = (map) => [...map.values()].map(n => ({
      name: n.name, values: n.values, children: toArr(n.children),
    }));
    const rootNodes = toArr(roots);
    if (rootValues.length > 0) rootNodes.unshift({ name: '(racine)', values: rootValues, children: [] });
    res.json({
      type,
      group: group || '',
      truncated: rows.length >= 50000,
      value_count: rows.length,
      roots: rootNodes,
    });
  } catch (err) {
    logger.error('Artifact tree error:', err);
    res.status(500).json({ error: 'Erreur construction arborescence' });
  }
});


router.get('/:caseId/timeline', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { artifact_types, search, search_op = 'contains', start_time, end_time, host_name, user_name, result_id, evidence_id,
            evidence_ids, hunt_id,
            tool, event_id, ext, tag, tags: tagsParam, dedupe,
            detections: detectionsParam, detection_severity, detection_category,
            host_name_op = 'contains', user_name_op = 'contains', tool_op, ext_op,
            page = 1, limit = 200, sort_dir = 'asc', sort_col = 'timestamp',
            sort_multi } = req.query;

    const toolList    = (!tool_op && tool) ? String(tool).split(',').map(s => s.trim()).filter(Boolean) : null;
    const extList     = (!ext_op  && ext)  ? String(ext).split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : null;
    const eventIdList = event_id
      ? String(event_id).split(',').map(s => parseInt(s, 10)).filter(Number.isFinite)
      : null;
    const rawTags = tagsParam || tag;
    const tagList = rawTags
      ? String(rawTags).split(',').map(s => s.trim()).filter(t => t && /^[\w:.\-]{1,64}$/.test(t))
      : null;
    const collapseDupes = dedupe === 'collapse' || dedupe === '1' || dedupe === 'true';
    const hasDetectionFilter = Boolean(detectionsParam || detection_severity || detection_category);
    // hunt_id counts as an "advanced filter" purely to keep it off the
    // Elasticsearch fast path below — ES has no notion of a Sigma predicate,
    // only Postgres (via huntPredicate, resolved further down) does.
    const hasAdvancedFilters = Boolean(toolList || extList || eventIdList || tagList || collapseDupes || hasDetectionFilter || hunt_id);

    const safeSortMulti = typeof sort_multi === 'string' && /^[\w,:]+$/.test(sort_multi)
      ? sort_multi : undefined;
    const pg        = Math.max(1, parseInt(page)  || 1);
    const lim       = Math.max(1, parseInt(limit) || 200);
    const offset    = (pg - 1) * lim;
    const direction = sort_dir === 'desc' ? 'DESC' : 'ASC';

    const SAFE_SORT_COLS = new Set(['timestamp', 'artifact_type', 'artifact_name', 'description', 'source']);
    const safeCol = SAFE_SORT_COLS.has(sort_col) ? sort_col : 'timestamp';

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    if (evidence_id) {

      if (!UUID_RE.test(evidence_id)) {
        return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      }
      const evCheck = await pool.query(
        `SELECT 1 FROM evidence WHERE id = $1 AND case_id = $2`,
        [evidence_id, caseId]
      );
      if (evCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Accès refusé : cette collecte n\'appartient pas à ce cas' });
      }
    }

    let validatedEvidenceIds = null;
    if (!evidence_id && evidence_ids) {
      const ids = evidence_ids.split(',').map(s => s.trim()).filter(Boolean);
      const invalid = ids.filter(id => !UUID_RE.test(id));
      if (invalid.length > 0) {
        return res.status(400).json({ error: `Paramètres evidence_ids invalides: ${invalid.slice(0, 3).join(', ')}` });
      }
      if (ids.length > 0) {
        const check = await pool.query(
          `SELECT id FROM evidence WHERE id = ANY($1::uuid[]) AND case_id = $2`,
          [ids, caseId]
        );
        if (check.rows.length !== ids.length) {
          return res.status(403).json({ error: 'Accès refusé : une ou plusieurs collectes n\'appartiennent pas à ce cas' });
        }
        validatedEvidenceIds = ids;
      }
    }

    // Sigma hunt pivot (Task 5, docs/superpowers/plans/2026-08-07-sigma-
    // platform-scoping-and-honest-counts.md): "click a match, land on the
    // SuperTimeline filtered to it" — see resolveHuntPredicate() above for
    // why this replays the rule's predicate instead of shipping an id list.
    // Every existing filter (search, host, artifact type…) still composes
    // with it, same as before extraction.
    let huntPredicate = null; // { where, params } once resolved
    if (hunt_id) {
      const resolvedHunt = await resolveHuntPredicate(caseId, hunt_id);
      if (!resolvedHunt.ok) return res.status(resolvedHunt.status).json({ error: resolvedHunt.error });
      huntPredicate = { where: resolvedHunt.where, params: resolvedHunt.params };
    }

    // Build the PG filter set first — the ES fast-path below needs the same
    // WHERE/params to verify ES is at least as complete as PG before serving it.
    const conditions = ['case_id = $1'];
    const params     = [caseId];
    let   pi         = 2;

    if (artifact_types) {
      conditions.push(`artifact_type = ANY($${pi++})`);
      params.push(artifact_types.split(','));
    }
    if (search || search_op === 'empty' || search_op === 'not_empty') {
      pi = pushSearchFilter(search || '', search_op, pi, conditions, params);
    }
    if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time);   }
    if (host_name || host_name_op === 'empty' || host_name_op === 'not_empty')
      pi = pushTextFilter('host_name', host_name || '', host_name_op, pi, conditions, params);
    if (user_name || user_name_op === 'empty' || user_name_op === 'not_empty')
      pi = pushTextFilter('user_name', user_name || '', user_name_op, pi, conditions, params);
    if (result_id)   { conditions.push(`result_id = $${pi++}`);      params.push(result_id);  }
    if (evidence_id) { conditions.push(`evidence_id = $${pi++}`);    params.push(evidence_id); }
    if (validatedEvidenceIds) { conditions.push(`evidence_id = ANY($${pi++}::uuid[])`); params.push(validatedEvidenceIds); }
    if (tool_op && (tool || tool_op === 'empty' || tool_op === 'not_empty'))
      pi = pushTextFilter('tool', tool || '', tool_op, pi, conditions, params);
    else if (toolList && toolList.length)
      { conditions.push(`tool = ANY($${pi++}::text[])`); params.push(toolList); }

    if (ext_op && (ext || ext_op === 'empty' || ext_op === 'not_empty'))
      pi = pushTextFilter('ext', ext || '', ext_op, pi, conditions, params);
    else if (extList && extList.length)
      { conditions.push(`lower(ext) = ANY($${pi++}::text[])`); params.push(extList); }
    if (eventIdList && eventIdList.length) { conditions.push(`event_id = ANY($${pi++}::int[])`);  params.push(eventIdList); }
    if (tagList && tagList.length)         { conditions.push(`tags && $${pi++}::text[]`);         params.push(tagList); }

    // v2.26 — Threat Engine quick filters
    const hitsOnly = detectionsParam === 'hits_only' || detectionsParam === 'hits' || detectionsParam === '1' || detectionsParam === 'true';
    if (hitsOnly) {
      conditions.push(`detections IS NOT NULL AND jsonb_array_length(detections) > 0`);
    }
    if (detection_severity && /^(greyware|low|medium|high|critical)(,(greyware|low|medium|high|critical))*$/.test(String(detection_severity))) {
      const sevList = String(detection_severity).split(',');
      const orParts = sevList.map((_, i) => `detections @> $${pi + i}::jsonb`);
      conditions.push('(' + orParts.join(' OR ') + ')');
      for (const s of sevList) params.push(JSON.stringify([{ severity: s }]));
      pi += sevList.length;
    }
    if (detection_category && /^[\w_]{1,32}(,[\w_]{1,32})*$/.test(String(detection_category))) {
      const catList = String(detection_category).split(',');
      const orParts = catList.map((_, i) => `detections @> $${pi + i}::jsonb`);
      conditions.push('(' + orParts.join(' OR ') + ')');
      for (const c of catList) params.push(JSON.stringify([{ category: c }]));
      pi += catList.length;
    }
    if (huntPredicate) {
      conditions.push(`(${shiftHuntPredicate(huntPredicate.where, pi)})`);
      params.push(...huntPredicate.params);
      pi += huntPredicate.params.length;
    }

    const where = conditions.join(' AND ');

    // The ES fast path is served only for filter browsing (no free-text search).
    // PG's search now covers event_id/host/user/tool/path (ES does not), and ES
    // multi_match cannot evaluate search_op (empty/not_empty/regex), so a total
    // comparison can never guarantee equal result sets once a search is active.
    const esSearchEligible = !search && !(search_op === 'empty' || search_op === 'not_empty' || search_op === 'regex');
    if (!host_name && !user_name && !hasAdvancedFilters && esSearchEligible) {
      try {
        const hasIndex = await esService.indexExists(caseId);
        if (hasIndex) {
          const esResult = await esService.searchTimeline(caseId, {
            page: pg, limit: lim, sort_dir, sort_col: safeCol,
            ...(safeSortMulti ? { sort_multi: safeSortMulti } : {}),
            artifact_types, search, start_time, end_time, result_id, evidence_id,
            evidence_ids: validatedEvidenceIds,
          });
          if (esResult.total > 0) {
            // ES is indexed fire-and-forget during parsing and can silently lag
            // behind PG (or a bulk batch can fail). A partial ES index must never
            // shadow the complete PG data — that's how EVTX events "disappear"
            // from the SuperTimeline. Only serve ES when it is at least as
            // complete as PG for the same filters; otherwise fall through to PG.
            const pgCount = (await pool.query(
              `SELECT COUNT(*)::int AS total FROM collection_timeline WHERE ${where}`,
              params
            ).catch(() => ({ rows: [{ total: null }] }))).rows[0]?.total;
            // Strict equality, BOTH directions: an ES index can also hold MORE
            // documents than PG (the pre-dedupe indexing path bulk-indexed rows
            // Postgres skipped via ON CONFLICT). `ES < PG` was caught before;
            // `ES > PG` silently inflated the SuperTimeline count. Either way
            // serve PG (correct) and let the esRebuild sweep fix the index.
            if (pgCount !== null && esResult.total !== pgCount) {
              logger.warn(`[timeline] ES count mismatch (${esResult.total}/${pgCount}) — serving PG (caseId=${caseId})`);
            } else {
              logger.info(`[timeline] ES hit: ${esResult.total} records (caseId=${caseId})`);
              if (Array.isArray(esResult.records)) esResult.records.forEach(hydrateTimelineRow);
              return res.json(esResult);
            }
          }
        }
      } catch (esErr) {
        logger.warn(`[timeline] ES error, falling back to PG: ${String(esErr.message).substring(0, 100)}`);
      }
    }

    // The agg cache (artifact-type / host / user counts) must reflect the exact
    // filtered result set — serving case-wide counts while a search or advanced
    // filter is active makes the artifact pills lie about the current page.
    // Hashing WHERE + params keys the cache per exact filter combination; the
    // unfiltered browse view keeps its own stable entry (still a cache hit).
    const aggFingerprint = crypto.createHash('md5').update(where + JSON.stringify(params)).digest('hex').slice(0, 16);
    const aggCacheKey = `timeline:aggs:${caseId}:${evidence_id || ''}:${(validatedEvidenceIds || []).join(',')}:${hunt_id || ''}:${aggFingerprint}`;
    let cachedAggs = null;
    try {
      const redis = getRedis();
      if (redis) {
        const raw = await redis.get(aggCacheKey);
        if (raw) cachedAggs = JSON.parse(raw);
      }
    } catch (_e) {}

    const countSql = collapseDupes
      ? `SELECT COUNT(*)::int AS total FROM (
           SELECT DISTINCT COALESCE(dedupe_hash, id::text) AS k
             FROM collection_timeline WHERE ${where}
         ) d`
      : `SELECT COUNT(*)::int AS total FROM collection_timeline WHERE ${where}`;

    const rowsSql = collapseDupes
      ? `SELECT DISTINCT ON (COALESCE(dedupe_hash, id::text))
                id, timestamp, artifact_type, artifact_name, description, source,
                host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections,
                raw
           FROM collection_timeline
          WHERE ${where}
          ORDER BY COALESCE(dedupe_hash, id::text),
                   array_length(tags, 1) DESC NULLS LAST,
                   length(COALESCE(description, '')) DESC,
                   ${safeCol} ${direction}
          LIMIT $${pi} OFFSET $${pi + 1}`
      : `SELECT id, timestamp, artifact_type, artifact_name, description, source,
                host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections,
                raw
           FROM collection_timeline
          WHERE ${where}
          ORDER BY ${safeCol} ${direction}, id ${direction}
          LIMIT $${pi} OFFSET $${pi + 1}`;

    const baseQueries = [
      pool.query(countSql, params),
      pool.query(rowsSql, [...params, lim, offset]),
    ];

    let typesRes, hostsRes, usersRes;
    if (cachedAggs) {

      typesRes  = { rows: cachedAggs.types };
      hostsRes  = { rows: cachedAggs.hosts };
      usersRes  = { rows: cachedAggs.users };
    } else {

      baseQueries.push(
        pool.query(`SELECT artifact_type, COUNT(*)::int AS cnt FROM collection_timeline WHERE ${where} GROUP BY artifact_type ORDER BY artifact_type`, params),
        pool.query(`SELECT DISTINCT host_name FROM collection_timeline WHERE case_id = $1 AND host_name IS NOT NULL ORDER BY host_name LIMIT 100`, [caseId]),
        pool.query(`SELECT DISTINCT user_name FROM collection_timeline WHERE case_id = $1 AND user_name IS NOT NULL ORDER BY user_name LIMIT 100`, [caseId])
      );
    }

    const results = await Promise.all(baseQueries);
    const countRes = results[0];
    const rowsRes  = results[1];
    if (!cachedAggs) {
      typesRes = results[2];
      hostsRes = results[3];
      usersRes = results[4];

      try {
        const redis = getRedis();
        if (redis) {
          await redis.setex(aggCacheKey, 300, JSON.stringify({
            types: typesRes.rows,
            hosts: hostsRes.rows,
            users: usersRes.rows,
          }));
        }
      } catch (_e) {}
    }

    const total = countRes.rows[0].total;

    // A hunt-scoped fetch (`hunt_id`) that yields zero rows must say so
    // explicitly, never fall through to the legacy `UnifiedTimeline` blob
    // below — that fallback ignores the Sigma predicate entirely and could
    // hand back unrelated events, which would misrepresent a hunt as having
    // matches it doesn't have. Zero here almost always means the matched
    // rows were removed from collection_timeline since the hunt ran.
    if (total === 0 && hunt_id) {
      return res.json({
        records: [], total: 0, page: pg, limit: lim, total_pages: 0,
        artifact_types_available: [],
        hosts_available: [], users_available: [],
        hunt_empty: true,
        message: HUNT_EMPTY_MESSAGE,
      });
    }
    if (total === 0 && evidence_id) {
      return res.json({
        records: [], total: 0, page: pg, limit: lim, total_pages: 0,
        artifact_types_available: [],
        hosts_available: [], users_available: [],
        isolated: true,
      });
    }
    if (total === 0) {
      const oldRes = await pool.query(
        `SELECT output_data, record_count FROM parser_results
          WHERE case_id = $1 AND parser_name = 'UnifiedTimeline'
          ORDER BY created_at DESC LIMIT 1`,
        [caseId]
      );
      if (oldRes.rows.length === 0) return res.json({ records: [], total: 0, page: pg });

      let recs = (oldRes.rows[0].output_data.unified_timeline || []);
      if (artifact_types) { const t = artifact_types.split(','); recs = recs.filter(r => t.includes(r.artifact_type)); }
      if (search)         { const q = search.toLowerCase(); recs = recs.filter(r => (r.description || '').toLowerCase().includes(q) || (r.source || '').toLowerCase().includes(q)); }
      if (start_time)     recs = recs.filter(r => r.timestamp >= start_time);
      if (end_time)       recs = recs.filter(r => r.timestamp <= end_time);
      recs = recs.sort((a, b) => {
        const ta = a.timestamp || '', tb = b.timestamp || '';
        return direction === 'DESC' ? tb.localeCompare(ta) : ta.localeCompare(tb);
      });
      return res.json({
        records: recs.slice(offset, offset + lim),
        total: recs.length,
        page: pg, limit: lim,
        total_pages: Math.ceil(recs.length / lim),
        artifact_types_available: [...new Set(recs.map(r => r.artifact_type))],
      });
    }

    // Stream the response to avoid JSON.stringify string-length limit on large pages
    res.setHeader('Content-Type', 'application/json');
    res.write('{"records":[');
    for (let i = 0; i < rowsRes.rows.length; i++) {
      hydrateTimelineRow(rowsRes.rows[i]);
      if (i > 0) res.write(',');
      res.write(JSON.stringify(rowsRes.rows[i]));
    }
    res.write(']');
    res.write(`,"total":${total}`);
    res.write(`,"page":${pg}`);
    res.write(`,"limit":${lim}`);
    res.write(`,"total_pages":${Math.ceil(total / lim)}`);
    res.write(`,"artifact_types_available":${JSON.stringify(typesRes.rows.map(r => r.artifact_type))}`);
    res.write(`,"artifact_types_counts":${JSON.stringify(Object.fromEntries(typesRes.rows.map(r => [r.artifact_type, r.cnt])))}`);
    res.write(`,"hosts_available":${JSON.stringify(hostsRes.rows.map(r => r.host_name))}`);
    res.write(`,"users_available":${JSON.stringify(usersRes.rows.map(r => r.user_name))}`);
    res.end('}');
  } catch (err) {
    logger.error('Timeline fetch error:', err);
    res.status(500).json({ error: 'Erreur récupération timeline' });
  }
});

// Ordinal position of a row under the canonical focus ordering
// (timestamp ASC NULLS LAST, id ASC). Lets the client convert rank -> page.
router.get('/:caseId/timeline/locate', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const rowId = req.query.rowId;
    if (!rowId) return res.status(400).json({ error: 'rowId requis' });
    const tgt = await pool.query(
      'SELECT timestamp FROM collection_timeline WHERE id = $1 AND case_id = $2',
      [rowId, caseId]
    );
    if (tgt.rowCount === 0) return res.status(404).json({ error: 'Ligne introuvable' });
    const ts = tgt.rows[0].timestamp;
    // Count rows that sort strictly before the target under
    // (timestamp ASC NULLS LAST, id ASC). NULL timestamps sort last.
    const rank = await pool.query(
      `SELECT COUNT(*)::int AS rank FROM collection_timeline
        WHERE case_id = $1
          AND (
            (timestamp IS NOT NULL AND $2::timestamptz IS NOT NULL AND
              (timestamp < $2 OR (timestamp = $2 AND id < $3)))
            OR (timestamp IS NOT NULL AND $2::timestamptz IS NULL)
            OR (timestamp IS NULL AND $2::timestamptz IS NULL AND id < $3)
          )`,
      [caseId, ts, rowId]
    );
    res.json({ rank: rank.rows[0].rank });
  } catch (err) {
    res.status(500).json({ error: 'locate: ' + err.message });
  }
});

router.post('/:caseId/timeline/session', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const keepAlive = req.body?.keep_alive || '5m';

    const caseCheck = await pool.query('SELECT id FROM cases WHERE id = $1', [caseId]);
    if (caseCheck.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });

    const hasIndex = await esService.indexExists(caseId);
    if (!hasIndex) {
      return res.status(404).json({ error: 'Aucun index ES pour ce cas — utilisez la pagination classique' });
    }

    const pitId = await esService.openPIT(caseId, keepAlive);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    res.json({ pit_id: pitId, expires_at: expiresAt, keep_alive: keepAlive });
  } catch (err) {
    logger.error('PIT session open error:', err);
    res.status(500).json({ error: 'Erreur ouverture session PIT' });
  }
});

router.delete('/:caseId/timeline/session', authenticate, async (req, res) => {
  try {
    const pitId = req.body?.pit_id || req.query?.pit_id;
    if (!pitId) return res.status(400).json({ error: 'pit_id requis' });
    await esService.closePIT(pitId);
    res.json({ closed: true });
  } catch (err) {
    logger.error('PIT session close error:', err);
    res.status(500).json({ error: 'Erreur fermeture session PIT' });
  }
});

router.get('/:caseId/timeline-row/:id/raw', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT raw FROM collection_timeline WHERE id = $1 AND case_id = $2`,
      [req.params.id, req.params.caseId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Record introuvable' });
    res.json({ raw: r.rows[0].raw });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/record/:index', authenticate, async (req, res) => {
  try {
    const idx = parseInt(req.params.index);
    if (isNaN(idx) || idx < 0) return res.status(400).json({ error: 'Index invalide' });

    const r = await pool.query(
      `SELECT timestamp, artifact_type, artifact_name, description, source, raw
         FROM collection_timeline
        WHERE case_id = $1
        ORDER BY timestamp
        LIMIT 1 OFFSET $2`,
      [req.params.caseId, idx]
    );
    if (r.rows.length > 0) return res.json(r.rows[0]);

    const old = await pool.query(
      `SELECT output_data FROM parser_results
        WHERE case_id = $1 AND parser_name = 'UnifiedTimeline'
        ORDER BY created_at DESC LIMIT 1`,
      [req.params.caseId]
    );
    if (old.rows.length === 0) return res.status(404).json({ error: 'Aucune donnée' });
    const records = old.rows[0].output_data.unified_timeline || [];
    if (idx >= records.length) return res.status(404).json({ error: 'Index invalide' });
    res.json(records[idx]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/* ──────────────────────────────────────────────────────────────────────────
 * v2.23 — Tool-agnostic CSV meta-import, persistent tags, mapping registry.
 * ────────────────────────────────────────────────────────────────────────── */

// List available CSV mappings so the UI can show what tools are supported.
router.get('/:caseId/timeline/mappings', authenticate, async (_req, res) => {
  try {
    const out = loadMappings().map(m => ({
      id: m.id, tool: m.tool, artifact_type: m.artifact_type, artifact_name: m.artifact_name,
      filename_patterns: m.filename_patterns.map(r => r.source),
      folder_patterns: m.folder_patterns.map(r => r.source),
      header_signatures: m.header_signatures,
    }));
    res.json({ mappings: out });
  } catch (e) {
    logger.error('[mappings] list error:', e.message);
    res.status(500).json({ error: 'mapping registry error' });
  }
});

// Server-side grouping aggregator for the Timeline Explorer grid.
// `by` is a comma-separated list of whitelisted columns (max depth 3).
// v2.26 — Threat Engine summary for the Workbench dashboard tile.
router.get('/:caseId/detections/summary', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const sql = `
      WITH hits AS (
        SELECT jsonb_array_elements(detections) AS d
          FROM collection_timeline
         WHERE case_id = $1
           AND detections IS NOT NULL
           AND jsonb_array_length(detections) > 0
      )
      SELECT
        COUNT(*)::int                                                                       AS total,
        COALESCE(jsonb_object_agg(sev, sev_count) FILTER (WHERE sev IS NOT NULL), '{}')     AS by_severity,
        COALESCE(jsonb_object_agg(cat, cat_count) FILTER (WHERE cat IS NOT NULL), '{}')     AS by_category
      FROM (
        SELECT
          d->>'severity' AS sev,
          COUNT(*) OVER (PARTITION BY d->>'severity') AS sev_count,
          d->>'category' AS cat,
          COUNT(*) OVER (PARTITION BY d->>'category') AS cat_count
        FROM hits
      ) x`;
    const topSql = `
      SELECT d->>'id' AS id, d->>'name' AS name, d->>'severity' AS severity,
             COUNT(*)::int AS count
        FROM collection_timeline, jsonb_array_elements(detections) AS d
       WHERE case_id = $1
         AND detections IS NOT NULL
         AND jsonb_array_length(detections) > 0
       GROUP BY d->>'id', d->>'name', d->>'severity'
       ORDER BY count DESC
       LIMIT 10`;
    const [sumRes, topRes] = await Promise.all([
      pool.query(sql, [caseId]),
      pool.query(topSql, [caseId]),
    ]);
    const row = sumRes.rows[0] || {};
    res.json({
      total: row.total || 0,
      by_severity: row.by_severity || {},
      by_category: row.by_category || {},
      top_rules: topRes.rows || [],
    });
  } catch (err) {
    logger.error(`[detections/summary] ${err.message}`);
    res.status(500).json({ error: 'Erreur détections summary' });
  }
});

// Returns a flat list of rolled-up buckets — the client tree-builds it.
router.get('/:caseId/timeline/groups', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const {
      by,
      artifact_types, search, search_op = 'contains',
      start_time, end_time,
      host_name, user_name, result_id, evidence_id, evidence_ids, hunt_id,
      tool, event_id, ext, tag, tags: tagsParam, dedupe,
      host_name_op = 'contains', user_name_op = 'contains', tool_op, ext_op,
    } = req.query;

    const ALLOWED = new Set([
      'tool', 'event_id', 'artifact_type', 'host_name', 'user_name',
      'ext', 'mitre_technique_id', 'source', 'process_name',
      'timestamp_kind', 'sha1', 'src_ip', 'dst_ip',
    ]);
    const groupCols = String(by || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 3);
    if (groupCols.length === 0) {
      return res.status(400).json({ error: 'parameter "by" required (comma list, max 3)' });
    }
    const invalidCol = groupCols.find(c => !ALLOWED.has(c));
    if (invalidCol) {
      return res.status(400).json({ error: `column not groupable: ${invalidCol}` });
    }
    const groupSelect = groupCols.map((c, i) => `${c} AS k${i}`).join(', ');
    const groupBy     = groupCols.join(', ');

    // Build WHERE clause — same shape as GET /timeline, hunt_id included.
    const conditions = ['case_id = $1'];
    const params     = [caseId];
    let pi = 2;

    if (artifact_types) {
      conditions.push(`artifact_type = ANY($${pi++})`);
      params.push(String(artifact_types).split(','));
    }
    if (search || search_op === 'empty' || search_op === 'not_empty') {
      pi = pushSearchFilter(search || '', search_op, pi, conditions, params);
    }
    if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time); }
    if (host_name || host_name_op === 'empty' || host_name_op === 'not_empty')
      pi = pushTextFilter('host_name', host_name || '', host_name_op, pi, conditions, params);
    if (user_name || user_name_op === 'empty' || user_name_op === 'not_empty')
      pi = pushTextFilter('user_name', user_name || '', user_name_op, pi, conditions, params);
    if (result_id)  { conditions.push(`result_id = $${pi++}`);    params.push(result_id); }

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (evidence_id) {
      if (!UUID_RE.test(evidence_id)) return res.status(400).json({ error: 'evidence_id invalide' });
      conditions.push(`evidence_id = $${pi++}`);
      params.push(evidence_id);
    } else if (evidence_ids) {
      const ids = String(evidence_ids).split(',').map(s => s.trim()).filter(Boolean);
      if (ids.some(id => !UUID_RE.test(id))) return res.status(400).json({ error: 'evidence_ids invalides' });
      if (ids.length) { conditions.push(`evidence_id = ANY($${pi++}::uuid[])`); params.push(ids); }
    }

    // Sigma hunt pivot — see resolveHuntPredicate() near GET /timeline above.
    // A grouped view is still a view of the timeline: a hunt-scoped pivot
    // must restrict the counts it aggregates the same way it restricts the
    // flat row list, or the analyst gets case-wide numbers with no sign the
    // scope changed.
    let huntPredicate = null;
    if (hunt_id) {
      const resolvedHunt = await resolveHuntPredicate(caseId, hunt_id);
      if (!resolvedHunt.ok) return res.status(resolvedHunt.status).json({ error: resolvedHunt.error });
      huntPredicate = { where: resolvedHunt.where, params: resolvedHunt.params };
    }

    if (tool_op && (tool || tool_op === 'empty' || tool_op === 'not_empty')) {
      pi = pushTextFilter('tool', tool || '', tool_op, pi, conditions, params);
    } else if (tool) {
      const list = String(tool).split(',').map(s => s.trim()).filter(Boolean);
      if (list.length) { conditions.push(`tool = ANY($${pi++}::text[])`); params.push(list); }
    }
    if (ext_op && (ext || ext_op === 'empty' || ext_op === 'not_empty')) {
      pi = pushTextFilter('ext', ext || '', ext_op, pi, conditions, params);
    } else if (ext) {
      const list = String(ext).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      if (list.length) { conditions.push(`lower(ext) = ANY($${pi++}::text[])`); params.push(list); }
    }
    if (event_id) {
      const list = String(event_id).split(',').map(s => parseInt(s, 10)).filter(Number.isFinite);
      if (list.length) { conditions.push(`event_id = ANY($${pi++}::int[])`); params.push(list); }
    }
    const rawTags = tagsParam || tag;
    if (rawTags) {
      const list = String(rawTags).split(',').map(s => s.trim()).filter(t => t && /^[\w:.\-]{1,64}$/.test(t));
      if (list.length) { conditions.push(`tags && $${pi++}::text[]`); params.push(list); }
    }
    if (huntPredicate) {
      conditions.push(`(${shiftHuntPredicate(huntPredicate.where, pi)})`);
      params.push(...huntPredicate.params);
      pi += huntPredicate.params.length;
    }

    const where = conditions.join(' AND ');
    const fromExpr = (dedupe === 'collapse' || dedupe === '1' || dedupe === 'true')
      ? `(SELECT DISTINCT ON (COALESCE(dedupe_hash, id::text))
              id, timestamp, tool, event_id, artifact_type, host_name, user_name,
              ext, mitre_technique_id, source, process_name
           FROM collection_timeline WHERE ${where}
           ORDER BY COALESCE(dedupe_hash, id::text)) ct`
      : `collection_timeline WHERE ${where}`;
    const fromClause = (dedupe === 'collapse' || dedupe === '1' || dedupe === 'true')
      ? `FROM ${fromExpr}`
      : `FROM ${fromExpr}`;

    const sql = `
      SELECT ${groupSelect},
             COUNT(*)::bigint     AS cnt,
             MIN(timestamp)        AS first_ts,
             MAX(timestamp)        AS last_ts,
             (ARRAY_AGG(id ORDER BY timestamp))[1:3] AS sample_ids
      ${fromClause}
      GROUP BY ${groupBy}
      ORDER BY cnt DESC
      LIMIT 10000
    `;
    const t0 = Date.now();
    const r = await pool.query(sql, params);
    const elapsed = Date.now() - t0;

    const groups = r.rows.map(row => {
      const key = groupCols.map((_, i) => row[`k${i}`]);
      return {
        key,
        count: Number(row.cnt),
        first_ts: row.first_ts,
        last_ts: row.last_ts,
        sample_ids: row.sample_ids || [],
      };
    });
    // A hunt-scoped grouping that comes back with nothing to group must say
    // so explicitly — same contract as GET /timeline's `hunt_empty`, so a
    // client watching for it doesn't have to special-case which timeline
    // view it called. See resolveHuntPredicate() near GET /timeline above.
    if (hunt_id && groups.length === 0) {
      return res.json({
        by: groupCols, total_groups: 0, elapsed_ms: elapsed, groups: [],
        hunt_empty: true,
        message: HUNT_EMPTY_MESSAGE,
      });
    }
    res.json({ by: groupCols, total_groups: groups.length, elapsed_ms: elapsed, groups });
  } catch (e) {
    logger.error('[timeline/groups] error:', e.message);
    res.status(500).json({ error: 'group aggregation failed' });
  }
});

// Returns ±N chronological neighbors around an anchor event (same host by default),
// ignoring any active timeline filters.
router.get('/:caseId/timeline/context', authenticate, async (req, res) => {
  try {
    const anchorId = parseInt(req.query.anchor_id, 10);
    if (!Number.isInteger(anchorId)) return res.status(400).json({ error: 'anchor_id (entier) requis' });
    const result = await fetchContext(pool, req.params.caseId, anchorId, {
      n: req.query.n, allHosts: String(req.query.all_hosts) === 'true',
    });
    res.json(result);
  } catch (err) {
    if (err instanceof AnchorNotFound) return res.status(404).json({ error: 'Événement ancre introuvable' });
    logger.error('[timeline/context]', err.message);
    res.status(500).json({ error: 'Erreur vue contexte' });
  }
});

// Two-sided timeline diff: added/removed/unchanged events between two
// {evidence_id?, host_name?} sides of the same case.
router.get('/:caseId/timeline/diff', authenticate, async (req, res) => {
  try {
    const sideA = { evidenceId: req.query.a_evidence || null, hostName: req.query.a_host ?? null };
    const sideB = { evidenceId: req.query.b_evidence || null, hostName: req.query.b_host ?? null };
    const has = (s) => Boolean(s.evidenceId) || (s.hostName != null && s.hostName !== '');
    if (!has(sideA) || !has(sideB)) return res.status(400).json({ error: 'Chaque côté requiert un evidence_id ou un host' });
    if (sideA.evidenceId === sideB.evidenceId && sideA.hostName === sideB.hostName)
      return res.status(400).json({ error: 'Les deux côtés sont identiques' });
    const result = await diffTimelines(pool, req.params.caseId, sideA, sideB, { limit: req.query.limit });
    res.json(result);
  } catch (err) {
    logger.error('[timeline/diff]', err.message);
    res.status(500).json({ error: 'Erreur diff timeline' });
  }
});

// Per-row tag PATCH — replaces the `tags` array for a single timeline row.
router.patch('/:caseId/timeline/:id/tags', authenticate, async (req, res) => {
  try {
    const { caseId, id } = req.params;
    const tags = Array.isArray(req.body?.tags)
      ? req.body.tags.map(t => String(t).trim()).filter(Boolean).slice(0, 32)
      : [];
    const rowId = parseInt(id, 10);
    if (!Number.isFinite(rowId)) return res.status(400).json({ error: 'id invalide' });
    const r = await pool.query(
      `UPDATE collection_timeline SET tags = $1::text[]
        WHERE id = $2 AND case_id = $3
      RETURNING id, tags`,
      [tags, rowId, caseId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'row introuvable' });
    res.json({ id: r.rows[0].id, tags: r.rows[0].tags });
  } catch (e) {
    logger.error('[tags] patch error:', e.message);
    res.status(500).json({ error: 'tag update error' });
  }
});

// Bulk tag update — accepts { updates: [{id, tags}, ...] } for many rows.
router.post('/:caseId/timeline/tags/bulk', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const updates = Array.isArray(req.body?.updates) ? req.body.updates : [];
    if (updates.length === 0) return res.json({ updated: 0 });
    if (updates.length > 2000) return res.status(400).json({ error: 'trop de rows (max 2000)' });
    const ids = [], tagsArr = [];
    for (const u of updates) {
      const rowId = parseInt(u?.id, 10);
      if (!Number.isFinite(rowId)) continue;
      ids.push(rowId);
      tagsArr.push((u.tags || []).map(t => String(t).trim()).filter(Boolean).slice(0, 32));
    }
    if (ids.length === 0) return res.json({ updated: 0 });
    const map = {};
    for (let i = 0; i < ids.length; i++) map[String(ids[i])] = tagsArr[i];
    const r = await pool.query(
      `UPDATE collection_timeline ct
          SET tags = ARRAY(SELECT jsonb_array_elements_text(v.tags_json))::text[]
         FROM jsonb_each($2::jsonb) AS v(id, tags_json)
        WHERE ct.id = v.id::bigint AND ct.case_id = $1`,
      [caseId, JSON.stringify(map)]
    );
    res.json({ updated: r.rowCount });
  } catch (e) {
    logger.error('[tags] bulk error:', e.message);
    res.status(500).json({ error: 'bulk tag error', detail: e.message });
  }
});

// ── Tagger (Timesketch-style auto-tagging) ──────────────────────────────────
// The keyword rules in config/timeline_keywords.yaml normally run at ingest.
// These endpoints expose the rules + current tag distribution, and let the
// analyst re-run the tagger over already-ingested rows (rules may have been
// edited since the collection was parsed). Tag matching reuses matchTags() so
// the behaviour is identical to ingest-time tagging.

router.get('/:caseId/timeline/tagger', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id } = req.query;
    const rules = require('../services/timelineKeywords').load();
    const ruleList = rules.map(r => ({ name: r.name, pattern: r.pattern, fields: r.fields, tags: r.tags }));

    const params = [caseId];
    let ev = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      ev = 'AND evidence_id = $2';
      params.push(evidence_id);
    }
    const { rows } = await pool.query(
      `SELECT tag, COUNT(*)::int AS cnt
         FROM collection_timeline ct, LATERAL unnest(ct.tags) AS tag
        WHERE case_id = $1 ${ev}
        GROUP BY tag ORDER BY cnt DESC, tag`, params);
    res.json({ rules: ruleList, tag_counts: rows });
  } catch (e) {
    logger.error('[tagger] error:', e.message);
    res.status(500).json({ error: 'Erreur récupération du tagger' });
  }
});

// Re-run the keyword tagger over existing rows (optionally one evidence),
// merging new tags with the ones already present. Bounded so a huge
// collection can't starve the backend: max rows scanned per run.
router.post('/:caseId/timeline/tagger/run', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id } = req.body || {};
    const MAX_ROWS = 50000;
    const BATCH = 2000;
    const params = [caseId];
    let ev = '';
    if (evidence_id) {
      if (!UUID_RE_G.test(evidence_id)) return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      ev = 'AND evidence_id = $2';
      params.push(evidence_id);
    }

    const matchTags = require('../services/timelineKeywords').matchTags;
    let scanned = 0, tagged = 0, updated = 0, offset = 0;
    while (scanned < MAX_ROWS) {
      const batchRes = await pool.query(
        `SELECT id, artifact_type, description, source, raw, tags
           FROM collection_timeline
          WHERE case_id = $1 ${ev}
          ORDER BY id
          LIMIT ${BATCH} OFFSET ${offset}`, params);
      const batch = batchRes.rows;
      if (batch.length === 0) break;
      offset += batch.length;
      scanned += batch.length;

      const upserts = [];
      for (const row of batch) {
        const record = { ...(row.raw || {}), artifact_type: row.artifact_type, description: row.description, source: row.source };
        let newTags = [];
        try { newTags = matchTags(record, row.description || ''); } catch (_e) {}
        if (newTags.length === 0) continue;
        const merged = Array.from(new Set([...(row.tags || []), ...newTags])).slice(0, 32);
        const added = merged.filter(t => !(row.tags || []).includes(t));
        if (added.length === 0) continue;
        upserts.push({ id: row.id, tags: merged });
        tagged += added.length;
      }
      if (upserts.length > 0) {
        // Single jsonb map id -> tags[]; avoids the brittle
        // UNNEST(bigint[], jsonb[]) array-cast that fails on some pg drivers.
        const map = {};
        for (const u of upserts) map[String(u.id)] = u.tags;
        const up = await pool.query(
          `UPDATE collection_timeline ct
              SET tags = ARRAY(SELECT jsonb_array_elements_text(v.tags_json))::text[]
             FROM jsonb_each($2::jsonb) AS v(id, tags_json)
            WHERE ct.id = v.id::bigint AND ct.case_id = $1`,
          [caseId, JSON.stringify(map)]);
        updated += up.rowCount;
      }
    }
    res.json({ scanned, rows_tagged: updated, tags_added: tagged });
  } catch (e) {
    logger.error('[tagger/run] error:', e.message);
    res.status(500).json({ error: 'Erreur exécution du tagger', detail: e.message });
  }
});

// CSV meta-import — accepts 1..N CSV files, detects tool via filename/folder/
// headers, applies the matched YAML mapping, runs the shared forensic field
// extractor + keyword enrichment, and bulk-inserts into collection_timeline.
const csvUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => {
      try { fs.mkdirSync(UPLOAD_COLLECTION_DIR, { recursive: true }); cb(null, UPLOAD_COLLECTION_DIR); }
      catch (err) { cb(err); }
    },
    filename: (_req, file, cb) => cb(null, `csv-${Date.now()}-${file.originalname.replace(/[^A-Za-z0-9._-]/g, '_')}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
});

router.post('/:caseId/import-csv', authenticate, csvUpload.array('files', 20), async (req, res) => {
  const { caseId } = req.params;
  const files = req.files || [];
  if (files.length === 0) return res.status(400).json({ error: 'aucun fichier CSV' });

  try {
    const caseCheck = await pool.query('SELECT id FROM cases WHERE id = $1', [caseId]);
    if (caseCheck.rows.length === 0) {
      for (const f of files) { try { fs.unlinkSync(f.path); } catch (_e) {} }
      return res.status(404).json({ error: 'Cas introuvable' });
    }

    // Create a parser_results row to group this import.
    const prRes = await pool.query(
      `INSERT INTO parser_results (case_id, parser_name, output_data, record_count, created_by)
       VALUES ($1, 'CsvMetaImport', '{}'::jsonb, 0, $2) RETURNING id`,
      [caseId, req.user.id]
    );
    const resultId = prRes.rows[0].id;

    const perFile = [];
    let grandTotal = 0;

    for (const f of files) {
      const filename = f.originalname || path.basename(f.path);
      const folderPath = path.dirname(filename);

      // Read header row to detect mapping.
      let headers = [];
      try {
        const firstChunk = fs.readFileSync(f.path, { encoding: 'utf-8', flag: 'r' }).slice(0, 8192);
        const firstLine = firstChunk.split(/\r?\n/)[0].replace(/^\uFEFF/, '');
        headers = parse(firstLine + '\n', { columns: false, skip_empty_lines: true, relax_column_count: true })[0] || [];
      } catch (e) {
        perFile.push({ file: filename, status: 'error', error: 'header read failed: ' + e.message });
        try { fs.unlinkSync(f.path); } catch (_e) {}
        continue;
      }

      const detected = detectMapping({ filename, folderPath, headers });
      if (!detected) {
        perFile.push({ file: filename, status: 'skipped', error: 'no mapping matched' });
        try { fs.unlinkSync(f.path); } catch (_e) {}
        continue;
      }
      const mapping = detected.mapping;

      // Stream-parse + bulk insert (shared with the automatic collection scan).
      const r = await importCsvFile(pool, {
        caseId, resultId, evidenceId: null,
        filePath: f.path, filename, mapping,
      });
      const inserted = r.inserted, skipped = r.skipped;

      grandTotal += inserted;
      perFile.push({ file: filename, status: r.status, tool: mapping.tool, detected_via: detected.via, inserted, skipped });
      try { fs.unlinkSync(f.path); } catch (_e) {}
    }

    await pool.query(
      `UPDATE parser_results SET record_count = $1, output_data = $2, updated_at = NOW() WHERE id = $3`,
      [grandTotal, JSON.stringify({ files: perFile }), resultId]
    );

    await auditLog(req.user.id, 'csv_meta_import', 'collection', resultId, { files: perFile.length, inserted: grandTotal }, req.ip);

    // Invalidate cached aggs so the UI sees new rows immediately.
    try {
      const redis = getRedis();
      if (redis) {
        const keys = await redis.keys(`timeline:aggs:${caseId}:*`);
        if (keys.length) await redis.del(...keys);
      }
    } catch (_e) {}

    res.json({ result_id: resultId, inserted: grandTotal, files: perFile });
  } catch (err) {
    logger.error('[csv-import] error:', err);
    for (const f of files) { try { fs.unlinkSync(f.path); } catch (_e) {} }
    res.status(500).json({ error: 'Erreur import CSV: ' + err.message });
  }
});

router.post('/:caseId/hayabusa', authenticate, async (req, res) => {
  const { caseId } = req.params;
  // Per-case in-flight guard: the parse pipeline auto-triggers Hayabusa
  // (startRunAll) AND the frontend POSTs after parse:done. Without this lock the
  // two would race and initHayabusaRecord (which DELETEs existing hayabusa rows
  // first) would wipe the other's partial stream-insert. The lock is released in
  // the finally below — deliberately NOT on res 'finish'/'close', because a
  // client disconnect (499) must not release it while the binary is still
  // stream-inserting server-side.
  if (ACTIVE_HAYABUSA_LOCKS.has(caseId)) {
    return res.status(409).json({
      error: 'Une analyse Hayabusa est déjà en cours pour ce cas',
      details: 'Attendez la fin de l\'analyse en cours avant de la relancer.',
    });
  }
  ACTIVE_HAYABUSA_LOCKS.add(caseId);
  try {
    const HAYABUSA_BIN = process.env.HAYABUSA_BIN || '/app/hayabusa/hayabusa';

    // Resolve collection directory — try MagnetRESPONSE_Import first, then fall back to
    // individual EVTX evidence files so cases imported without a RESPONSE package still work.
    let collectionDir = null;
    let hayEvidenceId = null;

    const importRecord = await pool.query(
      `SELECT input_file FROM parser_results
       WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'
       ORDER BY created_at DESC LIMIT 1`,
      [caseId]
    );
    if (importRecord.rows.length > 0 && importRecord.rows[0].input_file &&
        fs.existsSync(importRecord.rows[0].input_file)) {
      collectionDir = importRecord.rows[0].input_file;
      try {
        const evRow = await pool.query(
          `SELECT id FROM evidence WHERE case_id = $1 AND file_path = $2 LIMIT 1`,
          [caseId, collectionDir]
        );
        if (evRow.rows.length > 0) hayEvidenceId = evRow.rows[0].id;
      } catch (_e) {}
    }

    // Fallback: look for .evtx files registered directly in the evidence table
    let evtxFiles = collectionDir
      ? findFiles(collectionDir, ['**/*.evtx', '**/winevt/Logs/*.evtx'])
      : [];

    if (evtxFiles.length === 0) {
      try {
        const evRows = await pool.query(
          `SELECT id, file_path FROM evidence
           WHERE case_id = $1 AND (file_path ILIKE '%.evtx' OR file_name ILIKE '%.evtx')
           ORDER BY created_at DESC`,
          [caseId]
        );
        const existing = evRows.rows.filter(r => r.file_path && fs.existsSync(r.file_path));
        if (existing.length > 0) {
          evtxFiles = existing.map(r => r.file_path);
          hayEvidenceId = existing[0].id;
          collectionDir = path.dirname(existing[0].file_path);
        }
      } catch (_e) {}
    }

    // Evidence-scoped run (body evidence_id — the per-evidence background
    // auto-run sends it): restrict the scan to that evidence's own EVTX files
    // instead of the whole case's collection. The evidence's file_path is the
    // scan root: a collection dir → recursive search; a single .evtx → direct
    // file. When the evidence has no usable file, the case-wide discovery above
    // stays as the fallback.
    const scopeEvidenceId = req.body && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(req.body.evidence_id || ''))
      ? req.body.evidence_id : null;
    if (scopeEvidenceId) {
      hayEvidenceId = scopeEvidenceId;
      try {
        const evRow = await pool.query(
          `SELECT file_path FROM evidence WHERE id = $1 AND case_id = $2`,
          [scopeEvidenceId, caseId]);
        const fp = evRow.rows[0] && evRow.rows[0].file_path;
        if (fp && fs.existsSync(fp)) {
          if (fs.statSync(fp).isDirectory()) {
            const scoped = findFiles(fp, ['**/*.evtx', '**/winevt/Logs/*.evtx']);
            if (scoped.length > 0) { evtxFiles = scoped; collectionDir = fp; }
          } else if (/\.evtx$/i.test(fp)) {
            evtxFiles = [fp]; collectionDir = path.dirname(fp);
          }
        }
      } catch (_e) {}
    }

    // Last-resort evidence linkage (same rule as /parse): bind Hayabusa
    // detections to the case's most-populated evidence so they never land with
    // NULL evidence_id (invisible in the per-evidence menu).
    if (!hayEvidenceId) {
      try {
        const topEv = await pool.query(
          `SELECT evidence_id AS id
             FROM collection_timeline
            WHERE case_id = $1 AND evidence_id IS NOT NULL
            GROUP BY evidence_id
            ORDER BY COUNT(*) DESC
            LIMIT 1`, [caseId]);
        if (topEv.rows.length > 0) hayEvidenceId = topEv.rows[0].id;
      } catch (_e) {}
    }

    if (evtxFiles.length === 0) {
      return res.status(400).json({
        error: 'Aucun fichier .evtx trouvé pour ce cas. Importez une collecte Magnet RESPONSE ou des fichiers .evtx individuels.',
      });
    }

    function evtxCommonAncestor(files) {
      if (files.length === 1) return path.dirname(files[0]);
      const parts = files.map(f => path.dirname(f).split(path.sep));
      const minLen = Math.min(...parts.map(p => p.length));
      let i = 0;
      while (i < minLen && parts.every(p => p[i] === parts[0][i])) i++;
      const common = parts[0].slice(0, i).join(path.sep) || path.sep;

      return (common === path.sep || common.split(path.sep).filter(Boolean).length < 3)
        ? path.dirname(files[0])
        : common;
    }
    const evtxParentDir = evtxCommonAncestor(evtxFiles);
    const outputFile = path.join(TEMP_DIR, `hayabusa-${caseId}-${uuidv4()}.jsonl`);

    // Atomic helper: lock → wipe old Hayabusa data → insert fresh result record.
    // FOR UPDATE blocks a concurrent Hayabusa run on the same case until we commit,
    // ensuring exactly one result record exists at any time.
    async function initHayabusaRecord(outputDataJson, recordCount = 0) {
      const dbClient = await pool.connect();
      try {
        await dbClient.query('BEGIN');
        const oldRows = await dbClient.query(
          `SELECT id FROM parser_results WHERE case_id = $1 AND parser_name = 'Hayabusa'
             AND ($2::uuid IS NULL OR evidence_id = $2)
           FOR UPDATE`,
          [caseId, scopeEvidenceId]
        );
        const oldIds = oldRows.rows.map(r => r.id);
        await dbClient.query(
          `DELETE FROM collection_timeline WHERE case_id = $1 AND artifact_type = 'hayabusa'
             AND ($2::uuid IS NULL OR evidence_id = $2)`,
          [caseId, scopeEvidenceId]
        );
        if (oldIds.length > 0) {
          await dbClient.query(`DELETE FROM parser_results WHERE id = ANY($1::uuid[])`, [oldIds]);
        }
        const newRow = await dbClient.query(
          `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
           VALUES ($1, $2, 'Hayabusa', '2.x', $3, $4::jsonb, $5, $6) RETURNING id`,
          [caseId, scopeEvidenceId, evtxParentDir, outputDataJson, recordCount, req.user.id]
        );
        await dbClient.query('COMMIT');
        return { newId: newRow.rows[0].id, oldIds };
      } catch (err) {
        await dbClient.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        dbClient.release();
      }
    }

    let hayabusaRecords = [];
    let engineUsed      = 'sigma_fallback';
    let rulesCount      = 0;
    let hayStderrSnip   = '';

    const HAYABUSA_RULES_DIR = process.env.HAYABUSA_RULES_DIR || path.join(path.dirname(HAYABUSA_BIN), 'rules');
    const rulesPresent = fs.existsSync(HAYABUSA_RULES_DIR);
    if (rulesPresent) {
      try {
        const countOut = require('child_process').spawnSync(
          'find', [HAYABUSA_RULES_DIR, '-name', '*.yml'], { encoding: 'utf8', timeout: 10000 }
        );
        rulesCount = (countOut.stdout || '').split('\n').filter(Boolean).length;
        logger.info(`[hayabusa] rules dir: ${HAYABUSA_RULES_DIR} — ${rulesCount} rules`);
      } catch (_e) {}
    } else {
      logger.warn(`[hayabusa] rules dir not found: ${HAYABUSA_RULES_DIR}`);
    }

    // Run Hayabusa binary if available
    let binaryFailed = false;
    try {
      if (!fs.existsSync(HAYABUSA_BIN)) throw new Error(`Hayabusa binary not found: ${HAYABUSA_BIN}`);

      // --min-level informational : inclut tous les niveaux (informational, low, medium, high, critical).
      // --enable-all-rules : active toutes les règles quelle que soit la source EVTX.
      // --enable-noisy-rules : active les règles rclone/cloud-exfil désactivées par défaut.
      // --enable-deprecated-rules + --enable-unsupported-rules : couverture maximale.
      // --scan-all-evtx-files : analyse tous les fichiers EVTX sans filtrage par règle.
      // Sortie JSONL uniquement (-L) ; pas de CSV/HTML.
      const hayArgs = [
        HAYABUSA_BIN, 'json-timeline',
        '-d', evtxParentDir,
        '-o', outputFile,
        '--no-wizard', '-q',
        '--min-level', 'informational',
        '--enable-all-rules',
        '--enable-noisy-rules',
        '--enable-deprecated-rules',
        '--enable-unsupported-rules',
        '--scan-all-evtx-files',
        '--threads', '4',
        '-b',
        '-L',
        '-p', 'all-field-info',
      ];
      if (rulesPresent) hayArgs.push('-r', HAYABUSA_RULES_DIR);

      // Hayabusa writes ./logs/errorlog-<ts>.log relative to its CWD at the end of
      // every run. The backend's own CWD is /app (root-owned), so under the
      // unprivileged `node` user `File::create(...).unwrap()` in
      // src/detections/message.rs panics (PermissionDenied) AFTER the JSONL output
      // is fully written — the non-zero exit then made the backend discard a
      // complete run and fall back to the Sigma regex engine. Point its CWD at the
      // writable temp dir so ./logs lands somewhere the node user owns.
      let exitNonZero = false;
      try {
        await spawnTool(hayArgs, { timeout: 3600000, cwd: TEMP_DIR });
      } catch (e) {
        // Capture stderr snippet for diagnostic even on failure
        hayStderrSnip = (e.stderr || e.message || '').substring(0, 400);
        // A trailing crash (error-log panic, teardown OOM, …) can still leave a
        // complete, valid output file. Process it instead of discarding detections.
        if (fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0) {
          exitNonZero = true;
          logger.warn('[hayabusa] exited non-zero but produced output — processing results:', hayStderrSnip.substring(0, 150));
        } else {
          throw e;
        }
      }

      // Guard: skip reading if output file is suspiciously large (> 500 MB → OOM risk)

      if (fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0) {
        const outputSizeMb = (fs.statSync(outputFile).size / (1024 * 1024)).toFixed(1);
        logger.info(`[hayabusa] output file: ${outputSizeMb} MB — stream-inserting to DB`);

        // Atomically clear previous Hayabusa data and create the new result placeholder.
        const { newId: streamResultId, oldIds: streamOldIds } = await initHayabusaRecord(
          JSON.stringify({ evtx_dir: evtxParentDir, evtx_files_count: evtxFiles.length })
        );
        // Delete stale ES docs from previous run before inserting new ones.
        for (const oid of streamOldIds) {
          esService.deleteByResultId(caseId, oid).catch(e =>
            logger.warn('[ES] hayabusa stale cleanup warn:', e.message?.substring(0, 80))
          );
        }
        const streamStats    = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
        let   streamTotal    = 0;

        // Insert one batch using UNNEST arrays — same pattern as generic insertBatch (line 621).
        async function insertHayBatch(items) {
          if (!items || items.length === 0) return;
          const caseIds = [], resultIds = [], evidenceIds = [], timestamps = [];
          const artTypes = [], artNames = [], descs = [], sources = [], raws = [];
          const hostNames = [], userNames = [], processNames = [], mitreIds = [], mitreTactics = [];
          const tools = [], tsKinds = [], eventIds = [], dedupeHashes = [], tagsArr = [];
          const srcIps = [], dstIps = [], exts = [], paths = [], detailsArr = [];

          for (const p of items) {
            const lvl       = (p.Level || p.level || 'informational').toLowerCase();
            const techRaw   = p.MitreTechniques || p.mitre_techniques || '';
            const tacticRaw = p.MitreTactics    || p.mitre_tactics    || '';
            const mId       = /^T\d{4}(\.\d{3})?$/i.test(techRaw.split(',')[0].trim())
              ? (techRaw.split(',')[0].trim() || null)
              : null;
            const mTactic   = tacticRaw.split(',')[0].trim().toLowerCase() || null;
            const evIdRaw  = p.EventID || p.event_id || '';
            const evId     = /^\d+$/.test(String(evIdRaw).trim()) ? parseInt(evIdRaw, 10) : null;
            const ruleTitle = p.RuleTitle || p.rule_title || '';
            const afiEarly = p.AllFieldInfo || p.all_field_info;
            const desc     = buildHayabusaDescription({ level: lvl, ruleTitle, allFieldInfo: afiEarly });
            const src      = p.Channel || p.channel || '';
            // RecordID (EVTX record number) is the true unique key per event.
            // Use Channel+RecordID when available so identical-looking events at the
            // same millisecond (e.g. many 7045 service installs) are kept distinct.
            const recId  = String(p.RecordID || p['Record ID'] || p.recordId || '');
            const dedupe = recId
              ? crypto.createHash('md5')
                  .update([src, recId].join('|'))
                  .digest('hex').slice(0, 16)
              : crypto.createHash('md5')
                  .update([(p.Timestamp || ''), src, ruleTitle.slice(0, 200), evId == null ? '' : String(evId)].join('|'))
                  .digest('hex').slice(0, 16);
            let tags = [];
            try { tags = matchKeywordTags({ level: lvl, description: desc }, desc); } catch (_e) {}
            if (lvl === 'critical') tags = Array.from(new Set([...tags, 'critical']));
            else if (lvl === 'high') tags = Array.from(new Set([...tags, 'high']));
            const ips  = desc.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
            const extM = /\.([A-Za-z0-9]{1,10})(?=[\s"'\\\/)]|$)/.exec(desc);
            const patM = /([A-Z]:\\[^\s"']+|\/[^\s"']+)/.exec(desc);

            // Flatten AllFieldInfo into the stored raw: Hayabusa is invoked with
            // `-p all-field-info`, which nests the real event fields (LogonType,
            // IpAddress, TicketEncryptionType, CommandLine, Image, …) under
            // AllFieldInfo instead of as top-level columns. Detection rules query
            // raw->>'FieldName', so without this flattening every such condition is
            // NULL and the rule can never fire on Hayabusa rows. Top-level Hayabusa
            // keys (Timestamp, Computer, Channel, EventID, Level, RuleTitle, …)
            // win on collision — they are the values Hayabusa already normalized.
            const afi = p.AllFieldInfo || p.all_field_info;
            let hayDetails = null;
            if (afi && typeof afi === 'object') {
              hayDetails = Object.entries(afi)
                .filter(([, v]) => v !== null && v !== '' && v !== undefined)
                .map(([k, v]) => `${k}: ${String(v).slice(0, 20000)}`)
                .join(' | ')
                .slice(0, 200000) || null;
            } else if (typeof afi === 'string' && afi.trim()) {
              hayDetails = afi.slice(0, 200000);
            }

            const userName    = p.UserName || p.SubjectUserName || p.TargetUserName || p.user_name || null;
            const processName = p.ProcessName || p.NewProcessName || p.Image || p.process_name || null;

            if (streamStats[lvl] !== undefined) streamStats[lvl]++;
            caseIds.push(caseId);            resultIds.push(streamResultId);
            evidenceIds.push(hayEvidenceId); timestamps.push(p.Timestamp || p.timestamp || null);
            artTypes.push('hayabusa');        artNames.push(p.RuleTitle || p.rule_title || 'Hayabusa');
            descs.push(desc);                sources.push(src);
            raws.push(JSON.stringify(
              (afi && typeof afi === 'object' && !Array.isArray(afi)) ? { ...p, ...afi } : p
            ));
            hostNames.push(p.Computer || p.computer || null);
            userNames.push(userName);        processNames.push(processName);
            mitreIds.push(mId);              mitreTactics.push(mTactic);
            tools.push('Hayabusa');           tsKinds.push('Timestamp');
            eventIds.push(evId);             dedupeHashes.push(dedupe);
            tagsArr.push(JSON.stringify(tags));
            srcIps.push(ips[0] || null);     dstIps.push(ips[1] || null);
            exts.push(extM ? ('.' + extM[1].toLowerCase()).slice(0, 16) : null);
            paths.push(patM ? patM[1].slice(0, 500) : null);
            detailsArr.push(hayDetails);
          }

          await pool.query(
            `INSERT INTO collection_timeline
               (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name,
                description, source, raw, host_name, user_name, process_name,
                mitre_technique_id, mitre_tactic,
                tool, timestamp_kind, event_id, dedupe_hash, tags, src_ip, dst_ip, ext, path, details)
             SELECT u.ci, u.ri, u.ei, u.ts, u.at, u.an, u.de, u.sr, u.rw, u.hn, u.un, u.pn,
                    u.mi, u.mt, u.tl, u.tk, u.eid, u.dh,
                    COALESCE(ARRAY(SELECT jsonb_array_elements_text(u.tg)), '{}')::text[],
                    u.si, u.di, u.ex, u.pa, u.dt
             FROM UNNEST(
               $1::uuid[], $2::uuid[], $3::uuid[], $4::timestamptz[], $5::text[], $6::text[],
               $7::text[], $8::text[], $9::jsonb[], $10::text[], $11::text[], $12::text[],
               $13::text[], $14::text[],
               $15::text[], $16::text[], $17::int[], $18::text[], $19::jsonb[],
               $20::inet[], $21::inet[], $22::text[], $23::text[], $24::text[]
             ) AS u(ci, ri, ei, ts, at, an, de, sr, rw, hn, un, pn, mi, mt, tl, tk, eid, dh, tg, si, di, ex, pa, dt)
             ON CONFLICT (case_id, dedupe_hash) WHERE dedupe_hash IS NOT NULL DO NOTHING`,
            [caseIds, resultIds, evidenceIds, timestamps, artTypes, artNames,
             descs, sources, raws, hostNames, userNames, processNames,
             mitreIds, mitreTactics,
             tools, tsKinds, eventIds, dedupeHashes, tagsArr,
             srcIps, dstIps, exts, paths, detailsArr]
          );
          streamTotal += items.length;
          if (streamTotal % 10000 === 0) logger.info(`[hayabusa] streamed ${streamTotal} records…`);
          invalidateDetectionCache(caseId).catch(() => {});
        }

        // Pause/resume readline — 2000-item batches, yield every 2000 lines regardless
        // of JSON validity to prevent event loop block on files with few/no detections.
        let batch = []; let pendingInsert = null; let lineCount = 0;
        await new Promise((resolve, reject) => {
          const rl = readline.createInterface({
            input: fs.createReadStream(outputFile, { encoding: 'utf-8' }),
            crlfDelay: Infinity,
          });
          rl.on('line', (line) => {
            if (!line.trim()) return;
            lineCount++;
            let p; try { p = JSON.parse(line); } catch (_e) {
              // Yield every 2000 lines even when no valid JSON — prevents 4+ min event loop block
              if (lineCount % 2000 === 0) {
                rl.pause();
                pendingInsert = new Promise(r => setImmediate(r)).then(() => rl.resume()).catch(reject);
              }
              return;
            }
            batch.push(p);
            if (batch.length >= 2000) {
              rl.pause();
              const cur = batch; batch = [];
              pendingInsert = new Promise(r => setImmediate(r))
                .then(() => insertHayBatch(cur))
                .then(() => rl.resume())
                .catch(reject);
            }
          });
          rl.on('close', async () => {
            try {
              if (pendingInsert) await pendingInsert;
              if (batch.length > 0) {
                await new Promise(r => setImmediate(r));
                await insertHayBatch(batch);
              }
              resolve();
            } catch (e) { reject(e); }
          });
          rl.on('error', reject);
        });
        try { fs.unlinkSync(outputFile); } catch (_e) {}

        const finalDiag = {
          engine_used: 'hayabusa_binary', rules_count: rulesCount, rules_present: rulesPresent,
          evtx_files: evtxFiles.length, binary_path: HAYABUSA_BIN,
          truncated: false, exit_nonzero: exitNonZero, stderr_snippet: hayStderrSnip || null,
        };
        await pool.query(
          `UPDATE parser_results SET record_count = $1, output_data = $2::jsonb WHERE id = $3`,
          [streamTotal, JSON.stringify({
            evtx_dir: evtxParentDir, evtx_files_count: evtxFiles.length,
            stats: streamStats, diagnostic: finalDiag,
          }), streamResultId]
        );
        logger.info(`[hayabusa] stream-insert complete — ${streamTotal} detections (${rulesCount} rules)`);
        await auditLog(req.user.id, 'run_hayabusa', 'collection', streamResultId,
          { evtx_count: evtxFiles.length, detections: streamTotal }, req.ip);
        return res.json({
          id: streamResultId, total_detections: streamTotal,
          stats: streamStats, evtx_files_processed: evtxFiles.length, diagnostic: finalDiag,
        });

      } else {
        engineUsed = 'hayabusa_binary';
        logger.warn(`[hayabusa] binary ran with 0 detections — rules: ${rulesCount}, dir: ${rulesPresent ? 'present' : 'MISSING'}`);
      }
      try { if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile); } catch (_e) {}
    } catch (execErr) {
      binaryFailed = true;
      hayStderrSnip = hayStderrSnip || (execErr.message || '').substring(0, 400);
      logger.warn('[hayabusa] binary failed — falling back to Sigma rule engine:', execErr.message?.substring(0, 150));
    }

    // Sigma fallback — runs when binary failed OR 0 detections
    if (binaryFailed || hayabusaRecords.length === 0) {

      let evtxRecords = [];
      try {
        const evtxResult = await pool.query(
          `SELECT timestamp, description, source, raw, host_name
           FROM collection_timeline
           WHERE case_id = $1 AND artifact_type = 'evtx'
             AND ($2::uuid IS NULL OR evidence_id = $2)
           ORDER BY timestamp
           LIMIT 5000`,
          [caseId, scopeEvidenceId]
        );
        evtxRecords = evtxResult.rows;
      } catch (e) {}

      const SIGMA_RULES = [
        // ── Original rules ──
        { title: 'Suspicious PowerShell Download Cradle',    level: 'high',     match: /invoke-webrequest|downloadstring|invoke-expression|iex\s*\(/i,                           mitre: 'T1059.001', tactic: 'Execution' },
        { title: 'CobaltStrike Beacon Detection',            level: 'critical', match: /cobaltstrike|cobalt\s*strike|beacon/i,                                                    mitre: 'T1055',     tactic: 'Defense Evasion' },
        { title: 'Privilege Escalation via Token Manipulation', level: 'critical', match: /sedebugprivilege|seimpersonateprivilege/i,                                              mitre: 'T1134',     tactic: 'Privilege Escalation' },
        { title: 'DNS Tunneling Detected',                   level: 'high',     match: /malware-c2|\.onion|high\s*entropy|dns.*tunnel/i,                                          mitre: 'T1071.004', tactic: 'Command and Control' },
        { title: 'Suspicious Service Installation',          level: 'high',     match: /service was installed|new service|7045/i,                                                 mitre: 'T1543.003', tactic: 'Persistence' },
        { title: 'Security Audit Log Cleared',               level: 'critical', match: /log was cleared|1102.*security|event\s*log.*clear/i,                                     mitre: 'T1070.001', tactic: 'Defense Evasion' },
        { title: 'Scheduled Task Created',                   level: 'medium',   match: /scheduled task.*created|schtasks|4698/i,                                                  mitre: 'T1053.005', tactic: 'Persistence' },
        { title: 'Firewall Rule Modified',                   level: 'medium',   match: /firewall rule|2004.*firewall/i,                                                            mitre: 'T1562.004', tactic: 'Defense Evasion' },
        { title: 'RDP Lateral Movement',                     level: 'high',     match: /rdp.*logon|1149.*terminal|mstsc/i,                                                        mitre: 'T1021.001', tactic: 'Lateral Movement' },
        { title: 'Account Lockout (Brute Force)',            level: 'medium',   match: /account.*locked|4740/i,                                                                   mitre: 'T1110',     tactic: 'Credential Access' },
        { title: 'Suspicious Encoded PowerShell',            level: 'high',     match: /-enc[o]?[d]?\s|frombase64string|encodedcommand/i,                                        mitre: 'T1059.001', tactic: 'Execution' },
        { title: 'Process Injection Indicators',             level: 'critical', match: /virtualalloc|writeprocessmemory|createremotethread|ntmapviewofsection/i,                  mitre: 'T1055',     tactic: 'Defense Evasion' },

        // ── Data Exfiltration ──
        { title: 'Rclone Data Exfiltration Tool',            level: 'critical', match: /\brclone\b|rclone\.exe|rclone\s+(copy|sync|move|mount|bisync)|remote:.*bucket/i,         mitre: 'T1567.002', tactic: 'Exfiltration' },
        { title: 'Cloud Storage Exfiltration (S3/Azure/GCP)', level: 'high',   match: /aws\s+s3\s+cp|az\s+storage|gsutil\s+(cp|rsync)|azcopy|s3cmd\s+put|gdrive\s+upload/i,     mitre: 'T1567.002', tactic: 'Exfiltration' },
        { title: 'MEGA Sync / MEGAcmd Exfiltration',         level: 'high',     match: /megacmd|mega\.exe|mega-put|mega-sync|\bmega\b.*upload/i,                                  mitre: 'T1567.002', tactic: 'Exfiltration' },
        { title: 'Data Archiving Before Exfiltration',       level: 'medium',   match: /7z\s+a|winrar.*-r|compress-archive|rar\.exe\s+a\s|tar\s+czf.*\/tmp/i,                   mitre: 'T1560.001', tactic: 'Collection' },

        // ── Credential Access ──
        { title: 'LSASS Memory Dump (Credential Theft)',     level: 'critical', match: /procdump.*lsass|lsass.*procdump|comsvcs.*minidump|sekurlsa|werfault.*lsass|rundll32.*comsvcs/i, mitre: 'T1003.001', tactic: 'Credential Access' },
        { title: 'Mimikatz Execution',                       level: 'critical', match: /mimikatz|sekurlsa::logonpasswords|lsadump::dcsync|privilege::debug|kerberos::ptt/i,      mitre: 'T1003',     tactic: 'Credential Access' },
        { title: 'NTDS.dit Active Directory Database Access',level: 'critical', match: /ntds\.dit|ntdsutil.*activate.*ntds|vssadmin.*shadow.*ntds|copy.*ntds\.dit/i,             mitre: 'T1003.003', tactic: 'Credential Access' },
        { title: 'SAM Database Dump',                        level: 'critical', match: /\bsam\b.*dump|reg\s+save.*\\sam|fgdump|pwdump|samdump2/i,                               mitre: 'T1003.002', tactic: 'Credential Access' },
        { title: 'Credential Harvesting Tool',               level: 'high',     match: /lazagne|bloodhound|sharphound|crackmapexec|cme\s|ncrack|kerbrute|rubeus\b/i,             mitre: 'T1003',     tactic: 'Credential Access' },
        { title: 'Kerberoasting Attack (EventID 4769)',      level: 'high',     match: /4769.*rc4|kerberos.*ticket.*0x17|4769.*0x17|ticket.*encryption.*rc4/i,                   mitre: 'T1558.003', tactic: 'Credential Access' },
        { title: 'Pass-the-Hash / Pass-the-Ticket',         level: 'critical', match: /pass.*the.*hash|pth\b|sekurlsa::pth|pass.*the.*ticket|ptt\b/i,                           mitre: 'T1550.002', tactic: 'Lateral Movement' },

        // ── Defense Evasion ──
        { title: 'Volume Shadow Copy Deletion',              level: 'critical', match: /vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*systemstatebackup|bcdedit.*recoveryenabled.*no/i, mitre: 'T1490', tactic: 'Impact' },
        { title: 'Windows Defender Disabled/Tampered',       level: 'high',     match: /set-mppreference.*disable|add-mppreference.*exclusion|DisableRealtimeMonitoring|tamperprotection.*0/i, mitre: 'T1562.001', tactic: 'Defense Evasion' },
        { title: 'UAC Bypass via Registry',                  level: 'high',     match: /eventvwr.*mmc|fodhelper|sdclt|computerdefaults.*shell.*open/i,                           mitre: 'T1548.002', tactic: 'Privilege Escalation' },
        { title: 'AMSI Bypass',                              level: 'high',     match: /amsiutils.*class|amsi\.dll.*patch|reflection\.assembly.*amsi|amsicontext.*0/i,           mitre: 'T1562.001', tactic: 'Defense Evasion' },
        { title: 'Timestomping (Timestamp Manipulation)',    level: 'medium',   match: /timestomp|setfiletime|fileinfo.*modificationtime|touch\s+-[tm]\s/i,                      mitre: 'T1070.006', tactic: 'Defense Evasion' },

        // ── Execution / LOLBins ──
        { title: 'Certutil Suspicious Usage (Download/Decode)', level: 'high', match: /certutil.*-(urlcache|decode|encode|decodehex)|certutil\.exe.*http/i,                     mitre: 'T1105',     tactic: 'Command and Control' },
        { title: 'MSHTA Execution (LOLBin)',                 level: 'high',     match: /mshta\s+(http|vbscript|javascript)|mshta\.exe.*\.hta/i,                                  mitre: 'T1218.005', tactic: 'Defense Evasion' },
        { title: 'Regsvr32 COM Bypass (Squiblydoo)',         level: 'high',     match: /regsvr32.*\/s.*\/n.*\/i.*http|regsvr32.*scrobj\.dll/i,                                   mitre: 'T1218.010', tactic: 'Defense Evasion' },
        { title: 'WScript/CScript Suspicious Execution',    level: 'medium',   match: /wscript\s.*\.(vbs|js|vbe|jse)|cscript\s.*\.(vbs|js|vbe|jse)/i,                         mitre: 'T1059.005', tactic: 'Execution' },
        { title: 'BITS Job Abuse (Background Transfer)',     level: 'medium',   match: /bitsadmin\s+\/transfer|bitsadmin\s+\/addfile|start-bitstransfer/i,                       mitre: 'T1197',     tactic: 'Persistence' },

        // ── Lateral Movement ──
        { title: 'PsExec / Remote Service Execution',       level: 'high',     match: /psexec\s|psexesvc|paexec|remcom|winexe\b/i,                                              mitre: 'T1021.002', tactic: 'Lateral Movement' },
        { title: 'WMI Remote Execution',                    level: 'high',     match: /wmic\s+\/node:|invoke-wmimethod|invoke-cimmethod.*create|wmiprvse.*cmd\.exe/i,           mitre: 'T1047',     tactic: 'Lateral Movement' },
        { title: 'SMB / Admin Share Lateral Movement',      level: 'high',     match: /net\s+use\s+\\\\|net\s+view\s+\\\\|copy.*\\\\.*admin\$|\\\\.*\\\$.*\\.exe/i,            mitre: 'T1021.002', tactic: 'Lateral Movement' },
        { title: 'Remote PowerShell Session',               level: 'medium',   match: /new-pssession|enter-pssession|invoke-command.*-computername|wsmprovhost/i,              mitre: 'T1021.006', tactic: 'Lateral Movement' },

        // ── Reconnaissance ──
        { title: 'AD Enumeration (Net Commands)',           level: 'medium',   match: /net\s+(user|group|localgroup|accounts|computer)\s*(\/domain|\\s*$)|nltest\s+\/domain/i,  mitre: 'T1087',     tactic: 'Discovery' },
        { title: 'Network Reconnaissance (Port Scan/Ping)', level: 'low',      match: /nmap\b|masscan\b|advanced\s*port\s*scanner|invoke-portscan|test-netconnection/i,         mitre: 'T1046',     tactic: 'Discovery' },
        { title: 'System Information Discovery',            level: 'low',      match: /systeminfo\b|wmic\s+os\s+get|get-computerinfo|hostname\s*&&|ipconfig\s*\/all/i,          mitre: 'T1082',     tactic: 'Discovery' },

        // ── Persistence ──
        { title: 'Registry Run Key Persistence',            level: 'medium',   match: /currentversion\\run|currentversion\\runonce|software\\microsoft\\windows\\currentversion\\run/i, mitre: 'T1547.001', tactic: 'Persistence' },
        { title: 'Startup Folder Persistence',              level: 'medium',   match: /appdata.*roaming.*microsoft.*windows.*start\s*menu.*programs.*startup|programdata.*microsoft.*windows.*start\s*menu/i, mitre: 'T1547.001', tactic: 'Persistence' },
        { title: 'DLL Hijacking / Side-Loading',            level: 'high',     match: /dll\s*side.load|dll\s*hijack|phantom\s*dll|missing\s*dll\s*loaded/i,                     mitre: 'T1574.002', tactic: 'Persistence' },
      ];

      for (const record of evtxRecords) {

        const rawObj = (typeof record.raw === 'object' && record.raw !== null) ? record.raw : {};
        const text = (record.description || '') + ' ' + (record.source || '') + ' ' + JSON.stringify(rawObj);
        for (const rule of SIGMA_RULES) {
          if (rule.match.test(text)) {
            hayabusaRecords.push({
              timestamp: record.timestamp,
              artifact_type: 'hayabusa',
              artifact_name: 'Hayabusa',
              rule_title: rule.title,
              level: rule.level,
              event_id: rawObj.EventId || rawObj.EventID || '',
              channel: record.source || '',
              computer: record.host_name || rawObj.Computer || '',
              details: record.description,

              mitre_attack: rule.mitre,
              tactic: rule.tactic,
              description: `[${rule.level}] ${rule.title}`,
              source: record.source || '',
              raw: { ...rawObj, hayabusa_rule: rule.title, hayabusa_mitre: rule.mitre },
            });
            break;
          }
        }
      }
      if (engineUsed === 'sigma_fallback') {
        logger.info(`[hayabusa] sigma fallback — ${hayabusaRecords.length} matches from ${evtxRecords.length} evtx records`);
      }
    }

    hayabusaRecords.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const stats = {
      critical: hayabusaRecords.filter(r => r.level === 'critical').length,
      high:     hayabusaRecords.filter(r => r.level === 'high').length,
      medium:   hayabusaRecords.filter(r => r.level === 'medium').length,
      low:      hayabusaRecords.filter(r => r.level === 'low').length,
    };
    const diagnostic = {
      engine_used:    engineUsed,
      rules_count:    rulesCount,
      rules_present:  rulesPresent,
      evtx_files:     evtxFiles.length,
      binary_path:    HAYABUSA_BIN,
      truncated:      false,
      stderr_snippet: hayStderrSnip || null,
    };

    // Atomically clear previous Hayabusa data and insert the final result record.
    const { newId: hayResultId, oldIds: hayOldIds } = await initHayabusaRecord(
      JSON.stringify({
        hayabusa_timeline: hayabusaRecords,
        evtx_dir: evtxParentDir,
        evtx_files_count: evtxFiles.length,
        stats,
        diagnostic,
      }),
      hayabusaRecords.length
    );
    // Delete stale ES docs from previous run.
    for (const oid of hayOldIds) {
      esService.deleteByResultId(caseId, oid).catch(e =>
        logger.warn('[ES] hayabusa stale cleanup warn:', e.message?.substring(0, 80))
      );
    }
    if (hayabusaRecords.length > 0) {
      const CT_BATCH = 500;
      for (let i = 0; i < hayabusaRecords.length; i += CT_BATCH) {
        const chunk = hayabusaRecords.slice(i, i + CT_BATCH);
        const vals = [];
        const prms = [];
        let pi = 1;
        for (const r of chunk) {

          const mitreRaw = r.mitre_attack || '';
          const isTechniqueId = /^T\d{4}(\.\d{3})?$/i.test(mitreRaw.split(',')[0].trim());
          const mitreId   = isTechniqueId ? (mitreRaw.split(',')[0].trim() || null) : null;
          const mitreName = null;
          const mitreTactic = isTechniqueId
            ? ((r.tactic || '').split(',')[0].trim().toLowerCase() || null)
            : (mitreRaw.split(',')[0].trim().toLowerCase() || null);

          // v2.23 — forensic fields + keyword tags for Hayabusa rows
          const hayEvId = /^\d+$/.test(String(r.event_id || '').trim()) ? parseInt(r.event_id, 10) : null;
          const hayDesc = (r.description || '').slice(0, 200);
          const haySource = r.source || r.channel || '';
          const hayDedupe = crypto.createHash('md5')
            .update(['Timestamp', haySource, 'hayabusa', hayDesc, hayEvId == null ? '' : String(hayEvId)].join('|'))
            .digest('hex').slice(0, 16);
          let hayTags = [];
          try { hayTags = matchKeywordTags(r, r.description); } catch (_e) {}
          // Critical/high Hayabusa level also populates a severity tag
          if (r.level === 'critical') hayTags = Array.from(new Set([...hayTags, 'critical']));
          else if (r.level === 'high') hayTags = Array.from(new Set([...hayTags, 'high']));

          // v2.23 — enrich ext / path / ips / details from Hayabusa description
          const hayIpRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
          const hayIps = (r.description || '').match(hayIpRe) || [];
          const haySrcIp = hayIps[0] || null;
          const hayDstIp = hayIps[1] || null;
          const hayExtM  = /\.([A-Za-z0-9]{1,10})(?=[\s"'\\\/)]|$)/.exec(r.description || '');
          const hayExt   = hayExtM ? ('.' + hayExtM[1].toLowerCase()).slice(0, 16) : null;
          const hayPathM = /([A-Z]:\\[^\s"']+|\/[^\s"']+)/.exec(r.description || '');
          const hayPath  = hayPathM ? hayPathM[1].slice(0, 500) : null;
          const hayDetails = r.description ? r.description.slice(0, 200000) : null;
          // Hayabusa per-EventID MITRE override when rule didn't set one
          let hMitreId = mitreId, hMitreName = mitreName, hMitreTactic = mitreTactic;
          if (!hMitreId && hayEvId !== null && EVTX_MITRE_BY_EID[hayEvId]) {
            const m = EVTX_MITRE_BY_EID[hayEvId];
            hMitreId = m.technique_id; hMitreName = m.technique_name; hMitreTactic = m.tactic;
          }

          vals.push(`($${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++}::text[],$${pi++},$${pi++},$${pi++},$${pi++},$${pi++})`);
          prms.push(
            caseId,
            hayResultId,
            hayEvidenceId,
            r.timestamp,
            'hayabusa',
            r.rule_title || 'Hayabusa',
            r.description || '',
            haySource,
            JSON.stringify(r.raw),
            r.computer || null,
            null,
            null,
            hMitreId,
            hMitreName,
            hMitreTactic,
            // forensic columns
            'Hayabusa',
            'Timestamp',
            hayEvId,
            hayDedupe,
            hayTags,
            hayExt,
            hayPath,
            haySrcIp,
            hayDstIp,
            (r.details || hayDetails || null),
          );
        }
        await pool.query(
          `INSERT INTO collection_timeline
             (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
              host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
              tool, timestamp_kind, event_id, dedupe_hash, tags,
              ext, path, src_ip, dst_ip, details)
           VALUES ${vals.join(',')}
           ON CONFLICT DO NOTHING`,
          prms
        );
      }

      const ctRows = hayabusaRecords.map(r => {
        const mitreRaw = r.mitre_attack || '';
        const isTechId = /^T\d{4}(\.\d{3})?$/i.test(mitreRaw.split(',')[0].trim());
        return {
          timestamp:    r.timestamp,
          artifact_type: 'hayabusa',
          artifact_name: r.rule_title || 'Hayabusa',
          description:   r.description || '',
          source:        r.source || '',
          raw:           { level: r.level, event_id: r.event_id },
          host_name:     r.computer || null,
          user_name:     null,
          process_name:  null,
          mitre_technique_id:   isTechId ? mitreRaw.split(',')[0].trim() : null,
          mitre_technique_name: null,
          mitre_tactic:         isTechId
            ? ((r.tactic || '').split(',')[0].trim().toLowerCase() || null)
            : (mitreRaw.split(',')[0].trim().toLowerCase() || null),
        };
      });
      esService.bulkIndex(caseId, ctRows, hayResultId, hayEvidenceId).then(res => {
        if (res?.errors) {
          const failed = (res.items || []).filter(i => i.index?.error);
          if (failed.length) logger.warn(`[ES] hayabusa bulkIndex: ${failed.length} item errors`, failed[0]?.index?.error);
        }
      }).catch(e =>
        logger.warn('[ES] hayabusa bulkIndex warn:', e.message?.substring(0, 100))
      );
    }

    await auditLog(req.user.id, 'run_hayabusa', 'collection', hayResultId,
      { evtx_count: evtxFiles.length, detections: hayabusaRecords.length }, req.ip);

    res.json({
      id:               hayResultId,
      total_detections: hayabusaRecords.length,
      stats,
      evtx_files_processed: evtxFiles.length,
      diagnostic,
      timeline: hayabusaRecords,
    });
  } catch (err) {
    logger.error('Hayabusa error:', err);
    res.status(500).json({ error: 'Erreur exécution Hayabusa' });
  } finally {
    // Release the per-case guard on every exit path (success, error, client
    // disconnect mid-run) once the binary + stream-insert actually finished.
    ACTIVE_HAYABUSA_LOCKS.delete(caseId);
  }
});

// GET /hayabusa — reads detections from collection_timeline (paginated, cursor-based)
// Never reads parser_results JSONB — safe for any volume of records.
router.get('/:caseId/hayabusa', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const limit         = Math.min(parseInt(req.query.limit) || 10000, 100000);
    const cursor        = req.query.cursor || null; // BIGINT id cursor
    const evidence_id   = req.query.evidence_id || null; // v2.27 per-evidence scoping

    const meta = await pool.query(
      `SELECT output_data, record_count, created_at, id FROM parser_results
       WHERE case_id = $1 AND parser_name = 'Hayabusa'
       ORDER BY created_at DESC LIMIT 1`,
      [caseId]
    );

    if (meta.rows.length === 0) {
      return res.json({ timeline: [], total_detections: 0, stats: { critical: 0, high: 0, medium: 0, low: 0 }, next_cursor: null });
    }

    const metaRow  = meta.rows[0];
    const metaData = metaRow.output_data || {};

    // Build base WHERE clause — evidence_id scoping avoids full case scan
    const whereClauses = ['case_id = $1', "artifact_type = 'hayabusa'"];
    const params = [caseId];
    if (evidence_id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(evidence_id)) {
      params.push(evidence_id);
      whereClauses.push(`evidence_id = $${params.length}`);
    }

    // Read detections from collection_timeline — cursor-paginated by row id
    let ctQuery = `SELECT id, timestamp, artifact_name AS rule_title, description,
                          source, source AS channel,
                          raw, host_name AS computer, user_name, process_name,
                          mitre_technique_id AS mitre_attack,
                          mitre_tactic AS tactic, event_id, details, tags,
                          COALESCE(raw->>'Level', raw->>'level') AS level,
                          COALESCE(raw->>'event_id', raw->>'EventID') AS event_id_raw
                   FROM collection_timeline
                   WHERE ${whereClauses.join(' AND ')}`;
    if (cursor) {
      params.push(cursor);
      ctQuery += ` AND id > $${params.length}`;
    }
    params.push(limit);
    ctQuery += ` ORDER BY id ASC LIMIT $${params.length}`;

    // Build stats WHERE — same evidence scoping
    const statsWhere = whereClauses.join(' AND ');
    // Compute live stats from collection_timeline — always consistent with the grid
    const [ctResult, liveStats] = await Promise.all([
      pool.query(ctQuery, params),
      pool.query(
        `SELECT
           COUNT(*)                                                                                                            AS total,
           COUNT(*) FILTER (WHERE LOWER(COALESCE(raw->>'Level', raw->>'level')) IN ('critical', 'crit'))                      AS critical,
           COUNT(*) FILTER (WHERE LOWER(COALESCE(raw->>'Level', raw->>'level')) = 'high')                                     AS high,
           COUNT(*) FILTER (WHERE LOWER(COALESCE(raw->>'Level', raw->>'level')) IN ('medium', 'med'))                         AS medium,
           COUNT(*) FILTER (WHERE LOWER(COALESCE(raw->>'Level', raw->>'level')) = 'low')                                      AS low,
           COUNT(*) FILTER (WHERE LOWER(COALESCE(raw->>'Level', raw->>'level')) IN ('informational', 'info'))                 AS informational
         FROM collection_timeline
         WHERE ${statsWhere}`,
        [caseId, ...(evidence_id ? [evidence_id] : [])]
      ),
    ]);

    const rows       = ctResult.rows;
    const nextCursor = rows.length === limit ? rows[rows.length - 1].id : null;
    const ls         = liveStats.rows[0];
    const stats = {
      critical:      parseInt(ls.critical)      || 0,
      high:          parseInt(ls.high)          || 0,
      medium:        parseInt(ls.medium)        || 0,
      low:           parseInt(ls.low)           || 0,
      informational: parseInt(ls.informational) || 0,
    };

    res.json({
      timeline:         rows,
      total_detections: parseInt(ls.total) || 0,
      stats,
      evtx_files_count: metaData.evtx_files_count || 0,
      diagnostic:       metaData.diagnostic        || null,
      generated_at:     metaRow.created_at,
      next_cursor:      nextCursor,
    });
  } catch (err) {
    logger.error('[hayabusa GET]', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Counterpart to exhaustive parsing: take the filesystem timeline back out
// without touching any other artifact. Requires confirm=true in the body so it
// cannot be triggered by a stray request, and is audit-logged like any deletion.
router.delete('/:caseId/fs-timeline', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    if (req.body?.confirm !== true && req.body?.confirm !== 'true') {
      return res.status(400).json({
        error: 'Confirmation requise : renvoyez { "confirm": true } pour supprimer la timeline filesystem.',
      });
    }
    const evidenceId = req.body?.evidence_id || null;
    const removed = await purgeFsTimeline(pool, caseId, { evidenceId });
    await auditLog(req.user.id, 'purge_fs_timeline', 'case', caseId,
      { removed, evidence_id: evidenceId }, req.ip);
    logger.info(`[collection] fs timeline purged: ${removed} row(s) for case ${caseId}`);
    return res.json({ removed, evidence_id: evidenceId });
  } catch (err) {
    logger.error('[collection/fs-timeline DELETE]', err.message);
    return res.status(500).json({ error: 'Erreur lors de la suppression de la timeline filesystem' });
  }
});

// Same contract for the state inventory, optionally narrowed to one family —
// dropping lsof (525k rows) without losing the rest.
router.delete('/:caseId/state', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    if (req.body?.confirm !== true && req.body?.confirm !== 'true') {
      return res.status(400).json({
        error: 'Confirmation requise : renvoyez { "confirm": true } pour supprimer l\'inventaire d\'état.',
      });
    }
    const kind = req.body?.kind || null;
    const evidenceId = req.body?.evidence_id || null;
    const removed = await purgeCatScaleState(pool, caseId, { kind, evidenceId });
    await auditLog(req.user.id, 'purge_catscale_state', 'case', caseId,
      { removed, kind, evidence_id: evidenceId }, req.ip);
    logger.info(`[collection] catscale_state purged: ${removed} row(s) for case ${caseId}${kind ? ` (kind=${kind})` : ''}`);
    return res.json({ removed, kind, evidence_id: evidenceId });
  } catch (err) {
    logger.error('[collection/state DELETE]', err.message);
    return res.status(500).json({ error: 'Erreur lors de la suppression de l\'inventaire d\'état' });
  }
});

router.delete('/:caseId/data', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;

    const importRow = await pool.query(
      `SELECT output_data->>'collection_dir' AS dir
       FROM parser_results
       WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'
       ORDER BY created_at DESC LIMIT 1`,
      [caseId]
    );

    let freedBytes = 0;

    if (importRow.rows.length > 0) {
      const collDir = importRow.rows[0].dir;
      if (collDir && fs.existsSync(collDir)) {
        try {
          const duOut = await spawnTool(['du', '-sb', collDir], { timeout: 10000 });
          const szLine = duOut.trim().split(/\s+/)[0];
          freedBytes += parseInt(szLine) || 0;
        } catch (_e) {}
        fs.rmSync(collDir, { recursive: true, force: true });
        logger.info(`[collection] Deleted collection dir: ${collDir}`);
      }
    }

    try {
      for (const entry of fs.readdirSync(TEMP_DIR)) {
        if (entry.startsWith(`parse-${caseId}-`)) {
          try { fs.rmSync(path.join(TEMP_DIR, entry), { recursive: true, force: true }); } catch (_e) {}
        }
      }
    } catch (_e) {}

    const ctDeleted = await pool.query(
      `DELETE FROM collection_timeline WHERE case_id = $1`,
      [caseId]
    );

    const deleted = await pool.query(
      `DELETE FROM parser_results WHERE case_id = $1 RETURNING id`,
      [caseId]
    );

    await esService.deleteIndex(caseId).catch(e =>
      logger.warn(`[ES] deleteIndex warn on data-delete (${caseId}): ${String(e.message).substring(0, 100)}`));

    const freedMb = Math.round(freedBytes / 1024 / 1024);
    await auditLog(req.user.id, 'delete_collection_data', 'case', caseId,
      { freed_mb: freedMb, rows_deleted: deleted.rowCount, timeline_records_deleted: ctDeleted.rowCount }, req.ip);

    res.json({
      success: true,
      freed_mb: freedMb,
      rows_deleted: deleted.rowCount,
      timeline_records_deleted: ctDeleted.rowCount,
    });
  } catch (err) {
    logger.error('collection delete error:', err);
    res.status(500).json({ error: err.message });
  }
});

router.get('/:caseId/export/csv', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const rawSep = req.query.sep;
    const sep = rawSep === ';' ? ';' : rawSep === '\t' ? '\t' : ',';
    const { artifact_types, search, start_time, end_time, host_name, user_name, evidence_id } = req.query;

    if (evidence_id) {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(evidence_id)) {
        return res.status(400).json({ error: 'Paramètre evidence_id invalide' });
      }
      const evCheck = await pool.query(
        `SELECT 1 FROM evidence WHERE id = $1 AND case_id = $2`,
        [evidence_id, caseId]
      );
      if (evCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Accès refusé : cette collecte n\'appartient pas à ce cas' });
      }
    }

    const conditions = ['case_id = $1'];
    const params = [caseId];
    let pi = 2;

    if (artifact_types) {
      conditions.push(`artifact_type = ANY($${pi++})`);
      params.push(artifact_types.split(','));
    }
    if (search) {
      pi = pushSearchFilter(search || '', 'contains', pi, conditions, params);
    }
    if (start_time)  { conditions.push(`timestamp >= $${pi++}`);          params.push(start_time); }
    if (end_time)    { conditions.push(`timestamp <= $${pi++}`);          params.push(end_time);   }
    if (host_name)   { conditions.push(`host_name ILIKE $${pi++}`);       params.push('%' + escapeLike(host_name) + '%'); }
    if (user_name)   { conditions.push(`user_name ILIKE $${pi++}`);       params.push('%' + escapeLike(user_name) + '%'); }
    if (evidence_id) { conditions.push(`evidence_id = $${pi++}`);         params.push(evidence_id); }

    const requestedTypes = artifact_types ? artifact_types.split(',').filter(Boolean) : [];
    const singleArtifact = requestedTypes.length === 1 ? requestedTypes[0] : null;

    let rawKeys = [];
    if (singleArtifact) {
      try {
        const keysQ = await pool.query(
          `SELECT DISTINCT k
             FROM collection_timeline ct,
                  LATERAL jsonb_object_keys(ct.raw) AS k
            WHERE ${conditions.join(' AND ')}
              AND ct.raw IS NOT NULL
            LIMIT 200`,
          params
        );
        rawKeys = keysQ.rows.map(r => r.k).sort();
      } catch (_e) { rawKeys = []; }
    }

    const baseCols = ['timestamp', 'artifact_type', 'artifact_name', 'source', 'description',
                      'host_name', 'user_name', 'process_name',
                      'mitre_tactic', 'mitre_technique_id', 'mitre_technique_name'];
    const extraCols = singleArtifact
      ? ['tool', 'event_id', 'ext', 'file_size', 'ip_address', 'sha1', 'evidence_path', 'dedupe_hash', 'tags', 'detections']
      : [];

    const selectCols = singleArtifact
      ? `timestamp, artifact_type, artifact_name, source, description,
         host_name, user_name, process_name,
         mitre_tactic, mitre_technique_id, mitre_technique_name,
         tool, event_id, ext, file_size, ip_address, sha1, evidence_path, dedupe_hash,
         tags, detections, raw`
      : `timestamp, artifact_type, artifact_name, source, description,
         host_name, user_name, process_name,
         mitre_tactic, mitre_technique_id, mitre_technique_name`;

    const result = await pool.query(
      `SELECT ${selectCols}
       FROM collection_timeline
       WHERE ${conditions.join(' AND ')}
       ORDER BY timestamp ASC`,
      params
    );

    const COLS = [...baseCols, ...extraCols, ...rawKeys.map(k => `raw_${k}`)];

    function csvCell(v) {
      if (v == null) return '';
      let s;
      if (Array.isArray(v) || typeof v === 'object') s = JSON.stringify(v);
      else s = String(v);
      if (s.includes(sep) || s.includes('"') || s.includes('\n') || s.includes('\r')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    }

    const filename = singleArtifact
      ? `timeline-${singleArtifact}-${caseId}-${Date.now()}.csv`
      : `timeline-${caseId}-${Date.now()}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.write('\uFEFF');
    res.write(COLS.join(sep) + '\r\n');
    for (const row of result.rows) {
      const line = COLS.map(c => {
        if (c.startsWith('raw_')) {
          const k = c.slice(4);
          return csvCell(row.raw?.[k]);
        }
        return csvCell(row[c]);
      }).join(sep);
      res.write(line + '\r\n');
    }
    res.end();
  } catch (err) {
    logger.error('[export csv]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Erreur export CSV' });
  }
});

router.get('/:caseId/export-csv-stream', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const {
    artifact_types, search, start_time, end_time, host_name, user_name,
    result_id, evidence_id, sep = ','
  } = req.query;

  const separator = [',', ';', '\t'].includes(sep) ? sep : ',';
  const filename  = `timeline-${caseId}-${Date.now()}.csv`;

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('X-Accel-Buffering', 'no'); // disable nginx buffering for streaming

  const CSV_HEADERS = ['timestamp', 'artifact_type', 'artifact_name', 'description', 'source',
                        'host_name', 'user_name', 'process_name', 'mitre_tactic', 'mitre_technique_id'];

  function escapeCsv(val) {
    const s = String(val ?? '').replace(/"/g, '""');
    return s.includes(separator) || s.includes('"') || s.includes('\n') ? `"${s}"` : s;
  }

  res.write(CSV_HEADERS.join(separator) + '\n');

  let written = 0;
  try {
    const hasIndex = await esService.indexExists(caseId);

    if (hasIndex) {
      const { Client } = await import('@elastic/elasticsearch');
      const filters = [{ term: { case_id: caseId } }];
      if (artifact_types) {
        const types = artifact_types.split(',').filter(Boolean);
        if (types.length === 1) filters.push({ term: { artifact_type: types[0] } });
        else if (types.length > 1) filters.push({ terms: { artifact_type: types } });
      }
      if (start_time || end_time) {
        const range = {};
        if (start_time) range.gte = start_time;
        if (end_time) range.lte = end_time;
        filters.push({ range: { timestamp: range } });
      }
      if (result_id)  filters.push({ term: { result_id } });
      if (evidence_id) filters.push({ term: { evidence_id } });

      const mustClauses = [];
      if (search?.trim()) {
        mustClauses.push({ multi_match: { query: search.trim(), fields: ['description', 'source', 'artifact_type'], operator: 'and' } });
      }

      let searchAfter = null;
      const BATCH = 2000;

      while (true) {
        const body = {
          size: BATCH,
          query: { bool: { filter: filters, must: mustClauses } },
          sort: [{ timestamp: { order: 'asc' } }, { _shard_doc: { order: 'asc' } }],
          _source: CSV_HEADERS,
        };
        if (searchAfter) body.search_after = searchAfter;

        const result = await esService.rawSearch(caseId, body);
        const hits = result.hits?.hits || [];
        if (!hits.length) break;

        const chunk = hits.map(h => {
          const s = h._source;
          return CSV_HEADERS.map(col => escapeCsv(s[col])).join(separator);
        }).join('\n') + '\n';

        res.write(chunk);
        written += hits.length;

        if (hits.length < BATCH) break;
        searchAfter = hits[hits.length - 1].sort;
      }
    } else {
      const conditions = ['case_id = $1'];
      const params = [caseId];
      let pi = 2;
      if (artifact_types) { conditions.push(`artifact_type = ANY($${pi++})`); params.push(artifact_types.split(',')); }
      if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
      if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time);   }
      if (host_name)  { conditions.push(`host_name ILIKE $${pi++}`); params.push(escapeLike(host_name)); }
      if (user_name)  { conditions.push(`user_name ILIKE $${pi++}`); params.push(escapeLike(user_name)); }
      if (result_id)  { conditions.push(`result_id = $${pi++}`); params.push(result_id); }
      if (evidence_id){ conditions.push(`evidence_id = $${pi++}`); params.push(evidence_id); }

      const pgQuery = pool.query(new (require('pg').QueryStream)(
        `SELECT ${CSV_HEADERS.join(',')} FROM collection_timeline WHERE ${conditions.join(' AND ')} ORDER BY timestamp ASC`,
        params
      ));

      const CHUNK_SIZE = 500;
      let buffer = [];

      const stream = pool.query(
        `SELECT ${CSV_HEADERS.join(',')} FROM collection_timeline WHERE ${conditions.join(' AND ')} ORDER BY timestamp ASC`,
        params
      );

      let offset = 0;
      const BATCH = 2000;
      while (true) {
        const r = await pool.query(
          `SELECT ${CSV_HEADERS.join(',')} FROM collection_timeline WHERE ${conditions.join(' AND ')} ORDER BY timestamp ASC LIMIT $${pi} OFFSET $${pi+1}`,
          [...params, BATCH, offset]
        );
        if (!r.rows.length) break;
        const chunk = r.rows.map(row =>
          CSV_HEADERS.map(col => escapeCsv(row[col])).join(separator)
        ).join('\n') + '\n';
        res.write(chunk);
        written += r.rows.length;
        if (r.rows.length < BATCH) break;
        offset += BATCH;
      }
    }
  } catch (err) {
    logger.error('[export-csv-stream] error after', written, 'rows:', err.message);
  }

  res.end();
});


const _pcapUpload = multer({
  dest: '/tmp/pcap-uploads',
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
  fileFilter: (_req, file, cb) => {
    const ok = /\.(pcap|pcapng|cap)$/i.test(file.originalname);
    cb(ok ? null : new Error('Fichier PCAP requis (.pcap, .pcapng, .cap)'), ok);
  },
}).single('pcap');

router.post('/:caseId/pcap', authenticate, (req, res) => {
  _pcapUpload(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Aucun fichier PCAP fourni' });

    const { caseId } = req.params;
    const pcapPath = req.file.path;
    const source = req.file.originalname;
    const pcapEvidenceId = req.body?.evidence_id || null;

    const runTshark = (args) => new Promise((resolve) => {
      execFile('tshark', args, {
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        timeout: 120000,
      }, (_err, stdout) => resolve({ stdout: stdout || '' }));
    });

    const parseTabular = (stdout, sep = '|') => {
      if (!stdout) return [];
      const lines = stdout.trim().split('\n');
      const header = lines[0]?.split(sep) || [];
      const rows = [];
      for (const line of lines.slice(1)) {
        if (!line.trim()) continue;
        const cols = line.split(sep);
        const row = {};
        header.forEach((h, i) => { row[h] = cols[i] || ''; });
        rows.push(row);
      }
      return rows;
    };

    try {
      const fieldArgs = (fields) => ['-T', 'fields', '-E', 'separator=|', '-E', 'header=y', ...fields.flatMap(f => ['-e', f])];

      const dnsFields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'dns.qry.name', 'dns.a', 'dns.qry.type'];
      const httpFields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
        'http.request.method', 'http.host', 'http.request.uri', 'http.response.code', 'http.user_agent'];
      const tlsFields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
        'tls.handshake.extensions_server_name', 'tls.record.version'];

      const [dnsResult, httpResult, tlsResult, convResult] = await Promise.all([
        runTshark(['-r', pcapPath, '-Y', 'dns', ...fieldArgs(dnsFields)]),
        runTshark(['-r', pcapPath, '-Y', 'http', ...fieldArgs(httpFields)]),
        runTshark(['-r', pcapPath, '-Y', 'tls.handshake.type == 1', ...fieldArgs(tlsFields)]),
        runTshark(['-r', pcapPath, '-q', '-z', 'conv,tcp']),
      ]);
      const dnsRaw = parseTabular(dnsResult.stdout);
      const dnsRows = dnsRaw.flatMap(row => {
        const ts = parseFloat(row['frame.time_epoch']);
        if (isNaN(ts) || !row['dns.qry.name']) return [];
        return [{
          timestamp: new Date(ts * 1000).toISOString(),
          artifact_type: 'DNS',
          source,
          host_name: row['ip.src'] || null,
          description: `DNS query: ${row['dns.qry.name']}${row['dns.a'] ? ' → ' + row['dns.a'] : ''}`,
          raw: { src_ip: row['ip.src'], dst_ip: row['ip.dst'], query: row['dns.qry.name'], response: row['dns.a'], type: row['dns.qry.type'] },
        }];
      });

      const httpRaw = parseTabular(httpResult.stdout);
      const httpRows = httpRaw.flatMap(row => {
        const ts = parseFloat(row['frame.time_epoch']);
        if (isNaN(ts)) return [];
        const method = row['http.request.method'], code = row['http.response.code'];
        if (!method && !code) return [];
        const desc = method
          ? `HTTP ${method} ${row['http.host']}${row['http.request.uri']}`
          : `HTTP Response ${code} from ${row['ip.src']}`;
        return [{ timestamp: new Date(ts * 1000).toISOString(), artifact_type: 'HTTP', source, host_name: row['ip.src'] || null, description: desc,
          raw: { src_ip: row['ip.src'], dst_ip: row['ip.dst'], src_port: row['tcp.srcport'], dst_port: row['tcp.dstport'], method, host: row['http.host'], uri: row['http.request.uri'], response_code: code, user_agent: row['http.user_agent'] } }];
      });

      const tlsRaw = parseTabular(tlsResult.stdout);
      const tlsRows = tlsRaw.flatMap(row => {
        const ts = parseFloat(row['frame.time_epoch']);
        if (isNaN(ts)) return [];
        const sni = row['tls.handshake.extensions_server_name'];
        return [{ timestamp: new Date(ts * 1000).toISOString(), artifact_type: 'TLS', source, host_name: row['ip.src'] || null,
          description: `TLS ClientHello${sni ? ' SNI=' + sni : ''} → ${row['ip.dst']}:${row['tcp.dstport']}`,
          raw: { src_ip: row['ip.src'], dst_ip: row['ip.dst'], src_port: row['tcp.srcport'], dst_port: row['tcp.dstport'], sni, version: row['tls.record.version'] } }];
      });

      const convOut = convResult.stdout || '';
      const convRows = [];
      for (const line of convOut.split('\n')) {
        const m = line.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
        if (!m) continue;
        const [, srcIp, srcPort, dstIp, dstPort, fwdPkts, fwdBytes, revPkts, revBytes] = m;
        convRows.push({ timestamp: new Date().toISOString(), artifact_type: 'NetworkConnection', source, host_name: srcIp,
          description: `TCP flow ${srcIp}:${srcPort} <-> ${dstIp}:${dstPort} (${parseInt(fwdPkts) + parseInt(revPkts)} pkts)`,
          raw: { src_ip: srcIp, src_port: srcPort, dst_ip: dstIp, dst_port: dstPort, fwd_pkts: fwdPkts, fwd_bytes: fwdBytes, rev_pkts: revPkts, rev_bytes: revBytes } });
      }

      const allRows = [...dnsRows, ...httpRows, ...tlsRows, ...convRows];
      if (allRows.length === 0) {
        fs.unlink(pcapPath, () => {});
        return res.json({ inserted: 0, message: 'Aucun événement extrait du PCAP' });
      }

      const pgEsc = (v) => {
        if (v === null || v === undefined) return '\\N';
        return String(v).replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
      };

      const client = await pool.connect();
      let inserted = 0;
      try {
        await client.query('BEGIN');
        const copyStream = client.query(pgCopyFrom(
          'COPY collection_timeline (case_id, evidence_id, timestamp, artifact_type, source, description, raw, host_name) FROM STDIN'
        ));
        for (const r of allRows) {
          copyStream.write(
            [pgEsc(caseId), pgEsc(pcapEvidenceId), pgEsc(r.timestamp),
             pgEsc(r.artifact_type), pgEsc(r.source), pgEsc(r.description),
             pgEsc(JSON.stringify(r.raw)), pgEsc(r.host_name)].join('\t') + '\n'
          );
        }
        await new Promise((resolve, reject) => {
          copyStream.on('finish', resolve);
          copyStream.on('error', reject);
          copyStream.end();
        });
        inserted = allRows.length;
        await client.query('COMMIT');
        invalidateDetectionCache(caseId).catch(() => {});
      } catch (insertErr) {
        await client.query('ROLLBACK');
        throw insertErr;
      } finally {
        client.release();
      }

      fs.unlink(pcapPath, () => {});

      // Also insert TCP conversations into network_connections so the Network Map is populated.
      if (convRows.length > 0) {
        try {
          for (let i = 0; i < convRows.length; i++) {
            const raw = convRows[i].raw;
            await pool.query(
              `INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen)
               VALUES ($1,$2,$3,$4,$5,'TCP',$6,$7,$8,NOW(),NOW())
               ON CONFLICT DO NOTHING`,
              [caseId, raw.src_ip, parseInt(raw.src_port) || null, raw.dst_ip, parseInt(raw.dst_port) || null,
               parseInt(raw.fwd_bytes) || 0, parseInt(raw.rev_bytes) || 0,
               (parseInt(raw.fwd_pkts) || 0) + (parseInt(raw.rev_pkts) || 0)]
            );
          }
        } catch (ncErr) {
          logger.warn('[pcap] network_connections insert error:', ncErr.message);
        }
      }

      await auditLog(req.user.id, 'pcap_parse', 'case', caseId,
        { source, dns: dnsRows.length, http: httpRows.length, tls: tlsRows.length, tcp_flows: convRows.length }, req.ip);

      res.json({
        inserted,
        breakdown: { dns: dnsRows.length, http: httpRows.length, tls: tlsRows.length, tcp_flows: convRows.length },
        message: `${inserted} événements réseau importés depuis ${source}`,
      });
    } catch (pcapErr) {
      fs.unlink(pcapPath, () => {});
      logger.error('[pcap]', pcapErr);
      res.status(500).json({ error: 'Erreur parsing PCAP: ' + pcapErr.message });
    }
  });
});

router.get('/:caseId/parser-results', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id } = req.query;
    const params = [caseId];
    let where = 'WHERE pr.case_id = $1';
    if (evidence_id) {
      params.push(evidence_id);
      where += ` AND pr.evidence_id = $${params.length}`;
    }
    const result = await pool.query(
      `SELECT pr.id, pr.case_id, pr.evidence_id, pr.record_count,
              pr.output_data, pr.parsed_at, pr.updated_at,
              e.name AS evidence_name, e.original_filename
         FROM parser_results pr
         LEFT JOIN evidence e ON pr.evidence_id = e.id
         ${where}
         ORDER BY pr.updated_at DESC
         LIMIT 50`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    logger.error('[collection] GET parser-results:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/evidence-ids', authenticate, async (req, res) => {
  const { caseId } = req.params;
  try {
    const result = await req.app.locals.pool.query(
      `SELECT DISTINCT evidence_id
       FROM parser_results
       WHERE case_id = $1
         AND evidence_id IS NOT NULL
         AND parser_name != 'MagnetRESPONSE_Import'`,
      [caseId]
    );
    res.json({ evidence_ids: result.rows.map(r => r.evidence_id) });
  } catch (err) {
    logger.error('[collection] GET evidence-ids:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/heatmap', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const { artifact_types, start_time, end_time } = req.query;
  try {
    const conditions = ['case_id = $1'];
    const vals = [caseId];
    let idx = 2;
    if (artifact_types) {
      const types = artifact_types.split(',').map(t => t.trim()).filter(Boolean);
      if (types.length) { conditions.push(`artifact_type = ANY($${idx++})`); vals.push(types); }
    }
    if (start_time) { conditions.push(`timestamp >= $${idx++}`); vals.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${idx++}`); vals.push(end_time); }

    const sql = `
      SELECT
        EXTRACT(HOUR FROM timestamp AT TIME ZONE 'UTC')::int        AS hour,
        EXTRACT(DOW  FROM timestamp AT TIME ZONE 'UTC')::int        AS weekday,
        COUNT(*)::int                                                AS count
      FROM collection_timeline
      WHERE ${conditions.join(' AND ')}
      GROUP BY hour, weekday
      ORDER BY weekday, hour
    `;
    const result = await req.app.locals.pool.query(sql, vals);

    const matrix = Array.from({ length: 7 }, () => new Array(24).fill(0));
    let maxCount = 0;
    for (const row of result.rows) {
      matrix[row.weekday][row.hour] = row.count;
      if (row.count > maxCount) maxCount = row.count;
    }
    res.json({ matrix, max_count: maxCount });
  } catch (err) {
    logger.error('[collection] GET heatmap:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/dead-time', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const threshold = Math.max(1, parseInt(req.query.threshold_hours) || 4);
  const limit = Math.min(50, parseInt(req.query.limit) || 20);
  try {
    const sql = `
      WITH ordered AS (
        SELECT timestamp, artifact_type, description, source,
               LEAD(timestamp) OVER (ORDER BY timestamp) AS next_ts
        FROM collection_timeline
        WHERE case_id = $1
      )
      SELECT
        timestamp                                            AS gap_start,
        next_ts                                              AS gap_end,
        EXTRACT(EPOCH FROM (next_ts - timestamp))/3600.0   AS gap_hours,
        artifact_type, description, source
      FROM ordered
      WHERE next_ts IS NOT NULL
        AND next_ts - timestamp > ($2 * INTERVAL '1 hour')
      ORDER BY gap_hours DESC
      LIMIT $3
    `;
    const result = await req.app.locals.pool.query(sql, [caseId, threshold, limit]);
    res.json({ gaps: result.rows, threshold_hours: threshold });
  } catch (err) {
    logger.error('[collection] GET dead-time:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/verdicts', authenticate, async (req, res) => {
  try {
    const result = await req.app.locals.pool.query(
      `SELECT id, event_ref, verdict, analyst_note, created_by, updated_at
       FROM artifact_verdicts WHERE case_id = $1`,
      [req.params.caseId]
    );
    res.json({ verdicts: result.rows });
  } catch (err) {
    res.json({ verdicts: [] });
  }
});

router.post('/:caseId/verdicts', authenticate, async (req, res) => {
  const { event_ref, verdict, analyst_note } = req.body;
  if (!event_ref || !verdict) return res.status(400).json({ error: 'event_ref and verdict required' });
  const VALID = ['malicious', 'suspicious', 'benign', 'unknown'];
  if (!VALID.includes(verdict)) return res.status(400).json({ error: 'Invalid verdict' });
  try {
    await req.app.locals.pool.query(`
      CREATE TABLE IF NOT EXISTS artifact_verdicts (
        id           BIGSERIAL PRIMARY KEY,
        case_id      UUID NOT NULL,
        event_ref    TEXT NOT NULL,
        verdict      TEXT NOT NULL,
        analyst_note TEXT,
        created_by   UUID,
        updated_at   TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(case_id, event_ref)
      )
    `);
    const result = await req.app.locals.pool.query(`
      INSERT INTO artifact_verdicts (case_id, event_ref, verdict, analyst_note, created_by)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (case_id, event_ref)
      DO UPDATE SET verdict = EXCLUDED.verdict, analyst_note = EXCLUDED.analyst_note,
                    created_by = EXCLUDED.created_by, updated_at = NOW()
      RETURNING *
    `, [req.params.caseId, event_ref, verdict, analyst_note || null, req.user?.userId || null]);
    res.json({ verdict: result.rows[0] });
  } catch (err) {
    logger.error('[collection] POST verdict:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:caseId/verdicts/:eventRef', authenticate, async (req, res) => {
  try {
    await req.app.locals.pool.query(
      `DELETE FROM artifact_verdicts WHERE case_id = $1 AND event_ref = $2`,
      [req.params.caseId, req.params.eventRef]
    );
    res.json({ ok: true });
  } catch { res.json({ ok: true }); }
});

module.exports = router;
module.exports.extractTimestamp = extractTimestamp;
module.exports.detectCollectionPlatform = detectCollectionPlatform;
