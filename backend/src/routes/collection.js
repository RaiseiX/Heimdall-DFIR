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
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const esService = require('../services/elasticsearchService');
const { esMayServe } = require('../services/timelineSource');
const { resolveArtifactStatus } = require('../services/artifactStatus');
const { getRedis } = require('../config/redis');
const logger = require('../config/logger').default;
const { matchTags: matchKeywordTags } = require('../services/timelineKeywords');
const { safeBasename } = require('../services/uploadService');
const { detectMapping, loadMappings } = require('../services/timelineMappings');
const { buildSlimRaw } = require('../services/timelineFieldExtract');
const { buildHayabusaDescription } = require('../services/hayabusaDescription');
const { pushTextFilter, pushSearchFilter } = require('../utils/textFilter');
const { fetchContext, AnchorNotFound } = require('../services/timelineContext');
const { diffTimelines } = require('../services/timelineDiff');
const { stripNullBytes, normalizeTimestamp, extractTimestamp, extractDescription } = require('../services/timelineNormalizeCore');
const { extractForensicFields } = require('../services/timelineForensicFields');
const { importCsvFile } = require('../services/csv/importCsvFile');
const { findCsvFilesRecursive } = require('../services/csv/findCsvFiles');
const { scanCollectionCsvs } = require('../services/csv/scanCollectionCsvs');
const { ZIMMERMAN_DIR, ARTIFACT_PATTERNS, ECS_COLUMNS } = require('../config/artifactPatterns');
const { purgeFsTimeline, purgeCatScaleState } = require('../services/fsTimelinePurge');
const { purgeHayabusaScoped, aggregateHayabusaMeta } = require('../services/hayabusaScope');
const { natureScopedWhere } = require('../services/timelineNature');
const { buildAggCacheKeys, invalidateAggCache } = require('../services/timelineAggCache');
const { foldHistogramRows, BKT_BEFORE_LO, BKT_AFTER_HI } = require('../services/timelineHistogramFold');
const { parseRule, buildQuery } = require('../services/sigmaService');
const { collectionHost, establishedHostsQuery, resolvedHostExpr } = require('../services/collectionHost');
const { rawProjection } = require('../services/timelineRawScope');
const { resolveArtifactType } = require('../services/artifactSubtype');
const { reparseScope } = require('../services/reparseScope');
const { commonParserDir } = require('../services/commonParserDir');
const { hitsOnlyPredicate } = require('../services/huntDetections');

const router = express.Router();

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
  'userassist', 'netprofile', 'usb', 'schtasks', 'pwsh', 'dns', 'webcache', 'pcap', 'wmi', 'rdpcache',
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
  if (data.type === 'artifact_start' && data.artifact) {
    if (!e.parsers[data.artifact]) e.parsers[data.artifact] = { status: 'queued', records: 0, name: data.name || data.artifact };
    e.parsers[data.artifact].status = 'parsing';
  }
  if (data.type === 'artifact_done' && data.artifact) {
    const st = data.status === 'success' ? 'done' : data.status === 'skipped' ? 'skipped' : 'error';
    e.parsers[data.artifact] = { ...(e.parsers[data.artifact] || { name: data.name || data.artifact }), status: st, records: data.records ?? 0 };
  }
  // Global % from the COUNT of finished parsers — robust to parallel start order.
  // (The event `current` is a start index, not a completion count, so it can't drive %.)
  const states = Object.values(e.parsers);
  const finished = states.filter(p => p.status === 'done' || p.status === 'skipped' || p.status === 'error').length;
  e.globalPct = states.length ? Math.round((finished / states.length) * 100) : 0;
  e.updatedAt = Date.now();
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
async function streamNormalizeToDB(csvPath, caseId, resultId, artifactType, config, evidenceId = null, sourceDevice = null) {
  try { fs.statSync(csvPath); } catch { return { rawCount: 0, normalized: 0, columns: [] }; }

  const rowArtifactType = resolveArtifactType(artifactType, csvPath);

  let batch = [];
  let rawCount = 0;
  let normalized = 0;
  let columns = [];
  const benchStart = Date.now();
  let pgMs = 0;

  const insertBatch = (rows) => {
    if (rows.length === 0) return Promise.resolve();
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
    return pool.query(
      `INSERT INTO collection_timeline
         (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
          host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic, source_device,
          tool, timestamp_kind, details, "path", ext, event_id, file_size, src_ip, dst_ip, sha1, dedupe_hash, tags, detections)
       SELECT u.case_id, u.result_id, u.evidence_id, u.ts, u.art_type, u.art_name, u.descr, u.src, u.rw,
              u.hn, u.un, u.pn, u.mti, u.mtn, u.mt, u.sd,
              u.tl, u.tk, u.dt, u.pth, u.ex, u.eid, u.fs, u.sip, u.dip, u.s1, u.dh,
              COALESCE(ARRAY(SELECT jsonb_array_elements_text(u.tg_json)), '{}')::text[],
              u.det
         FROM UNNEST(
           $1::uuid[], $2::uuid[], $3::uuid[], $4::timestamptz[], $5::text[], $6::text[], $7::text[], $8::text[], $9::jsonb[],
           $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[],
           $17::text[], $18::text[], $19::text[], $20::text[], $21::text[], $22::int[], $23::bigint[], $24::inet[], $25::inet[], $26::text[], $27::text[],
           $28::jsonb[], $29::jsonb[]
         ) AS u(case_id, result_id, evidence_id, ts, art_type, art_name, descr, src, rw,
                hn, un, pn, mti, mtn, mt, sd,
                tl, tk, dt, pth, ex, eid, fs, sip, dip, s1, dh, tg_json, det)
       ON CONFLICT DO NOTHING`,
      [caseIds, resultIds, evidenceIds, timestamps, artTypes, artNames, descriptions, sources, raws,
       hostNames, userNames, processNames, mitreTechIds, mitreTechNames, mitreTactics, sourceDevices,
       tools, tsKinds, detailsArr, paths, exts, eventIds, fileSizes, srcIps, dstIps, sha1s, dedupeHashes, tagsArr,
       detectionsArr],
    ).then(r => { pgMs += Date.now() - t0; return r; });
  };

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err) => { if (!settled) { settled = true; err ? reject(err) : resolve({ rawCount, normalized, columns }); } };

    const csvParser = parseStream({
      columns: true,
      skip_empty_lines: true,
      relax_column_count: true,
      encoding: 'utf8',
    });

    csvParser.on('data', (rawRecord) => {
      csvParser.pause();
      rawCount++;
      if (columns.length === 0) columns = Object.keys(rawRecord);

      const clean = stripNullBytes(rawRecord);
      const tsResult = extractTimestamp(clean, config.timestampColumns);
      if (!tsResult) { csvParser.resume(); return; }

      const slimRaw = buildSlimRaw(clean, artifactType);

      const ecs = extractEcsFields(clean, artifactType);
      let baseDesc = extractDescription(clean, config.descriptionColumns);
      // AmcacheParser KeyName format: "ProgramName|hexhash" — strip the hash suffix
      if (artifactType === 'amcache' && baseDesc && /\|[0-9a-f]{8,}$/i.test(baseDesc)) {
        baseDesc = baseDesc.replace(/\|[0-9a-f]{8,}$/i, '').trim();
      }
      let baseSource = clean[config.sourceColumn] || '';
      // amcache ShortCuts CSV has no ProgramName — fall back to LnkName path
      if (artifactType === 'amcache' && !baseSource && clean['LnkName']) {
        baseSource = clean['LnkName'];
      }
      const forensic = extractForensicFields(clean, artifactType, config, tsResult.column, baseDesc, baseSource);
      batch.push({
        timestamp:     tsResult.timestamp,
        artifact_type: rowArtifactType,
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
          if (!prevTs) continue;
          const prevDesc = `${execName} [previous run]`;
          const prevForensic = extractForensicFields(clean, 'prefetch', config, `PreviousRun${pi}`, prevDesc, baseSource);
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

        insertBatch(toFlush)
          .then(() => {
            normalized += toFlush.length;
            esService.bulkIndex(caseId, toFlush, resultId, evidenceId).catch(e =>
              logger.warn(`[ES] bulkIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
            csvParser.resume();
          })
          .catch(done);
      } else {
        csvParser.resume();
      }
    });

    csvParser.on('end', () => {
      const toFlush = batch;
      batch = [];
      insertBatch(toFlush)
        .then(() => {
          normalized += toFlush.length;
          esService.bulkIndex(caseId, toFlush, resultId, evidenceId).catch(e =>
            logger.warn(`[ES] bulkIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
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

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

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
        } else if (ext === '.zip') {
          try {
            await spawnTool(['unzip', '-o', '-q', uploadedPath, '-d', collectionDir], { timeout: 3600000 });
          } catch (unzipErr) {

            logger.warn('[collection] unzip failed, retrying with 7z:', unzipErr.message);
            await spawnTool(['7z', 'x', uploadedPath, `-o${collectionDir}`, '-y'], { timeout: 3600000 });
          }
        } else {
          await spawnTool(extractArgs(ext, uploadedPath, collectionDir), { timeout: 3600000 });
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

        await pool.query(
          `INSERT INTO evidence (case_id, name, original_filename, file_path, evidence_type, notes, added_by, metadata,
                                 hash_md5, hash_sha1, hash_sha256, file_size)
           VALUES ($1, $2, $3, $4, 'collection', $5, $6, $7, $8, $9, $10, $11)`,
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

// Current parse progress for a case — lets the UI re-attach the monitor after navigation.
router.get('/:caseId/parse-progress', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const e = PARSE_PROGRESS.get(caseId);
  if (!e) return res.json({ active: false, live: false, globalPct: 0, parsers: {} });
  const age = Date.now() - e.updatedAt;
  // A finished parse (explicit done flag or 100%) or a long-idle orphan is no
  // longer "active" — clear it so the cockpit doesn't linger as a frozen
  // snapshot after the job ends, dies, or is interrupted by navigation.
  if (e.done || e.globalPct >= 100 || age > 5 * 60 * 1000) {
    PARSE_PROGRESS.delete(caseId);
    return res.json({ active: false, live: false, globalPct: 0, parsers: {} });
  }
  res.json({ active: true, live: age < 15000, globalPct: e.globalPct, parsers: e.parsers });
});

// Event-density histogram of the case timeline — buckets for the live parsing sparkline.
// Bounds are clamped to a sane window so forensic junk timestamps (year 2069…) don't skew it.
router.get('/:caseId/timeline-histogram', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const N = Math.min(80, Math.max(12, parseInt(req.query.buckets, 10) || 48));
  // This sparkline aggregates the whole case timeline (can be millions of rows)
  // and is polled live during parsing. A dedicated client with a hard
  // statement_timeout guarantees a slow scan aborts instead of piling up into
  // zombie queries that exhaust the pool and block schema migrations / deletes.
  const client = await pool.connect();
  try {
    await client.query("SET statement_timeout = '8000'");

    // Bornes au 1er et au 99e centile, pas au minimum et au maximum.
    //
    // Mesuré le 2026-08-24 sur une collecte Windows : min/max donnaient
    // 2000-01-01 → 2035-01-01, soit 35 ans dont une date future, alors que 99,35 %
    // des lignes tenaient entre 2021 et 2026. Les six années portant l'enquête
    // occupaient 17 % de la barre. La garde `BETWEEN '1990' AND '2100'` n'y changeait
    // rien : les deux aberrations sont à l'intérieur.
    //
    // Par décalage sur idx_ct_case_ts, pas par percentile_disc : 0,6 ms contre
    // 1 392 ms sur 340 952 lignes. Ce point d'accès est sondé pendant le parsing,
    // sous un statement_timeout de 8 s.
    const cnt = await client.query(
      `SELECT COUNT(*)::int n FROM collection_timeline
        WHERE case_id = $1 AND timestamp IS NOT NULL`, [caseId]);
    const dated = cnt.rows[0]?.n || 0;
    const off = Math.floor(dated * 0.01);

    const bnd = await client.query(
      `SELECT
         (SELECT timestamp FROM collection_timeline
           WHERE case_id = $1 AND timestamp IS NOT NULL
           ORDER BY timestamp ASC OFFSET $2 LIMIT 1) AS lo,
         (SELECT timestamp FROM collection_timeline
           WHERE case_id = $1 AND timestamp IS NOT NULL
           ORDER BY timestamp DESC OFFSET $2 LIMIT 1) AS hi`, [caseId, off]);
    const lo = bnd.rows[0]?.lo || null;
    const hi = bnd.rows[0]?.hi || null;

    if (!lo || !hi) {
      return res.json({ buckets: [], total: dated, lo: null, hi: null, before_lo: 0, after_hi: 0 });
    }

    // Un seul balayage là où il y en avait deux. Le comptage par seau et le comptage
    // des hors-bornes lisaient exactement le même ensemble — le cas et ses 2,1 M
    // lignes datées — sur la même connexion, donc l'un après l'autre : node-postgres
    // sérialise les requêtes d'un client, un Promise.all n'y aurait rien changé.
    // Mesuré le 2026-08-26 : 2 320 ms pour les quatre requêtes de ce point d'accès.
    //
    // Comptées, jamais seulement écartées : l'écran les nomme aux extrémités de la
    // barre et l'analyste peut y aller. Les masquer serait le défaut que ce dépôt
    // corrige partout ailleurs.
    //
    // La frontière ne bouge pas. Le CASE teste `< lo` et `> hi` exactement comme le
    // faisait la requête supprimée. S'en remettre au 0 et au N+1 que `width_bucket`
    // rend déjà aurait décalé la borne haute d'une seconde, puisque celle qu'on lui
    // passe est `hi + 1` : une ligne à `hi + 0,5 s` serait tombée dans le dernier seau
    // au lieu d'être comptée au-dessus de la borne.
    //
    // Les deux sentinelles sont des constantes du module, jamais une valeur du client.
    const r = await client.query(
      `SELECT CASE
                WHEN timestamp < $3 THEN ${BKT_BEFORE_LO}
                WHEN timestamp > $4 THEN ${BKT_AFTER_HI}
                ELSE width_bucket(EXTRACT(EPOCH FROM timestamp),
                                  EXTRACT(EPOCH FROM $3::timestamptz),
                                  EXTRACT(EPOCH FROM $4::timestamptz) + 1, $2)
              END AS bkt,
              COUNT(*)::int AS n
         FROM collection_timeline
        WHERE case_id = $1 AND timestamp IS NOT NULL
        GROUP BY 1 ORDER BY 1`, [caseId, N, lo, hi]);

    const { buckets, before_lo, after_hi } = foldHistogramRows(r.rows, N);
    res.json({ buckets, total: dated, lo, hi, before_lo, after_hi });
  } catch (err) {
    logger.warn('[timeline-histogram]', err.message);
    res.json({ buckets: [], total: 0, lo: null, hi: null });
  } finally {
    // Clear the timeout before returning the connection to the pool so it
    // doesn't leak onto the next query that borrows this client.
    await client.query('RESET statement_timeout').catch(() => {});
    client.release();
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

router.post('/:caseId/parse', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const { collection_dir, artifact_types, types, evidence_id: bodyEvidenceId } = req.body;

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

  const typesToParse = requestedTypes === 'all'
    ? Object.keys(ARTIFACT_PATTERNS)
    : (Array.isArray(requestedTypes) ? requestedTypes : [requestedTypes]);

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
  let oldResultIds = [];
  let resultId;
  {
    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      const oldPrRows = await dbClient.query(
        `SELECT id FROM parser_results
         WHERE case_id = $1 AND input_file = $2 AND parser_name != 'MagnetRESPONSE_Import'
         FOR UPDATE`,
        [caseId, collDir]
      );
      oldResultIds = oldPrRows.rows.map(r => r.id);
      const scope = reparseScope(requestedTypes);
      if (oldResultIds.length > 0 && scope.full) {
        await dbClient.query(
          `DELETE FROM collection_timeline WHERE result_id = ANY($1::uuid[])`,
          [oldResultIds]
        );
        await dbClient.query(
          `DELETE FROM parser_results WHERE id = ANY($1::uuid[])`,
          [oldResultIds]
        );
      } else if (oldResultIds.length > 0 && scope.types.length > 0) {
        await dbClient.query(
          `DELETE FROM collection_timeline
            WHERE result_id = ANY($1::uuid[]) AND artifact_type = ANY($2::text[])`,
          [oldResultIds, scope.types]
        );
      }
      const prRow = await dbClient.query(
        `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
         VALUES ($1, $2, 'UnifiedTimeline', '2.0', $3, '{"status":"parsing"}'::jsonb, 0, $4) RETURNING id`,
        [caseId, evidenceId || null, collDir, req.user.id]
      );
      resultId = prRow.rows[0].id;
      await dbClient.query('COMMIT');
    } catch (initErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      dbClient.release();
      return res.status(500).json({ error: 'Erreur initialisation DB', details: initErr.message });
    }
    dbClient.release();
  }

  // ES cleanup outside the transaction — best-effort, non-blocking for the DB
  if (oldResultIds.length > 0) {
    for (const rid of oldResultIds) {
      await esService.deleteByResultId(caseId, rid).catch(e =>
        logger.warn(`[ES] deleteByResultId warn (${caseId}/${rid}): ${String(e.message).substring(0, 100)}`));
    }
  } else {
    await esService.ensureIndex(caseId).catch(e =>
      logger.warn(`[ES] ensureIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
  }

    res.json({ id: resultId, status: 'parsing' });

    (async () => {
      try {

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

        if (_pythonModuleAvailable('libscca') || _pythonModuleAvailable('pyscca')) {
          toolArgs = ['python3', '/app/parsers/parse_prefetch.py', '-d', pfDir, '--csv', outputDir, '--csvf', 'prefetch_results.csv'];
        } else if (fs.existsSync(pecmdDll)) {
          logger.warn('[parse] prefetch: libscca not available — falling back to dotnet PECmd.dll (Win10 LZXPRESS files may be skipped)');
          toolArgs = ['dotnet', pecmdDll, '-d', pfDir, '--csv', outputDir, '--csvf', 'prefetch_results.csv', '-q'];
        } else {

          toolArgs = ['python3', '/app/parsers/parse_prefetch.py', '-d', pfDir, '--csv', outputDir, '--csvf', 'prefetch_results.csv'];
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
          const pr = spawnSync('python3', ['/app/parsers/parse_pcap.py', '-d', collDir, '--csv', outputDir, '--csvf', 'pcap_results.csv'],
            { encoding: 'utf8', maxBuffer: 1 << 28, timeout: 1800000 });
          toolStdout = (pr.stdout || pr.stderr || '').slice(0, 1500);
          const csvPath = path.join(outputDir, 'pcap_results.csv');
          if (fs.existsSync(csvPath)) {
            const rows = fs.readFileSync(csvPath, 'utf8').split('\n').filter(Boolean);
            rows.shift(); // header
            for (const line of rows) {
              const c = line.split(',');
              if (c.length < 10 || !c[0] || !c[2]) continue;
              const toInt = v => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : 0; };
              await pool.query(
                `INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                [caseId, c[0], c[1] || null, c[2], c[3] || null, c[4] || null, toInt(c[5]), toInt(c[6]), toInt(c[7]), c[8] || null, c[9] || null]);
              inserted++;
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
          const pr = spawnSync('python3', ['/app/tools/bmc-tools.py', '-s', cacheDir, '-d', RDP_BASE, '-b'],
            { encoding: 'utf8', timeout: 600000 });
          toolStdout = (pr.stdout || pr.stderr || '').slice(0, 1500);
          count = fs.existsSync(RDP_BASE) ? fs.readdirSync(RDP_BASE).filter(f => /\.(bmp|png)$/i.test(f)).length : 0;
        } catch (e) { logger.warn('[rdpcache]', e.message); }
        results[artifactType] = { status: count > 0 ? 'ok' : 'empty', name: config?.name || 'RDP Bitmap Cache', records: count };
        toolArgs = null;
      } else if (isDirectory && DIRECTORY_MODE_PARSERS.includes(artifactType)) {

        let dirInput = commonParserDir(files, collDir) || path.dirname(files[0]);

        if (artifactType === 'lnk' && files.length > 1) {
          const recentFiles = files.filter(f => {
            const lower = f.toLowerCase();
            return !lower.includes('recycle') && (lower.includes('/recent/') || lower.includes('/lnk_files/'));
          });
          if (recentFiles.length > 0) {
            dirInput = commonParserDir(recentFiles, collDir) || path.dirname(recentFiles[0]);
          }
        }
        if (artifactType === 'evtx') {

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
          toolArgs = config.argsBuilder(dirInput, outputDir);
          if (config.toolEnv) toolEnv = { ...process.env, ...config.toolEnv };
        }
      } else {

        const bestFile = pickBestFile(files);
        if (artifactType === 'registry') {

          const batchCandidates = [
            path.join(ZIMMERMAN_DIR, 'BatchExamples', 'RECmd', 'BatchExamples', 'Kroll_Batch.reb'),
            path.join(ZIMMERMAN_DIR, 'BatchExamples', 'RECmd', 'BatchExamples', 'DFIRBatch.reb'),
            path.join(ZIMMERMAN_DIR, 'BatchExamples', 'RECmd_Batch_MC.reb'),
          ];
          const batchFile = batchCandidates.find(p => fs.existsSync(p)) || null;
          const regLines = [];
          for (let ri = 0; ri < files.length; ri++) {
            const hive = files[ri];
            const hname = path.basename(hive).replace(/[^a-zA-Z0-9._-]/g, '_');
            const csvf = `reg_${ri}_${hname}.csv`;
            const rcmdArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'RECmd.dll'), '-f', hive, '--csv', outputDir, '--csvf', csvf, '--recover', 'false'];
            if (batchFile) rcmdArgs.push('--bn', batchFile);
            try {
              const ro = await spawnTool(rcmdArgs, { timeout: 120000, maxBuffer: 1024 * 1024 * 128, cwd: outputDir });
              regLines.push(`${hname}: ${(ro || '').trim().split('\n').slice(-1)[0]?.substring(0, 120) || 'ok'}`);
            } catch (re) {
              const rmsg = ((re.stderr || '') + (re.stdout || '') + (re.message || '')).toString().substring(0, 150);
              regLines.push(`${hname}: ERR ${rmsg}`);
            }
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
        } else {
          toolArgs = config.argsBuilder(bestFile, outputDir);
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
      let csvRawCount = 0, csvNormCount = 0, firstCols = [];
      // Les fichiers dont l'insertion a été refusée. Sans cette liste, un échec
      // d'écriture laissait les compteurs à zéro et se présentait comme un CSV vide.
      const csvFailures = [];

      const csvT0 = Date.now();
      await runConcurrent(csvFiles, async (csvFilePath) => {
        // Global DB-write semaphore: bounds total concurrent inserts across all parsers.
        await dbWriteSem.acquire();
        try {
          const r = await streamNormalizeToDB(csvFilePath, caseId, resultId, artifactType, config, evidenceId, sourceDevice);
          csvRawCount  += r.rawCount;
          csvNormCount += r.normalized;
          if (firstCols.length === 0) firstCols = r.columns;
        } catch (streamErr) {
          // Full error inline so winston actually surfaces it (pg errors carry code/detail/where).
          logger.error(`[parse] Stream insert error ${artifactType}/${path.basename(csvFilePath)}: ` +
            `${streamErr.message || streamErr} | code=${streamErr.code || '?'}` +
            `${streamErr.detail ? ' | detail=' + String(streamErr.detail).slice(0, 200) : ''}` +
            `${streamErr.where ? ' | where=' + String(streamErr.where).slice(0, 150) : ''}`);
          // Retenu, pas seulement journalisé : c'est cette liste qui empêche l'échec
          // de se présenter plus bas comme un fichier vide. Journalisé en `error` et
          // non `warn` — le 2026-08-13 un avertissement d'une autre étape a défilé
          // sans être vu et douze artefacts sont passés pour vides pendant dix jours.
          csvFailures.push({
            file: path.basename(csvFilePath),
            reason: `${streamErr.message || streamErr}`.slice(0, 200),
            code: streamErr.code || null,
          });
        } finally {
          dbWriteSem.release();
        }
      }, 3);
      const csvMs = Date.now() - csvT0;
      const rps = csvMs > 0 ? Math.round(csvNormCount / (csvMs / 1000)) : 0;
      // Les échecs figurent dans la ligne de résumé. « 0 raw → 0 rows » sans mention
      // d'échec se lit « le fichier était vide » ; c'est ce qu'on a lu le 2026-08-24
      // pour un $MFT de 365 031 lignes dont l'insertion avait été refusée.
      const failNote = csvFailures.length
        ? ` | ${csvFailures.length} FICHIER(S) REFUSÉ(S): ${csvFailures.map(f => `${f.file} (${f.code || 'sans code'})`).join(', ')}`
        : '';
      logger.info(`[BENCH] ${artifactType} CSV→DB: ${csvFiles.length} files, ${csvRawCount} raw → ${csvNormCount} rows in ${csvMs}ms (${rps} rows/s, batch=${CT_DB_BATCH})${failNote}`);

      const artifactStatus = resolveArtifactStatus({
        toolError, normalized: csvNormCount, failures: csvFailures,
      });
      results[artifactType] = {
        status: artifactStatus,
        name: config.name,
        files_processed: files.length,
        raw_records: csvRawCount,
        normalized_records: csvNormCount,
        columns: firstCols,
        ...(toolError && csvNormCount === 0 ? { error: toolError } : {}),
        // Les refus d'insertion voyagent avec le résultat : la couverture et l'écran
        // doivent pouvoir nommer le fichier perdu, pas seulement en compter zéro.
        ...(csvFailures.length ? { csv_failures: csvFailures } : {}),
        // Le libellé suit la cause réelle. Il affirmait « fichier vide ou format non
        // reconnu » pour tout `degraded` ; depuis qu'un échec partiel produit aussi ce
        // statut, cette phrase aurait décrit un fichier refusé comme un fichier vide.
        ...(artifactStatus !== 'success' && csvFailures.length
          ? { warning: `${csvFailures.length} fichier(s) lus mais refusés à l'écriture — ${csvNormCount} ligne(s) écrite(s) sur ce type` }
          : artifactStatus === 'degraded'
            ? { warning: '0 événements parsés (fichier vide ou format non reconnu)' }
            : {}),
        ...(csvNormCount === 0 && toolStdout ? { tool_output: toolStdout.trim().split('\n').slice(-6).join(' | ').substring(0, 500) } : {}),
      };
      logger.info(`[parse] ${artifactType}: files=${files.length} csv_raw=${csvRawCount} normalized=${csvNormCount}`);
      emitProgress({ type: 'artifact_done', artifact: artifactType, name: config.name, status: results[artifactType].status, records: csvNormCount, current: myProgress, total: totalTypes });

      totalRecords += csvNormCount;

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
      const exhaustiveFsTimeline = req.body?.exhaustive_fs_timeline === true
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
    await pool.query(
      `UPDATE parser_results
         SET output_data   = $1,
             record_count  = $2,
             updated_at    = NOW()
       WHERE id = $3`,
      [
        JSON.stringify({ parse_results: results, artifact_types: typesToParse, total_records: totalRecords }),
        totalRecords,
        resultId,
      ]
    );

    // Les nouvelles lignes doivent etre visibles tout de suite : voir
    // services/timelineAggCache.ts, qui nomme les cles et sait donc les retrouver.
    await invalidateAggCache(getRedis(), caseId);

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

      io.to(`user:${req.user.id}`).emit('notification:job_done', {
        type: 'parse',
        caseId,
        status: 'done',
        message: `Parsing terminé : ${totalRecords.toLocaleString('fr-FR')} événements indexés`,
        total_records: totalRecords,
      });
    }
  } catch (dbErr) {
    logger.error('[collection] parse DB error:', dbErr.message);
    if (io) {
      if (socketId) io.to(socketId).emit('collection:parse:error', {
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
        logger.error('[collection] async parse error:', parseErr.message);
        if (io) {
          if (socketId) io.to(socketId).emit('collection:parse:error', {
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
        // The job has settled (done / DB-error / crash) — mark the progress
        // entry terminal so the live cockpit clears instead of lingering as a
        // frozen snapshot. The next /parse-progress poll returns active:false.
        const e = PARSE_PROGRESS.get(caseId);
        if (e) { e.done = true; e.updatedAt = Date.now(); }
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

// Is the Elasticsearch index complete enough to answer for this case?
//
// See src/services/timelineSource.js for why an index can hold a strict subset of
// Postgres. The two case-wide counts are cached together for five minutes: this only
// runs when an index exists at all, and the Postgres side is an index-only scan on
// idx_ct_case_ts. Any failure resolves to false — Postgres has everything, so falling
// back costs latency, while trusting a partial index costs rows.
async function esCanAnswerFor(caseId) {
  const key = `timeline:essource:${caseId}`;
  try {
    const redis = getRedis();
    if (redis) {
      const cached = await redis.get(key);
      if (cached !== null && cached !== undefined) return cached === '1';
    }
    const [es, pg] = await Promise.all([
      esService.searchTimeline(caseId, { page: 1, limit: 1 }),
      pool.query('SELECT COUNT(*)::int n FROM collection_timeline WHERE case_id = $1', [caseId]),
    ]);
    const ok = esMayServe(es?.total, pg.rows[0]?.n);
    if (!ok) {
      logger.info(`[timeline] ES bypassed for ${caseId}: index holds ${es?.total}, Postgres holds ${pg.rows[0]?.n}`);
    }
    try { if (redis) await redis.setex(key, 300, ok ? '1' : '0'); } catch (_e) {}
    return ok;
  } catch (e) {
    logger.warn(`[timeline] ES completeness check failed, using PG: ${String(e.message).substring(0, 100)}`);
    return false;
  }
}

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

    // Inventory rows (timestamp_kind = 'inventory') carry a NULL timestamp. Postgres
    // sorts NULLs first under DESC, so the default "most recent first" view would have
    // opened on 872,419 undated lsof lines with the actual chronology buried beneath
    // them. Every ORDER BY below therefore carries NULLS LAST in *both* directions:
    // an undated row is in the view and reachable, but never ahead of a dated one.
    //
    // The start_time / end_time filters need no such care — `timestamp >= x` is
    // unknown for NULL, so a time range already excludes inventory by construction.

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

    if (!host_name && !user_name && !hasAdvancedFilters) {
      try {
        const hasIndex = await esService.indexExists(caseId);
        if (hasIndex && await esCanAnswerFor(caseId)) {
          const esResult = await esService.searchTimeline(caseId, {
            page: pg, limit: lim, sort_dir, sort_col: safeCol,
            ...(safeSortMulti ? { sort_multi: safeSortMulti } : {}),
            artifact_types, search, start_time, end_time, result_id, evidence_id,
            evidence_ids: validatedEvidenceIds,
          });
          if (esResult.total > 0) {
            logger.info(`[timeline] ES hit: ${esResult.total} records (caseId=${caseId})`);
            if (Array.isArray(esResult.records)) esResult.records.forEach(hydrateTimelineRow);
            return res.json(esResult);
          }
        }
      } catch (esErr) {
        logger.warn(`[timeline] ES error, falling back to PG: ${String(esErr.message).substring(0, 100)}`);
      }
    }

    const conditions = ['case_id = $1'];
    const params     = [caseId];
    let   pi         = 2;

    let hostCol = 'host_name';
    let hostMachines = [];
    let hostEtablis = [];
    try {
      const hq = establishedHostsQuery(caseId);
      const hr = await pool.query(hq.text, hq.values);
      const parCollecte = new Map();
      for (const row of hr.rows) {
        if (!parCollecte.has(row.evidence_id)) parCollecte.set(row.evidence_id, []);
        parCollecte.get(row.evidence_id).push({ host: row.host, events: row.events });
      }
      const machines = [];
      for (const [evidence_id, obs] of parCollecte) {
        const seule = collectionHost(obs);
        if (seule) machines.push({ evidence_id, host: seule.host });
      }
      const etablis = [...new Set(hr.rows.map(r => String(r.host)))];
      const filtreHote = Boolean(host_name || host_name_op === 'empty' || host_name_op === 'not_empty');
      const expr = resolvedHostExpr(machines, etablis, pi);
      if (expr.params.length) {
        hostMachines = machines;
        hostEtablis = etablis;
        if (filtreHote) {
          hostCol = expr.sql;
          params.push(...expr.params);
          pi += expr.params.length;
        }
      }
    } catch { hostCol = 'host_name'; hostMachines = []; hostEtablis = []; }

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
      pi = pushTextFilter(hostCol, host_name || '', host_name_op, pi, conditions, params);
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
      conditions.push(hitsOnlyPredicate());
    }
    if (detection_severity && /^(greyware|low|medium|high|critical)(,(greyware|low|medium|high|critical))*$/.test(String(detection_severity))) {
      const sevList = String(detection_severity).split(',');
      conditions.push(`detections @? ('$[*] ? (@.severity == "' || ANY($${pi}::text[]) || '")')::jsonpath IS NOT NULL`);
      // Simpler + safer form using containment:
      conditions.pop();
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

    // Filtre de nature, applique aux lignes rendues et non au comptage : voir
    // services/timelineNature.ts pour la regle et ses tests.
    const whereRows = natureScopedWhere(where, req.query.nature);

    // Deux caches, parce que les agregats n'ont pas les memes dependances : hotes et
    // utilisateurs sont interroges avec [caseId] seul, la facette des types avec le
    // `where` complet. Voir services/timelineAggCache.ts pour le defaut mesure que
    // cette separation corrige — une cle unique rendait la facette d'un filtre sur
    // la vue non filtree du meme cas.
    const { dimensions: dimsKey, facets: facetsKey } = buildAggCacheKeys(caseId, where, params);
    let cachedFacets = null; // [{ artifact_type, cnt }]
    let cachedDims   = null; // { hosts, users }
    try {
      const redis = getRedis();
      if (redis) {
        const [rawFacets, rawDims] = await redis.mget(facetsKey, dimsKey);
        if (rawFacets) cachedFacets = JSON.parse(rawFacets);
        if (rawDims)   cachedDims   = JSON.parse(rawDims);
      }
    } catch (_e) {}

    // `undated` sort du même agrégat que `total` : sur une table de 1,2 million de
    // lignes ce compte tourne à chaque page, et une seconde requête doublerait le coût
    // pour une information que la première connaît déjà.
    //
    // Il existe parce que l'en-tête annonçait « 1 213 366 events » alors que 872 414 de
    // ces lignes sont des objets d'inventaire sans horodatage. La ligne dit sa nature
    // depuis la cellule DateTime vide et sa colonne Type TS ; le total, lui, les fondait
    // toutes dans le même mot. Les deux branches le portent, sinon activer le
    // dédoublonnage ferait réapparaître le compte fondu.
    const countSql = collapseDupes
      ? `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE ts IS NULL)::int AS undated
           FROM (
             SELECT DISTINCT ON (COALESCE(dedupe_hash, id::text))
                    COALESCE(dedupe_hash, id::text) AS k, timestamp AS ts
               FROM collection_timeline WHERE ${where}
           ) d`
      : `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE timestamp IS NULL)::int AS undated
           FROM collection_timeline WHERE ${where}`;

    const projExpr = resolvedHostExpr(hostMachines, hostEtablis, pi + 2);
    const hostProj = projExpr.params.length ? projExpr.sql : 'host_name';

    const rawCol = rawProjection(artifact_types);

    const rowsSql = collapseDupes
      ? `SELECT DISTINCT ON (COALESCE(dedupe_hash, id::text))
                id, timestamp, artifact_type, artifact_name, description, source,
                ${hostProj} AS host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections${rawCol}
           FROM collection_timeline
          WHERE ${whereRows}
          ORDER BY COALESCE(dedupe_hash, id::text),
                   array_length(tags, 1) DESC NULLS LAST,
                   length(COALESCE(description, '')) DESC,
                   ${safeCol} ${direction} NULLS LAST
          LIMIT $${pi} OFFSET $${pi + 1}`
      : `SELECT id, timestamp, artifact_type, artifact_name, description, source,
                ${hostProj} AS host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
                tool, timestamp_kind, details, "path", ext, event_id, file_size,
                src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1, tags, detections${rawCol}
           FROM collection_timeline
          WHERE ${whereRows}
          ORDER BY ${safeCol} ${direction} NULLS LAST, id ${direction}
          LIMIT $${pi} OFFSET $${pi + 1}`;

    const baseQueries = [
      pool.query(countSql, params),
      pool.query(rowsSql, [...params, lim, offset, ...projExpr.params]),
    ];

    // Chaque agregat absent du cache est ajoute a la volee et son rang retenu. Les
    // deux caches se ratent independamment : supposer une position fixe dans
    // `results` rendrait la facette a la place des hotes des que l'un des deux
    // repondrait seul.
    const slot = {};
    if (!cachedFacets) {
      slot.facets = baseQueries.length;
      baseQueries.push(
        pool.query(`SELECT artifact_type, COUNT(*)::int AS cnt FROM collection_timeline WHERE ${where} GROUP BY artifact_type ORDER BY artifact_type`, params)
      );
    }
    if (!cachedDims) {
      slot.dims = baseQueries.length;
      baseQueries.push(
        (() => {
          const fx = resolvedHostExpr(hostMachines, hostEtablis, 2);
          const col = fx.params.length ? fx.sql : 'host_name';
          return pool.query(
            `SELECT DISTINCT h AS host_name FROM (
               SELECT ${col} AS h FROM collection_timeline WHERE case_id = $1 AND host_name IS NOT NULL
             ) d WHERE h IS NOT NULL ORDER BY h LIMIT 100`,
            [caseId, ...fx.params]);
        })(),
        pool.query(`SELECT DISTINCT user_name FROM collection_timeline WHERE case_id = $1 AND user_name IS NOT NULL ORDER BY user_name LIMIT 100`, [caseId])
      );
    }

    const results = await Promise.all(baseQueries);
    const countRes = results[0];
    const rowsRes  = results[1];

    const typesRes = { rows: cachedFacets ?? results[slot.facets].rows };
    const hostsRes = { rows: cachedDims ? cachedDims.hosts : results[slot.dims].rows };
    const usersRes = { rows: cachedDims ? cachedDims.users : results[slot.dims + 1].rows };

    try {
      const redis = getRedis();
      if (redis) {
        const writes = [];
        if (!cachedFacets) writes.push(redis.setex(facetsKey, 300, JSON.stringify(typesRes.rows)));
        if (!cachedDims)   writes.push(redis.setex(dimsKey,   300, JSON.stringify({ hosts: hostsRes.rows, users: usersRes.rows })));
        if (writes.length) await Promise.all(writes);
      }
    } catch (_e) {}

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
    res.write(`,"undated":${countRes.rows[0].undated ?? 0}`);
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
    const groupSelect = groupCols.map((c, i) => `${c === 'host_name' ? '__HOSTCOL__' : c} AS k${i}`).join(', ');
    const groupBy     = groupCols.join(', ');
    const besoinHote  = groupCols.includes('host_name')
      || Boolean(host_name || host_name_op === 'empty' || host_name_op === 'not_empty');

    // Build WHERE clause — same shape as GET /timeline, hunt_id included.
    const conditions = ['case_id = $1'];
    const params     = [caseId];
    let pi = 2;

    let hostColG = 'host_name';
    if (besoinHote) {
      try {
        const hq = establishedHostsQuery(caseId);
        const hr = await pool.query(hq.text, hq.values);
        const par = new Map();
        for (const row of hr.rows) {
          if (!par.has(row.evidence_id)) par.set(row.evidence_id, []);
          par.get(row.evidence_id).push({ host: row.host, events: row.events });
        }
        const machines = [];
        for (const [evidence_id, obs] of par) {
          const seule = collectionHost(obs);
          if (seule) machines.push({ evidence_id, host: seule.host });
        }
        const etablis = [...new Set(hr.rows.map(r => String(r.host)))];
        const expr = resolvedHostExpr(machines, etablis, pi);
        if (expr.params.length) {
          hostColG = expr.sql;
          params.push(...expr.params);
          pi += expr.params.length;
        }
      } catch { hostColG = 'host_name'; }
    }

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
      pi = pushTextFilter(hostColG, host_name || '', host_name_op, pi, conditions, params);
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
              id, timestamp, tool, event_id, artifact_type, ${hostColG} AS host_name, user_name,
              ext, mitre_technique_id, source, process_name
           FROM collection_timeline WHERE ${where}
           ORDER BY COALESCE(dedupe_hash, id::text)) ct`
      : `collection_timeline WHERE ${where}`;
    const fromClause = (dedupe === 'collapse' || dedupe === '1' || dedupe === 'true')
      ? `FROM ${fromExpr}`
      : `FROM ${fromExpr}`;

    // Quand le dedoublonnage est actif, le sous-select a deja resolu l'hote et ne
    // projette pas `evidence_id` : l'expression ne peut pas s'y appliquer une seconde
    // fois. Sinon elle s'applique ici, sur la table.
    const dedoublonne = (dedupe === 'collapse' || dedupe === '1' || dedupe === 'true');
    const groupSelectResolu = groupSelect.replace('__HOSTCOL__', dedoublonne ? 'host_name' : hostColG);
    const groupByResolu     = groupCols.map(c => (c === 'host_name' && !dedoublonne) ? hostColG : c).join(', ');

    const sql = `
      SELECT ${groupSelectResolu},
             COUNT(*)::bigint     AS cnt,
             MIN(timestamp)        AS first_ts,
             MAX(timestamp)        AS last_ts,
             (ARRAY_AGG(id ORDER BY timestamp))[1:3] AS sample_ids
      ${fromClause}
      GROUP BY ${groupByResolu}
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
    const r = await pool.query(
      `UPDATE collection_timeline ct
          SET tags = u.new_tags
         FROM UNNEST($1::bigint[], $2::jsonb[]) AS u(id, tags_json),
              LATERAL (SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(u.tags_json)), '{}')::text[] AS new_tags) x
        WHERE ct.id = u.id AND ct.case_id = $3`,
      [ids, tagsArr.map(a => JSON.stringify(a)), caseId]
    );
    res.json({ updated: r.rowCount });
  } catch (e) {
    logger.error('[tags] bulk error:', e.message);
    res.status(500).json({ error: 'bulk tag error' });
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
    await invalidateAggCache(getRedis(), caseId);

    res.json({ result_id: resultId, inserted: grandTotal, files: perFile });
  } catch (err) {
    logger.error('[csv-import] error:', err);
    for (const f of files) { try { fs.unlinkSync(f.path); } catch (_e) {} }
    res.status(500).json({ error: 'Erreur import CSV: ' + err.message });
  }
});

router.post('/:caseId/hayabusa', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
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

    // Atomic helper: lock → replace this collection's Hayabusa data → insert fresh result.
    // The purge is scoped to the collection being parsed, not to the case: a case can
    // hold several collections, and replacing one must never erase the detections of
    // the others. FOR UPDATE still blocks a concurrent run on the same collection.
    async function initHayabusaRecord(outputDataJson, recordCount = 0) {
      const dbClient = await pool.connect();
      try {
        await dbClient.query('BEGIN');
        const { timelineRows, resultIds: oldIds } =
          await purgeHayabusaScoped(dbClient, caseId, hayEvidenceId);
        if (timelineRows > 0) {
          logger.info(`[hayabusa] replacing ${timelineRows} detection row(s) from a previous run of this collection`);
        }
        const newRow = await dbClient.query(
          `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
           VALUES ($1, $2, 'Hayabusa', '2.x', $3, $4::jsonb, $5, $6) RETURNING id`,
          [caseId, hayEvidenceId, evtxParentDir, outputDataJson, recordCount, req.user.id]
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

      try {
        await spawnTool(hayArgs, { timeout: 3600000 });
      } catch (e) {
        // Capture stderr snippet for diagnostic even on failure
        hayStderrSnip = (e.stderr || e.message || '').substring(0, 400);
        throw e;
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

            const afi = p.AllFieldInfo || p.all_field_info;
            let hayDetails = null;
            if (afi && typeof afi === 'object') {
              hayDetails = Object.entries(afi)
                .filter(([, v]) => v !== null && v !== '' && v !== undefined)
                .map(([k, v]) => `${k}: ${String(v).slice(0, 200)}`)
                .join(' | ')
                .slice(0, 500) || null;
            } else if (typeof afi === 'string' && afi.trim()) {
              hayDetails = afi.slice(0, 500);
            }

            const userName    = p.UserName || p.SubjectUserName || p.TargetUserName || p.user_name || null;
            const processName = p.ProcessName || p.NewProcessName || p.Image || p.process_name || null;

            if (streamStats[lvl] !== undefined) streamStats[lvl]++;
            caseIds.push(caseId);            resultIds.push(streamResultId);
            evidenceIds.push(hayEvidenceId); timestamps.push(p.Timestamp || p.timestamp || null);
            artTypes.push('hayabusa');        artNames.push(p.RuleTitle || p.rule_title || 'Hayabusa');
            descs.push(desc);                sources.push(src);
            raws.push(JSON.stringify(p));
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
          truncated: false, stderr_snippet: hayStderrSnip || null,
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
           ORDER BY timestamp
           LIMIT 5000`,
          [caseId]
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
          const hayDetails = r.description ? r.description.slice(0, 500) : null;
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
  }
});

// GET /hayabusa — reads detections from collection_timeline (paginated, cursor-based)
// Never reads parser_results JSONB — safe for any volume of records.
router.get('/:caseId/hayabusa', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const limit  = Math.min(parseInt(req.query.limit) || 10000, 100000);
    const cursor = req.query.cursor || null; // BIGINT id cursor

    // One Hayabusa run per collection, so a case holds as many result rows as it
    // holds parsed collections. Reading a single row here while counting detections
    // case-wide below would put one collection's evtx count beside every
    // collection's detections.
    const meta = await pool.query(
      `SELECT output_data, record_count, created_at, id, evidence_id FROM parser_results
       WHERE case_id = $1 AND parser_name = 'Hayabusa'
       ORDER BY created_at DESC`,
      [caseId]
    );

    if (meta.rows.length === 0) {
      return res.json({ timeline: [], total_detections: 0, stats: { critical: 0, high: 0, medium: 0, low: 0 }, next_cursor: null });
    }

    const hayMeta = aggregateHayabusaMeta(meta.rows);

    // Read detections from collection_timeline — cursor-paginated by row id
    let ctQuery = `SELECT id, timestamp, artifact_name AS rule_title, description,
                          source, source AS channel,
                          raw, host_name AS computer, user_name, process_name,
                          mitre_technique_id AS mitre_attack,
                          mitre_tactic AS tactic, event_id, details, tags,
                          COALESCE(raw->>'Level', raw->>'level') AS level,
                          COALESCE(raw->>'event_id', raw->>'EventID') AS event_id_raw
                   FROM collection_timeline
                   WHERE case_id = $1 AND artifact_type = 'hayabusa'`;
    const params = [caseId];
    if (cursor) {
      params.push(cursor);
      ctQuery += ` AND id > $${params.length}`;
    }
    params.push(limit);
    ctQuery += ` ORDER BY id ASC LIMIT $${params.length}`;

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
         WHERE case_id = $1 AND artifact_type = 'hayabusa'`,
        [caseId]
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
      evtx_files_count: hayMeta.evtxFilesCount,
      diagnostic:       hayMeta.diagnostic,
      generated_at:     hayMeta.generatedAt,
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
      conditions.push(`(description ILIKE $${pi} OR source ILIKE $${pi} OR artifact_type ILIKE $${pi})`);
      params.push('%' + search.replace(/[%_]/g, '\\$&') + '%');
      pi++;
    }
    if (start_time)  { conditions.push(`timestamp >= $${pi++}`);          params.push(start_time); }
    if (end_time)    { conditions.push(`timestamp <= $${pi++}`);          params.push(end_time);   }
    if (host_name)   { conditions.push(`host_name ILIKE $${pi++}`);       params.push('%' + host_name + '%'); }
    if (user_name)   { conditions.push(`user_name ILIKE $${pi++}`);       params.push('%' + user_name + '%'); }
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
    // Header names double as row keys below (`csvCell(row[c])`), so they must be the
    // column names Postgres actually returns.
    //
    // `ip_address` and `evidence_path` were named here and in the SELECT below, and
    // neither has ever existed on collection_timeline — the real columns are src_ip,
    // dst_ip, source_device and path. The query therefore threw, and the route
    // answered 500. It only fired when exactly one artifact type was requested, which
    // is to say whenever an analyst exported a filtered view; exporting everything
    // took the other branch and worked, which is why it went unnoticed.
    const extraCols = singleArtifact
      ? ['tool', 'event_id', 'ext', 'file_size', 'src_ip', 'dst_ip', 'sha1',
         'source_device', 'path', 'dedupe_hash', 'tags', 'detections']
      : [];

    const selectCols = singleArtifact
      ? `timestamp, artifact_type, artifact_name, source, description,
         host_name, user_name, process_name,
         mitre_tactic, mitre_technique_id, mitre_technique_name,
         tool, event_id, ext, file_size,
         src_ip::text AS src_ip, dst_ip::text AS dst_ip, sha1,
         source_device, "path", dedupe_hash,
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
    // The message goes in the message, not in the metadata: as `logger.error(tag, err)`
    // the cause landed outside `message` and the 500 left no readable trace in the log
    // stream — this failure was diagnosed from the source, not from the logs.
    logger.error(`[export csv] ${err?.message ?? err}`);
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
      if (host_name)  { conditions.push(`host_name ILIKE $${pi++}`); params.push(host_name); }
      if (user_name)  { conditions.push(`user_name ILIKE $${pi++}`); params.push(user_name); }
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
