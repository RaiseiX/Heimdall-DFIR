const express = require('express');
const { execSync, exec, spawnSync, spawn, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
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
const { getRedis } = require('../config/redis');
const logger = require('../config/logger').default;

const router = express.Router();
const ZIMMERMAN_DIR = process.env.ZIMMERMAN_TOOLS_DIR || '/app/zimmerman-tools';

pool.query(`
  CREATE TABLE IF NOT EXISTS collection_timeline (
    id            BIGSERIAL PRIMARY KEY,
    case_id       UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    result_id     UUID REFERENCES parser_results(id) ON DELETE CASCADE,
    evidence_id   UUID REFERENCES evidence(id) ON DELETE CASCADE,
    timestamp     TIMESTAMPTZ NOT NULL,
    artifact_type VARCHAR(50)  NOT NULL DEFAULT '',
    artifact_name VARCHAR(100) NOT NULL DEFAULT '',
    description   TEXT         NOT NULL DEFAULT '',
    source        VARCHAR(200) NOT NULL DEFAULT '',
    raw           JSONB        NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ  DEFAULT NOW()
  )
`).then(() => Promise.all([
  pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_case_ts    ON collection_timeline(case_id, timestamp)`),
  pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_case_type  ON collection_timeline(case_id, artifact_type)`),
  pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_result     ON collection_timeline(result_id)`),
  pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_evidence   ON collection_timeline(evidence_id)`),
  pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_case_ev_ts ON collection_timeline(case_id, evidence_id, timestamp)`),

  pool.query(`ALTER TABLE collection_timeline ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE CASCADE`),

  pool.query(`ALTER TABLE collection_timeline ADD COLUMN IF NOT EXISTS source_device VARCHAR(256)`),
])).catch(e => logger.warn('[collection] auto-migration warning:', e.message));
const COLLECTIONS_DIR = '/app/collections';
const TEMP_DIR = '/app/temp';

const WINDOWS_ONLY_PARSERS = new Set([]);

const PYTHON_FALLBACK_PARSERS = new Set(['prefetch', 'srum', 'sqle', 'wxtcmd']);

const LARGE_CSV_THRESHOLD = 30 * 1024 * 1024;

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
      cb(null, `${Date.now()}-${file.originalname}`);
    },
  }),
});

const ARTIFACT_PATTERNS = {
  evtx: {
    patterns: ['**/*.evtx', '**/winevt/Logs/*.evtx'],
    tool: 'EvtxECmd.dll',
    toolKey: 'evtx',
    name: 'Event Logs',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'EvtxECmd.dll'), '-d', input, '--csv', output, '--csvf', 'evtx_results.csv'],
    timestampColumns: ['TimeCreated', 'SystemTime'],
    descriptionColumns: ['MapDescription', 'PayloadData1'],
    sourceColumn: 'Channel',
  },
  prefetch: {
    patterns: ['**/Prefetch/*.pf', '**/*.pf'],
    tool: 'PECmd.dll',
    toolKey: 'prefetch',
    name: 'PECmd',
    argsBuilder: (input, output) => {
      const dir = fs.statSync(input).isDirectory() ? input : path.dirname(input);
      return ['dotnet', path.join(ZIMMERMAN_DIR, 'PECmd.dll'), '-d', dir, '--csv', output, '--csvf', 'prefetch_results.csv', '-q'];
    },
    timestampColumns: ['LastRun', 'SourceCreated', 'SourceModified'],
    descriptionColumns: ['ExecutableName'],
    sourceColumn: 'SourceFilename',
  },
  mft: {
    patterns: ['**/$MFT', '**/MFT/$MFT', '**/$MFT*'],
    tool: 'MFTECmd.dll',
    toolKey: 'mft',
    name: '$MFT',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'MFTECmd.dll'), '-f', input, '--csv', output, '--csvf', 'mft_results.csv'],
    timestampColumns: ['Created0x10', 'Created0x30', 'LastModified0x10', 'LastAccess0x10'],
    descriptionColumns: ['FileName'],
    sourceColumn: 'FolderPath',
  },
  lnk: {
    patterns: ['**/Recent/**/*.lnk', '**/*.lnk'],
    tool: 'LECmd.dll',
    toolKey: 'lnk',
    name: 'LNK Shortcuts',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'LECmd.dll'), '-d', input, '--csv', output, '--csvf', 'lnk_results.csv'],
    timestampColumns: ['SourceCreated', 'SourceModified', 'TargetCreated', 'TargetModified'],
    descriptionColumns: ['LocalPath', 'SourceFile'],
    sourceColumn: 'SourceFile',
  },
  registry: {
    patterns: ['**/config/SAM', '**/config/SECURITY', '**/config/SOFTWARE', '**/config/SYSTEM', '**/NTUSER.DAT', '**/UsrClass.dat'],
    tool: 'RECmd.dll',
    toolKey: 'registry',
    name: 'Registry Hives',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'RECmd.dll'), '-f', input, '--csv', output, '--csvf', 'registry_results.csv', '--bn', path.join(ZIMMERMAN_DIR, 'BatchExamples', 'RECmd_Batch_MC.reb')],
    timestampColumns: ['LastWriteTimestamp'],
    descriptionColumns: ['Description', 'ValueName'],
    sourceColumn: 'HivePath',
  },
  amcache: {
    patterns: ['**/Amcache.hve', '**/appcompat/Programs/Amcache.hve'],
    tool: 'AmcacheParser.dll',
    toolKey: 'amcache',
    name: 'Amcache',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'AmcacheParser.dll'), '-f', input, '--csv', output, '--csvf', 'amcache_results.csv'],
    timestampColumns: ['FileKeyLastWriteTimestamp', 'LinkDate'],
    descriptionColumns: ['FileDescription', 'FullPath', 'ProgramName'],
    sourceColumn: 'ProgramName',
  },
  appcompat: {
    patterns: ['**/config/SYSTEM', '**/SYSTEM'],
    tool: 'AppCompatCacheParser.dll',
    toolKey: 'appcompat',
    name: 'ShimCache (AppCompat)',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'AppCompatCacheParser.dll'), '-f', input, '--csv', output, '--csvf', 'shimcache_results.csv'],
    timestampColumns: ['LastModifiedTimeUTC', 'CacheEntryPosition'],
    descriptionColumns: ['Path'],
    sourceColumn: 'SourceFile',
  },
  shellbags: {
    patterns: ['**/UsrClass.dat', '**/NTUSER.DAT'],
    tool: 'SBECmd.dll',
    toolKey: 'shellbags',
    name: 'Shellbags',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'SBECmd.dll'), '-d', input, '--csv', output],
    timestampColumns: ['CreatedOn', 'ModifiedOn', 'AccessedOn', 'LastWriteTime'],
    descriptionColumns: ['AbsolutePath'],
    sourceColumn: 'AbsolutePath',
  },
  jumplist: {
    patterns: ['**/*.automaticDestinations-ms', '**/*.customDestinations-ms'],
    tool: 'JLECmd.dll',
    toolKey: 'jumplist',
    name: 'Jump Lists',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'JLECmd.dll'), '-d', input, '--csv', output, '--csvf', 'jumplist_results.csv'],
    timestampColumns: ['SourceCreated', 'SourceModified', 'TargetCreated', 'TargetModified'],
    descriptionColumns: ['AppIdDescription', 'LocalPath'],
    sourceColumn: 'SourceFile',
  },
  srum: {
    patterns: ['**/SRUDB.dat'],
    tool: 'SrumECmd.dll',
    toolKey: 'srum',
    name: 'SrumECmd',

    argsBuilder: (input, output) => ['python3', '/app/parsers/parse_srum.py', '-f', input, '--csv', output, '--csvf', 'srum_results.csv'],
    timestampColumns: ['Timestamp', 'ConnectStartTime'],
    descriptionColumns: ['ExeInfo'],
    sourceColumn: 'AppId',
  },
  wxtcmd: {
    patterns: ['**/ActivitiesCache.db'],
    tool: 'WxTCmd.dll',
    toolKey: 'wxtcmd',
    name: 'Windows Timeline',

    argsBuilder: (input, output) => {
      const dir = fs.statSync(input).isDirectory() ? input : path.dirname(input);
      return ['python3', '/app/parsers/parse_wxtcmd.py', '-d', dir, '--csv', output, '--csvf', 'wxtcmd_results.csv'];
    },
    timestampColumns: ['StartTime', 'EndTime', 'LastModifiedTime'],
    descriptionColumns: ['DisplayText', 'Description', 'AppId'],
    sourceColumn: 'AppId',
  },
  recycle: {
    patterns: ['**/$Recycle.Bin/**/$I*', '**/$I*'],
    tool: 'RBCmd.dll',
    toolKey: 'recycle',
    name: 'Recycle Bin ($I)',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'RBCmd.dll'), '-d', input, '--csv', output],
    timestampColumns: ['DeletedOn'],
    descriptionColumns: ['FileName'],
    sourceColumn: 'SourceName',
  },
  bits: {
    patterns: ['**/qmgr*.dat', '**/BITS/**'],
    tool: 'BitsParser.dll',
    toolKey: 'bits',
    name: 'BITS Jobs',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'BitsParser.dll'), '-f', input, '--csv', output],
    timestampColumns: ['CreationTime', 'ModifiedTime', 'CompletedTime'],
    descriptionColumns: ['JobName'],
    sourceColumn: 'TargetDirectory',
  },
  sum: {
    patterns: ['**/Current.mdb', '**/SystemIdentity.mdb'],
    tool: 'SumECmd.dll',
    toolKey: 'sum',
    name: 'User Access Logging',
    argsBuilder: (input, output) => ['dotnet', path.join(ZIMMERMAN_DIR, 'SumECmd.dll'), '-d', input, '--csv', output],
    timestampColumns: ['InsertDate', 'LastAccess'],
    descriptionColumns: ['UserName'],
    sourceColumn: 'UserName',
  },
  sqle: {

    patterns: ['**/History', '**/places.sqlite', '**/formhistory.sqlite',
               '**/downloads.sqlite', '**/cookies.sqlite'],
    tool: 'SQLECmd.dll',
    toolKey: 'sqle',
    name: 'Browser History',
    argsBuilder: (input, output) => ['python3', '/app/parsers/parse_sqle.py', '-d', input, '--csv', output, '--csvf', 'sqle_results.csv'],
    timestampColumns: ['LastVisitDate', 'VisitDate', 'StartTime'],
    descriptionColumns: ['Title', 'URL'],
    sourceColumn: 'SourceFile',
  },
};

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
};

const ECS_COLUMNS = {
  evtx:      { host: ['Computer'], user: ['SubjectUserName', 'TargetUserName', 'RemoteUserName', 'SourceUserName'], process: ['ProcessName', 'NewProcessName', 'Image'] },
  prefetch:  { host: [], user: [], process: ['ExecutableName'] },
  mft:       { host: [], user: [], process: ['FileName'] },
  lnk:       { host: ['MachineID', 'NetBiosMachineName'], user: [], process: ['Name', 'TargetFilenameLastPart'] },
  jumplist:  { host: ['MachineID', 'NetBiosMachineName'], user: [], process: ['AppId', 'AppIdDescription'] },
  shellbags: { host: [], user: [], process: ['Value', 'AbsolutePath'] },
  amcache:   { host: [], user: [], process: ['ProgramName', 'FullPath'] },
  appcompat: { host: [], user: [], process: ['Path'] },
  registry:  { host: [], user: ['UserName'], process: ['ValueName'] },
  srum:      { host: [], user: ['UserSid'], process: ['ExeInfo'] },
  sqle:      { host: [], user: ['Profile'], process: [] },
  wxtcmd:    { host: [], user: ['Sid'], process: ['AppId', 'DisplayText'] },
  recycle:   { host: [], user: [], process: ['FileName', 'SourceName'] },
  bits:      { host: [], user: [], process: ['JobName'] },
  sum:       { host: ['ClientName', 'ComputerName'], user: ['UserName', 'AuthenticatedUserName'], process: [] },
};

function extractEcsFields(record, artifactType) {
  const mitre = MITRE_MAP[artifactType] || {};
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

function normalizeTimestamp(value) {
  if (!value || value === '' || value === '(null)') return null;
  try {

    let cleaned = value.trim();

    if (cleaned.endsWith('Z')) cleaned = cleaned.slice(0, -1);

    if (cleaned.includes(' ') && !cleaned.includes('T')) {
      cleaned = cleaned.replace(' ', 'T');
    }

    const d = new Date(cleaned + 'Z');
    if (isNaN(d.getTime())) return null;

    const year = d.getUTCFullYear();
    if (year < 1980 || year > 2035) return null;
    return d.toISOString();
  } catch {
    return null;
  }
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

function findCsvFilesRecursive(dir) {
  const results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) results.push(...findCsvFilesRecursive(full));
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.csv')) results.push(full);
    }
  } catch (_e) {}
  return results;
}

const CT_DB_BATCH = 5000;
const PARSE_CONCURRENCY = 3;

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

    for (const rec of rows) {
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
    }

    const t0 = Date.now();
    return pool.query(
      `INSERT INTO collection_timeline
         (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
          host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic, source_device)
       SELECT * FROM UNNEST(
         $1::uuid[], $2::uuid[], $3::uuid[], $4::timestamptz[], $5::text[], $6::text[], $7::text[], $8::text[], $9::jsonb[],
         $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[]
       )`,
      [caseIds, resultIds, evidenceIds, timestamps, artTypes, artNames, descriptions, sources, raws,
       hostNames, userNames, processNames, mitreTechIds, mitreTechNames, mitreTactics, sourceDevices],
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

      const slimRaw = Object.fromEntries(Object.entries(clean).slice(0, 15));

      if (artifactType === 'evtx') {
        const eventId = parseInt(clean['EventId'] || clean['EventID'] || '0', 10);

        const NETWORK_EVENT_IDS = new Set([3, 22, 5156, 5158]);
        if (NETWORK_EVENT_IDS.has(eventId)) {

          const payload = [
            clean['PayloadData1'] || '', clean['PayloadData2'] || '',
            clean['PayloadData3'] || '', clean['PayloadData4'] || '',
          ].join(' ');

          const dstIpM = payload.match(/Destination(?:Ip|Address|\ Address)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i);
          if (dstIpM) slimRaw['DstIP'] = dstIpM[1];

          const dstPortM = payload.match(/Destination(?:Port|\ Port)[:\s]+(\d+)/i);
          if (dstPortM) slimRaw['DstPort'] = dstPortM[1];

          const hostM = payload.match(/(?:DestinationHostname|QueryName)[:\s]+([^\s,;]+)/i);
          if (hostM && hostM[1] !== '-') slimRaw['dst_host'] = hostM[1];
        }
      }

      const ecs = extractEcsFields(clean, artifactType);
      const baseDesc = extractDescription(clean, config.descriptionColumns);
      batch.push({
        timestamp:     tsResult.timestamp,
        artifact_type: artifactType,
        artifact_name: config.name,
        description:   baseDesc,
        source:        clean[config.sourceColumn] || '',
        raw:           slimRaw,
        ...ecs,
      });

      if (artifactType === 'prefetch') {
        const execName = clean['ExecutableName'] || baseDesc;
        for (let pi = 0; pi <= 6; pi++) {
          const prevVal = clean[`PreviousRun${pi}`];
          if (!prevVal || !prevVal.trim()) continue;
          const prevTs = normalizeTimestamp(prevVal.trim());
          if (!prevTs) continue;
          batch.push({
            timestamp:     prevTs,
            artifact_type: 'prefetch',
            artifact_name: config.name,
            description:   `${execName} [previous run]`,
            source:        clean[config.sourceColumn] || '',
            raw:           slimRaw,
            ...ecs,
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
    try { execSync(`which ${name}`, { stdio: 'ignore' }); cache[name] = true; }
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

function stripNullBytes(record) {
  const clean = {};
  for (const [k, v] of Object.entries(record)) {
    clean[k] = typeof v === 'string' ? v.replace(/\u0000/g, '') : v;
  }
  return clean;
}

function extractTimestamp(record, timestampColumns) {
  for (const col of timestampColumns) {
    if (record[col]) {
      const ts = normalizeTimestamp(record[col]);
      if (ts) return { timestamp: ts, column: col };
    }
  }

  for (const [key, val] of Object.entries(record)) {
    if (typeof val === 'string' && /\d{4}-\d{2}-\d{2}/.test(val)) {
      const ts = normalizeTimestamp(val);
      if (ts) return { timestamp: ts, column: key };
    }
  }
  return null;
}

function extractDescription(record, descriptionColumns) {
  for (const col of descriptionColumns) {
    const val = (record[col] || '').toString().trim();
    if (val && val !== '-' && val !== 'N/A') return val;
  }
  for (const val of Object.values(record)) {
    const s = (val || '').toString().trim();
    if (s && s !== '-' && s !== 'N/A') return s;
  }
  return '';
}

router.post('/:caseId/import', authenticate, upload.single('collection'), async (req, res) => {
  const { caseId } = req.params;

  const socketId = req.body?.socketId || null;
  const io = req.app.locals.io;
  const collectionDir = path.join(COLLECTIONS_DIR, `case-${caseId}-${Date.now()}`);

  try {

    const caseResult = await pool.query('SELECT id FROM cases WHERE id = $1', [caseId]);
    if (caseResult.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });

    if (!req.file) return res.status(400).json({ error: 'Aucun fichier uploadé' });

    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!['.zip', '.tar', '.gz', '.tgz', '.7z'].includes(ext)) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
      return res.status(400).json({ error: 'Format non supporté. Utilisez .zip, .tar.gz ou .7z' });
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

        if (ext === '.zip') {
          try {
            await spawnTool(['unzip', '-o', '-q', uploadedPath, '-d', collectionDir], { timeout: 3600000 });
          } catch (unzipErr) {

            logger.warn('[collection] unzip failed, retrying with 7z:', unzipErr.message);
            await spawnTool(['7z', 'x', uploadedPath, `-o${collectionDir}`, '-y'], { timeout: 3600000 });
          }
        } else if (ext === '.tar' || ext === '.gz' || ext === '.tgz') {
          await spawnTool(['tar', 'xzf', uploadedPath, '-C', collectionDir], { timeout: 3600000 });
        } else {
          await spawnTool(['7z', 'x', uploadedPath, `-o${collectionDir}`, '-y'], { timeout: 3600000 });
        }

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
          logger.warn('[CatScale] detection at import failed:', e.message);
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
              };
            }
          }
        }

        const collectionResult = await pool.query(
          `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
           VALUES ($1, 'MagnetRESPONSE_Import', '1.0', $2, $3, 0, $4) RETURNING id`,
          [caseId, collectionDir, JSON.stringify({ status: 'imported', detected: detectedArtifacts }), userId]
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
  }
  emitProgress({ type: 'start', total: totalTypes, artifacts: validTypes });

  const results = {};
  let totalRecords = 0;

  const oldPrRows = await pool.query(
    `SELECT id FROM parser_results WHERE case_id = $1 AND input_file = $2 AND parser_name != 'MagnetRESPONSE_Import'`,
    [caseId, collDir]
  );
  const oldResultIds = oldPrRows.rows.map(r => r.id);
  if (oldResultIds.length > 0) {

    await pool.query(
      `DELETE FROM collection_timeline WHERE result_id = ANY($1::uuid[])`,
      [oldResultIds]
    );

    for (const rid of oldResultIds) {
      await esService.deleteByResultId(caseId, rid).catch(e =>
        logger.warn(`[ES] deleteByResultId warn (${caseId}/${rid}): ${String(e.message).substring(0, 100)}`));
    }

    await pool.query(
      `DELETE FROM parser_results WHERE id = ANY($1::uuid[])`,
      [oldResultIds]
    );
  } else {

    await esService.ensureIndex(caseId).catch(e =>
      logger.warn(`[ES] ensureIndex warn (${caseId}): ${String(e.message).substring(0, 100)}`));
  }

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

  let resultId;
  try {
    const prRow = await pool.query(
      `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1, $2, 'UnifiedTimeline', '2.0', $3, '{"status":"parsing"}'::jsonb, 0, $4) RETURNING id`,
      [caseId, evidenceId || null, collDir, req.user.id]
    );
    resultId = prRow.rows[0].id;
  } catch (initErr) {
    return res.status(500).json({ error: 'Erreur initialisation DB', details: initErr.message });
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

    const outputDir = path.join(TEMP_DIR, `parse-${caseId}-${artifactType}-${Date.now()}`);
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

        if (artifactType === 'lnk' && files.length > 1) {
          const recentFiles = files.filter(f => {
            const lower = f.toLowerCase();
            return !lower.includes('recycle') && (lower.includes('/recent/') || lower.includes('/lnk_files/'));
          });
          if (recentFiles.length > 0) dirInput = path.dirname(recentFiles[0]);
        }
        if (artifactType === 'evtx') {

          let mapsDir = null;
          const mapsBase = path.join(ZIMMERMAN_DIR, 'Maps');
          if (fs.existsSync(mapsBase)) {
            const hasDirect = fs.readdirSync(mapsBase).some(f => f.endsWith('.map') || f.endsWith('.json'));
            const subDir = path.join(mapsBase, 'Maps');
            const hasSub = fs.existsSync(subDir) && fs.readdirSync(subDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            if (hasDirect) mapsDir = mapsBase;
            else if (hasSub) mapsDir = subDir;
          }
          const mapsFlag = mapsDir ? ` --maps "${mapsDir}"` : '';
          logger.info(`[parse] evtx maps: ${mapsDir || 'none found'}`);

          const evtxDirArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'EvtxECmd.dll'), '-d', dirInput, '--csv', '.'];
          if (mapsDir) evtxDirArgs.push('--maps', mapsDir);
          toolArgs = evtxDirArgs;
        } else {
          toolArgs = config.argsBuilder(dirInput, outputDir);
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
            const subDir = path.join(mapsBase, 'Maps');
            const hasSub = fs.existsSync(subDir) && fs.readdirSync(subDir).some(f => f.endsWith('.map') || f.endsWith('.json'));
            if (hasDirect) mapsDir = mapsBase;
            else if (hasSub) mapsDir = subDir;
          }
          const mapsFlag = mapsDir ? ` --maps "${mapsDir}"` : '';
          logger.info(`[parse] evtx single-file maps: ${mapsDir || 'none found'}`);
          const evtxFileArgs = ['dotnet', path.join(ZIMMERMAN_DIR, 'EvtxECmd.dll'), '-f', bestFile, '--csv', '.'];
          if (mapsDir) evtxFileArgs.push('--maps', mapsDir);
          toolArgs = evtxFileArgs;
        } else {
          toolArgs = config.argsBuilder(bestFile, outputDir);
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

      const csvT0 = Date.now();
      await runConcurrent(csvFiles, async (csvFilePath) => {
        try {
          const r = await streamNormalizeToDB(csvFilePath, caseId, resultId, artifactType, config, evidenceId, sourceDevice);
          csvRawCount  += r.rawCount;
          csvNormCount += r.normalized;
          if (firstCols.length === 0) firstCols = r.columns;
        } catch (streamErr) {
          logger.warn(`[parse] Stream insert error ${path.basename(csvFilePath)}:`, streamErr.message?.substring(0, 100));
        }
      }, 3);
      const csvMs = Date.now() - csvT0;
      const rps = csvMs > 0 ? Math.round(csvNormCount / (csvMs / 1000)) : 0;
      logger.info(`[BENCH] ${artifactType} CSV→DB: ${csvFiles.length} files, ${csvRawCount} raw → ${csvNormCount} rows in ${csvMs}ms (${rps} rows/s, batch=${CT_DB_BATCH})`);

      const artifactStatus = (toolError && csvNormCount === 0)
        ? 'error'
        : (csvNormCount === 0 && !toolError)
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
        ...(artifactStatus === 'degraded' ? { warning: '0 événements parsés (fichier vide ou format non reconnu)' } : {}),
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
      const csResult = await parseCatScale(catscaleRoot, caseId, pool, collectionTime, (p) => {
        if (socketId && io) io.to(socketId).emit('collection:progress', { ...p, artifact: 'catscale' });
      }, resultId);
      results['catscale'] = {
        status: 'ok',
        name: 'CatScale Linux IR',
        records: csResult.events,
        hostname: csResult.hostname,
        artifacts: csResult.artifacts,
      };
      totalRecords += csResult.events;
      emitProgress({ type: 'artifact_done', artifact: 'catscale', name: 'CatScale Linux IR', status: 'ok', records: csResult.events, current: totalTypes + 1, total: totalTypes + 1 });
      logger.info(`[CatScale] Detected and parsed: ${csResult.events} events from ${csResult.hostname}`);
    }
  } catch (e) {
    logger.warn('[CatScale] detection/parse error:', e.message);
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
      }
    })();
});

router.get('/:caseId/timeline', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { artifact_types, search, search_op = 'contains', start_time, end_time, host_name, user_name, result_id, evidence_id,
            evidence_ids,
            page = 1, limit = 200, sort_dir = 'asc', sort_col = 'timestamp',
            sort_multi } = req.query;

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

    if (!host_name && !user_name) {
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
            logger.info(`[timeline] ES hit: ${esResult.total} records (caseId=${caseId})`);
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

    if (artifact_types) {
      conditions.push(`artifact_type = ANY($${pi++})`);
      params.push(artifact_types.split(','));
    }
    if (search) {

      const safe = search.replace(/[%_]/g, '\\$&');
      if (search_op === 'equals') {
        conditions.push(`(description ILIKE $${pi} OR source ILIKE $${pi} OR artifact_type ILIKE $${pi})`);
        params.push(safe);
      } else if (search_op === 'starts_with') {
        conditions.push(`(description ILIKE $${pi} OR source ILIKE $${pi} OR artifact_type ILIKE $${pi})`);
        params.push(safe + '%');
      } else if (search_op === 'regex') {

        conditions.push(`(description ~* $${pi} OR source ~* $${pi} OR artifact_type ~* $${pi})`);
        params.push(search);
      } else {

        conditions.push(`(description ILIKE $${pi} OR source ILIKE $${pi} OR artifact_type ILIKE $${pi})`);
        params.push('%' + safe + '%');
      }
      pi++;
    }
    if (start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(start_time); }
    if (end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(end_time);   }
    if (host_name)   { conditions.push(`host_name ILIKE $${pi++}`);  params.push(host_name);  }
    if (user_name)   { conditions.push(`user_name ILIKE $${pi++}`);  params.push(user_name);  }
    if (result_id)   { conditions.push(`result_id = $${pi++}`);      params.push(result_id);  }
    if (evidence_id) { conditions.push(`evidence_id = $${pi++}`);    params.push(evidence_id); }
    if (validatedEvidenceIds) { conditions.push(`evidence_id = ANY($${pi++}::uuid[])`); params.push(validatedEvidenceIds); }

    const where = conditions.join(' AND ');

    const aggCacheKey = `timeline:aggs:${caseId}:${evidence_id || ''}:${(validatedEvidenceIds || []).join(',')}`;
    let cachedAggs = null;
    try {
      const redis = getRedis();
      if (redis) {
        const raw = await redis.get(aggCacheKey);
        if (raw) cachedAggs = JSON.parse(raw);
      }
    } catch (_e) {}

    const baseQueries = [
      pool.query(`SELECT COUNT(*)::int AS total FROM collection_timeline WHERE ${where}`, params),
      pool.query(
        `SELECT timestamp, artifact_type, artifact_name, description, source, raw,
                host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic
           FROM collection_timeline
          WHERE ${where}
          ORDER BY ${safeCol} ${direction}, id ${direction}
          LIMIT $${pi} OFFSET $${pi + 1}`,
        [...params, lim, offset]
      ),
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

    res.json({
      records:                  rowsRes.rows,
      total,
      page:                     pg,
      limit:                    lim,
      total_pages:              Math.ceil(total / lim),
      artifact_types_available: typesRes.rows.map(r => r.artifact_type),
      artifact_types_counts:    Object.fromEntries(typesRes.rows.map(r => [r.artifact_type, r.cnt])),
      hosts_available:          hostsRes.rows.map(r => r.host_name),
      users_available:          usersRes.rows.map(r => r.user_name),
    });
  } catch (err) {
    logger.error('Timeline fetch error:', err);
    res.status(500).json({ error: 'Erreur récupération timeline' });
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

router.post('/:caseId/hayabusa', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const HAYABUSA_BIN = process.env.HAYABUSA_BIN || '/app/hayabusa/hayabusa';

    const importRecord = await pool.query(
      `SELECT input_file FROM parser_results
       WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'
       ORDER BY created_at DESC LIMIT 1`,
      [caseId]
    );

    if (importRecord.rows.length === 0) {
      return res.status(400).json({ error: 'Aucune collecte importée pour ce cas. Importez d\'abord une collecte Magnet RESPONSE.' });
    }

    const collectionDir = importRecord.rows[0].input_file;
    if (!collectionDir || !fs.existsSync(collectionDir)) {
      return res.status(400).json({ error: 'Répertoire de collecte introuvable sur le disque. Ré-importez la collecte.' });
    }

    let hayEvidenceId = null;
    try {
      const evRow = await pool.query(
        `SELECT id FROM evidence WHERE case_id = $1 AND file_path = $2 LIMIT 1`,
        [caseId, collectionDir]
      );
      if (evRow.rows.length > 0) hayEvidenceId = evRow.rows[0].id;
    } catch (_e) {}

    const evtxFiles = findFiles(collectionDir, ['**/*.evtx', '**/winevt/Logs/*.evtx']);
    if (evtxFiles.length === 0) {
      return res.status(400).json({ error: 'Aucun fichier .evtx trouvé dans la collecte importée.' });
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
    const outputFile = path.join(TEMP_DIR, `hayabusa-${caseId}-${Date.now()}.jsonl`);

    let hayabusaRecords = [];

    try {

      if (!fs.existsSync(HAYABUSA_BIN)) throw new Error(`Hayabusa binary not found: ${HAYABUSA_BIN}`);

      const HAYABUSA_RULES_DIR = process.env.HAYABUSA_RULES_DIR || path.join(path.dirname(HAYABUSA_BIN), 'rules');
      const hayArgs = [
        HAYABUSA_BIN, 'json-timeline',
        '-d', evtxParentDir,
        '-o', outputFile,
        '--no-wizard', '-q',
        '-p', 'all-field-info',
      ];

      if (fs.existsSync(HAYABUSA_RULES_DIR)) {
        hayArgs.push('-r', HAYABUSA_RULES_DIR);
        logger.info(`[hayabusa] using rules dir: ${HAYABUSA_RULES_DIR}`);
      } else {
        logger.warn(`[hayabusa] rules dir not found (${HAYABUSA_RULES_DIR}) — using embedded rules`);
      }

      await spawnTool(hayArgs, {
        timeout: 3600000,
      });

      if (!fs.existsSync(outputFile) || fs.statSync(outputFile).size === 0) {
        throw new Error('Hayabusa produced no output (empty or missing file)');
      }

      await new Promise((resolve, reject) => {
        const rl = readline.createInterface({
          input: fs.createReadStream(outputFile, { encoding: 'utf-8' }),
          crlfDelay: Infinity,
        });
        rl.on('line', (line) => {
          if (!line.trim()) return;
          try {
            const parsed = JSON.parse(line);
            hayabusaRecords.push({
              timestamp: parsed.Timestamp || parsed.timestamp || null,
              artifact_type: 'hayabusa',
              artifact_name: 'Hayabusa',
              rule_title: parsed.RuleTitle || parsed.rule_title || '',
              level: (parsed.Level || parsed.level || 'informational').toLowerCase(),
              event_id: parsed.EventID || parsed.event_id || '',
              channel: parsed.Channel || parsed.channel || '',
              computer: parsed.Computer || parsed.computer || '',
              details: parsed.Details || parsed.details || '',
              mitre_attack: parsed.MitreTactics || parsed.mitre_tactics || '',
              rule_file: parsed.RuleFile || parsed.rule_file || '',
              description: `[${(parsed.Level || 'info').toLowerCase()}] ${parsed.RuleTitle || parsed.rule_title || ''}`,
              source: parsed.Channel || parsed.channel || '',
              raw: parsed,
            });
          } catch (_e) {}
        });
        rl.on('close', resolve);
        rl.on('error', reject);
      });
      fs.unlinkSync(outputFile);
      logger.info(`[hayabusa] binary OK — ${hayabusaRecords.length} detections`);
    } catch (execErr) {
      logger.warn('[hayabusa] binary failed or produced no output — using sigma fallback:', execErr.message?.substring(0, 150));

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
        { title: 'Suspicious PowerShell Download Cradle', level: 'high', match: /invoke-webrequest|downloadstring|invoke-expression|iex\s*\(/i, mitre: 'T1059.001', tactic: 'Execution' },
        { title: 'CobaltStrike Beacon Detection', level: 'critical', match: /cobaltstrike|cobalt\s*strike|beacon/i, mitre: 'T1055', tactic: 'Defense Evasion' },
        { title: 'Privilege Escalation via Token Manipulation', level: 'critical', match: /sedebugprivilege|seimpersonateprivilege/i, mitre: 'T1134', tactic: 'Privilege Escalation' },
        { title: 'DNS Tunneling Detected', level: 'high', match: /malware-c2|\.onion|high\s*entropy|dns.*tunnel/i, mitre: 'T1071.004', tactic: 'Command and Control' },
        { title: 'Suspicious Service Installation', level: 'high', match: /service was installed|new service|7045/i, mitre: 'T1543.003', tactic: 'Persistence' },
        { title: 'Security Audit Log Cleared', level: 'critical', match: /log was cleared|1102.*security|event\s*log.*clear/i, mitre: 'T1070.001', tactic: 'Defense Evasion' },
        { title: 'Scheduled Task Created by Non-Admin', level: 'medium', match: /scheduled task.*created|schtasks|4698/i, mitre: 'T1053.005', tactic: 'Persistence' },
        { title: 'Firewall Rule Modified', level: 'medium', match: /firewall rule|2004.*firewall/i, mitre: 'T1562.004', tactic: 'Defense Evasion' },
        { title: 'RDP Lateral Movement', level: 'high', match: /rdp.*logon|1149.*terminal|mstsc/i, mitre: 'T1021.001', tactic: 'Lateral Movement' },
        { title: 'Account Lockout (Brute Force)', level: 'medium', match: /account.*locked|4740/i, mitre: 'T1110', tactic: 'Credential Access' },
        { title: 'Suspicious Encoded PowerShell', level: 'high', match: /-enc[o]?[d]?\s|frombase64string|encodedcommand/i, mitre: 'T1059.001', tactic: 'Execution' },
        { title: 'Process Injection Indicators', level: 'critical', match: /virtualalloc|writeprocessmemory|createremotethread|ntmapviewofsection/i, mitre: 'T1055', tactic: 'Defense Evasion' },
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
    }

    hayabusaRecords.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const storeResult = await pool.query(
      `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1, 'Hayabusa', '2.x', $2, $3, $4, $5) RETURNING id`,
      [caseId, evtxParentDir, JSON.stringify({
        hayabusa_timeline: hayabusaRecords,
        evtx_dir: evtxParentDir,
        evtx_files_count: evtxFiles.length,
        stats: {
          critical: hayabusaRecords.filter(r => r.level === 'critical').length,
          high: hayabusaRecords.filter(r => r.level === 'high').length,
          medium: hayabusaRecords.filter(r => r.level === 'medium').length,
          low: hayabusaRecords.filter(r => r.level === 'low').length,
        },
      }), hayabusaRecords.length, req.user.id]
    );

    await pool.query(
      `DELETE FROM collection_timeline WHERE case_id = $1 AND artifact_type = 'hayabusa'`,
      [caseId]
    );
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

          vals.push(`($${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++},$${pi++})`);
          prms.push(
            caseId,
            storeResult.rows[0].id,
            hayEvidenceId,
            r.timestamp,
            'hayabusa',
            r.rule_title || 'Hayabusa',
            r.description || '',
            r.source || r.channel || '',
            JSON.stringify({ level: r.level, event_id: r.event_id, channel: r.channel, rule_file: r.rule_file }),
            r.computer || null,
            null,
            null,
            mitreId,
            mitreName,
            mitreTactic,
          );
        }
        await pool.query(
          `INSERT INTO collection_timeline
             (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
              host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic)
           VALUES ${vals.join(',')}`,
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
      esService.bulkIndex(caseId, ctRows, storeResult.rows[0].id, hayEvidenceId).then(res => {
        if (res?.errors) {
          const failed = (res.items || []).filter(i => i.index?.error);
          if (failed.length) logger.warn(`[ES] hayabusa bulkIndex: ${failed.length} item errors`, failed[0]?.index?.error);
        }
      }).catch(e =>
        logger.warn('[ES] hayabusa bulkIndex warn:', e.message?.substring(0, 100))
      );
    }

    await auditLog(req.user.id, 'run_hayabusa', 'collection', storeResult.rows[0].id,
      { evtx_count: evtxFiles.length, detections: hayabusaRecords.length }, req.ip);

    res.json({
      id: storeResult.rows[0].id,
      total_detections: hayabusaRecords.length,
      stats: {
        critical: hayabusaRecords.filter(r => r.level === 'critical').length,
        high: hayabusaRecords.filter(r => r.level === 'high').length,
        medium: hayabusaRecords.filter(r => r.level === 'medium').length,
        low: hayabusaRecords.filter(r => r.level === 'low').length,
      },
      evtx_files_processed: evtxFiles.length,
      timeline: hayabusaRecords,
    });
  } catch (err) {
    logger.error('Hayabusa error:', err);
    res.status(500).json({ error: 'Erreur exécution Hayabusa' });
  }
});

router.get('/:caseId/hayabusa', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT output_data, record_count, created_at FROM parser_results
       WHERE case_id = $1 AND parser_name = 'Hayabusa'
       ORDER BY created_at DESC LIMIT 1`,
      [req.params.caseId]
    );

    if (result.rows.length === 0) {
      return res.json({ timeline: [], total_detections: 0, stats: { critical: 0, high: 0, medium: 0, low: 0 } });
    }

    const data = result.rows[0].output_data;
    res.json({
      timeline: data.hayabusa_timeline || [],
      total_detections: result.rows[0].record_count,
      stats: data.stats || {},
      evtx_files_count: data.evtx_files_count || 0,
      generated_at: result.rows[0].created_at,
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
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

    const result = await pool.query(
      `SELECT timestamp, artifact_type, artifact_name, source, description,
              host_name, user_name, process_name,
              mitre_tactic, mitre_technique_id, mitre_technique_name
       FROM collection_timeline
       WHERE ${conditions.join(' AND ')}
       ORDER BY timestamp ASC`,
      params
    );

    const COLS = ['timestamp', 'artifact_type', 'artifact_name', 'source', 'description',
                  'host_name', 'user_name', 'process_name',
                  'mitre_tactic', 'mitre_technique_id', 'mitre_technique_name'];

    function csvCell(v) {
      const s = v == null ? '' : String(v);
      if (s.includes(sep) || s.includes('"') || s.includes('\n') || s.includes('\r')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    }

    const filename = `timeline-${caseId}-${Date.now()}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.write('\uFEFF'); // UTF-8 BOM (Excel compatibility)
    res.write(COLS.join(sep) + '\r\n');
    for (const row of result.rows) {
      res.write(COLS.map(c => csvCell(row[c])).join(sep) + '\r\n');
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
