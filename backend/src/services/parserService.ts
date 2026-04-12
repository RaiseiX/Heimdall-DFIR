
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import readline from 'readline';
import { parse as csvParseSync } from 'csv-parse/sync';
import type { Server as IOServer } from 'socket.io';
import type { Pool } from 'pg';
import type {
  ZimmermanTool,
  ParserRunConfig,
  ParserStatusEvent,
  ParserLogEvent,
} from '../types/index';
import { safePath } from './uploadService';

const ZIMMERMAN_DIR =
  process.env.ZIMMERMAN_TOOLS_DIR || '/app/zimmerman-tools';
const TEMP_DIR = '/app/temp';
const DOTNET_BIN = 'dotnet';
const HAYABUSA_BIN =
  process.env.HAYABUSA_BIN || '/app/hayabusa/hayabusa';

export const ZIMMERMAN_TOOLS: Record<string, ZimmermanTool> = {
  mft:      { dll: 'MFTECmd.dll',             name: 'MFTECmd',              description: 'Parse $MFT (Master File Table)',              extensions: ['.mft', '$mft'] },
  prefetch: { dll: 'PECmd.dll',               name: 'PECmd',                description: 'Parse Windows Prefetch files (.pf)',          extensions: ['.pf'] },
  lnk:      { dll: 'LECmd.dll',               name: 'LECmd',                description: 'Parse Windows LNK (shortcut) files',         extensions: ['.lnk'] },
  shellbags:{ dll: 'SBECmd.dll',              name: 'SBECmd',               description: 'Parse Shellbags',                            extensions: [] },
  amcache:  { dll: 'AmcacheParser.dll',       name: 'AmcacheParser',        description: 'Parse Amcache.hve',                          extensions: ['.hve'] },
  appcompat:{ dll: 'AppCompatCacheParser.dll',name: 'AppCompatCacheParser', description: 'Parse AppCompatCache (ShimCache)',            extensions: [] },
  evtx:     { dll: 'EvtxECmd.dll',            name: 'EvtxECmd',             description: 'Parse Windows Event Logs (.evtx)',           extensions: ['.evtx'] },
  registry: { dll: 'RECmd.dll',               name: 'RECmd',                description: 'Parse Windows Registry hives (SAM, SYSTEM, NTUSER.DAT)', extensions: ['.dat', '.hve'] },
  jumplist: { dll: 'JLECmd.dll',              name: 'JLECmd',               description: 'Parse Jump Lists',                           extensions: ['.automaticDestinations-ms'] },
  srum:     { dll: 'SrumECmd.dll',            name: 'SrumECmd',             description: 'Parse SRUM database (app/network usage)',    extensions: ['.dat'] },
  sqle:     { dll: 'SQLECmd.dll',             name: 'SQLECmd',              description: 'Parse browser SQLite DBs (Chrome, Firefox, Edge history/cookies)', extensions: ['.sqlite', '.db'] },
  wxtcmd:   { dll: 'WxTCmd.dll',              name: 'WxTCmd',               description: 'Parse Windows Timeline (ActivitiesCache.db)', extensions: ['.db'] },
  recycle:  { dll: 'RBCmd.dll',               name: 'RBCmd',                description: 'Parse Recycle Bin $I files',                 extensions: [] },
  bits:     { dll: 'BitsParser.dll',          name: 'BitsParser',           description: 'Parse BITS job database',                    extensions: ['.dat'] },
  sum:      { dll: 'SumECmd.dll',             name: 'SumECmd',              description: 'Parse User Access Logging (SUMdb)',          extensions: ['.mdb'] },
  hayabusa: { dll: '',                         name: 'Hayabusa',             description: 'Threat hunting on EVTX logs (Sigma rules)',  extensions: ['.evtx'] },
};

const DIRECTORY_PARSERS = new Set(['evtx', 'prefetch', 'lnk', 'jumplist', 'shellbags', 'sqle']);

function buildZimmermanArgs(
  dllPath: string,
  inputFile: string,
  outputDir: string,
  parser: string,
  extraArgs: Record<string, string> = {}
): string[] {

  const isDir = fs.existsSync(inputFile) && fs.statSync(inputFile).isDirectory();
  const inputFlag = (isDir && DIRECTORY_PARSERS.has(parser)) ? '-d' : '-f';

  const base = parser === 'evtx'
    ? [dllPath, inputFlag, inputFile, '--csv', outputDir]
    : [dllPath, inputFlag, inputFile, '--csv', outputDir, '--csvf', 'output.csv'];

  if (parser === 'evtx') {

    const mapsBase = path.join(ZIMMERMAN_DIR, 'Maps');
    if (fs.existsSync(mapsBase)) {
      const hasDirect = fs.readdirSync(mapsBase).some((f) => f.endsWith('.map') || f.endsWith('.json'));
      const subDir = path.join(mapsBase, 'Maps');
      const hasSub = fs.existsSync(subDir) && fs.readdirSync(subDir).some((f) => f.endsWith('.map') || f.endsWith('.json'));
      const mapsDir = hasDirect ? mapsBase : hasSub ? subDir : null;
      if (mapsDir) base.push('--maps', mapsDir);
    }
  }
  if (parser === 'registry' && extraArgs['maps']) {
    base.push('--bn', extraArgs['maps']);
  }

  if (parser === 'sqle') {

    base.push('--hunt');
    const sqlMapsDir = path.join(ZIMMERMAN_DIR, 'SQLMaps');
    if (fs.existsSync(sqlMapsDir) && fs.readdirSync(sqlMapsDir).length > 0) {
      base.push('--maps', sqlMapsDir);
    }
  }

  return base;
}

function buildHayabusaArgs(
  inputFile: string,
  outputDir: string,
  extraArgs: Record<string, string> = {}
): string[] {
  return [
    'csv-timeline',
    '--directory', inputFile,
    '--output', path.join(outputDir, 'hayabusa-results.csv'),
    '--profile', extraArgs['profile'] || 'standard',
    '--no-wizard',
    '--quiet',
  ];
}

function emitStatus(io: IOServer, socketId: string, payload: ParserStatusEvent): void {
  io.to(socketId).emit('parser:status', payload);
}

function emitLog(io: IOServer, socketId: string, stream: 'stdout' | 'stderr', line: string): void {
  const payload: ParserLogEvent = { stream, line, ts: Date.now() };
  io.to(socketId).emit('parser:log', payload);
}

async function streamCsvToDb(
  csvPath: string,
  pool: Pool,
  resultId: string
): Promise<number> {
  return new Promise((resolve, reject) => {
    let batch: Record<string, string>[] = [];
    let totalRows = 0;
    let headers: string[] = [];
    let isFirstLine = true;

    const BATCH_SIZE = 500;

    const rl = readline.createInterface({
      input: fs.createReadStream(csvPath, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    async function flushBatch(): Promise<void> {
      if (batch.length === 0) return;

      await pool.query(
        `UPDATE parser_results
         SET output_data = output_data || $1::jsonb,
             record_count = record_count + $2,
             updated_at = NOW()
         WHERE id = $3`,
        [JSON.stringify(batch), batch.length, resultId]
      );
      totalRows += batch.length;
      batch = [];
    }

    rl.on('line', async (line) => {
      if (!line.trim()) return;
      if (isFirstLine) {
        headers = line.split(',').map((h) => h.replace(/^"|"$/g, '').trim());
        isFirstLine = false;
        return;
      }

      try {

        const [raw] = csvParseSync(line, {
          columns: headers,
          skip_empty_lines: true,
          relax_column_count: true,
        }) as Record<string, string>[];

        const record: Record<string, string> = {};
        for (const [k, v] of Object.entries(raw)) {
          record[k] = typeof v === 'string' ? v.replace(/\u0000/g, '') : v;
        }
        batch.push(record);

        if (batch.length >= BATCH_SIZE) {
          rl.pause();
          await flushBatch();
          rl.resume();
        }
      } catch {

      }
    });

    rl.on('close', async () => {
      try {
        await flushBatch();
        resolve(totalRows);
      } catch (err) {
        reject(err);
      }
    });

    rl.on('error', reject);
  });
}

export async function runParser(
  config: ParserRunConfig,
  io: IOServer,
  pool: Pool
): Promise<void> {
  const { parser, evidenceId, caseId, userId, socketId, extraArgs = {} } = config;

  emitStatus(io, socketId, { status: 'INIT', message: 'Initialisation du parseur…' });

  const tool = ZIMMERMAN_TOOLS[parser];
  if (!tool) {
    emitStatus(io, socketId, { status: 'FAILED', message: `Parseur inconnu: ${parser}` });
    return;
  }

  let inputFile: string;
  try {
    const result = await pool.query<{ file_path: string }>(
      'SELECT file_path FROM evidence WHERE id = $1',
      [evidenceId]
    );
    if (result.rows.length === 0) throw new Error('Preuve non trouvée en base');
    inputFile = result.rows[0].file_path;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    emitStatus(io, socketId, { status: 'FAILED', message: `DB error: ${msg}` });
    return;
  }

  if (!fs.existsSync(inputFile)) {
    emitStatus(io, socketId, { status: 'FAILED', message: `Fichier introuvable: ${inputFile}` });
    return;
  }

  const uploadDir = process.env.UPLOAD_DIR || '/app/uploads';
  const pathCheck = safePath(path.basename(inputFile), path.dirname(inputFile));
  if (!pathCheck.safe) {
    emitStatus(io, socketId, { status: 'FAILED', message: `Chemin non autorisé: ${pathCheck.reason}` });
    return;
  }

  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const outputDir = path.join(TEMP_DIR, `parse-${runId}`);
  fs.mkdirSync(outputDir, { recursive: true });

  let resultId: string;
  try {
    const dbResult = await pool.query<{ id: string }>(
      `INSERT INTO parser_results
         (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1, $2, $3, $4, $5, '[]'::jsonb, 0, $6)
       RETURNING id`,
      [caseId, evidenceId, tool.name, '2.0', inputFile, userId]
    );
    resultId = dbResult.rows[0].id;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    emitStatus(io, socketId, { status: 'FAILED', message: `Erreur DB: ${msg}` });
    return;
  }

  let binary: string;
  let args: string[];

  if (parser === 'hayabusa') {
    binary = HAYABUSA_BIN;
    args = buildHayabusaArgs(inputFile, outputDir, extraArgs);
  } else if (parser === 'prefetch') {

    const isPrefetchDir = fs.existsSync(inputFile) && fs.statSync(inputFile).isDirectory();
    binary = 'python3';
    args = [
      '/app/parsers/parse_prefetch.py',
      isPrefetchDir ? '-d' : '-f', inputFile,
      '--csv', outputDir,
      '--csvf', 'output.csv',
    ];
  } else if (parser === 'srum') {

    binary = 'python3';
    args = ['/app/parsers/parse_srum.py', '-f', inputFile, '--csv', outputDir, '--csvf', 'output.csv'];
  } else {
    const dllPath = path.join(ZIMMERMAN_DIR, tool.dll);
    if (!fs.existsSync(dllPath)) {
      emitStatus(io, socketId, {
        status: 'FAILED',
        message: `DLL introuvable: ${dllPath}. Déposez ${tool.dll} dans ${ZIMMERMAN_DIR}`,
      });
      await pool.query(`DELETE FROM parser_results WHERE id = $1`, [resultId]);
      return;
    }
    binary = DOTNET_BIN;
    args = buildZimmermanArgs(dllPath, inputFile, outputDir, parser, extraArgs);
  }

  emitLog(io, socketId, 'stdout', `▶ ${binary} ${args.join(' ')}`);
  emitStatus(io, socketId, { status: 'RUNNING', message: 'Exécution en cours…' });

  const child = spawn(binary, args, {
    stdio: ['ignore', 'pipe', 'pipe'],

    cwd: outputDir,
    env: {
      ...process.env,

      DOTNET_GCHeapHardLimit: String(512 * 1024 * 1024),
    },
  });

  const rlOut = readline.createInterface({ input: child.stdout!, crlfDelay: Infinity });
  rlOut.on('line', (line) => {
    if (line.trim()) emitLog(io, socketId, 'stdout', line);
  });

  const rlErr = readline.createInterface({ input: child.stderr!, crlfDelay: Infinity });
  rlErr.on('line', (line) => {
    if (line.trim()) emitLog(io, socketId, 'stderr', line);
  });

  const exitCode = await new Promise<number>((resolve) => {
    child.on('close', (code) => resolve(code ?? -1));
    child.on('error', (err) => {
      emitLog(io, socketId, 'stderr', `Erreur spawn: ${err.message}`);
      resolve(-1);
    });
  });

  function findCsvRecursive(dir: string): string[] {
    const results: string[] = [];
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) results.push(...findCsvRecursive(full));
        else if (entry.isFile() && entry.name.toLowerCase().endsWith('.csv')) results.push(full);
      }
    } catch (_e) {}
    return results;
  }

  let totalRecords = 0;
  const csvPaths = findCsvRecursive(outputDir);
  if (exitCode === 0 || csvPaths.length > 0) {
    emitLog(io, socketId, 'stdout', `✓ ${csvPaths.length} fichier(s) CSV produit(s)`);

    for (const csvPath of csvPaths) {
      const csvFile = path.relative(outputDir, csvPath);
      try {
        emitLog(io, socketId, 'stdout', `  → Import streaming: ${csvFile}`);
        const rows = await streamCsvToDb(csvPath, pool, resultId);
        totalRecords += rows;
        emitLog(io, socketId, 'stdout', `  ✓ ${rows.toLocaleString()} lignes importées`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        emitLog(io, socketId, 'stderr', `  ✗ Erreur import ${csvFile}: ${msg}`);
      }
    }
  }

  try {
    fs.rmSync(outputDir, { recursive: true, force: true });
  } catch {

  }

  if (exitCode === 0 && csvPaths.length > 0 && totalRecords === 0) {
    emitStatus(io, socketId, {
      status: 'DEGRADED',
      message: `Terminé — 0 événements parsés (fichier vide ou format non reconnu)`,
      resultId,
      recordCount: 0,
    });
  } else if (exitCode === 0) {
    emitStatus(io, socketId, {
      status: 'SUCCESS',
      message: `Terminé — ${totalRecords.toLocaleString()} événements importés`,
      resultId,
      recordCount: totalRecords,
    });
  } else {
    emitStatus(io, socketId, {
      status: 'FAILED',
      message: `Processus terminé avec le code ${exitCode}`,
      exitCode,
      resultId,
      recordCount: totalRecords,
    });
  }
}

export function getAvailableTools(): Record<
  string,
  ZimmermanTool & { available: boolean; path: string }
> {
  const result: Record<string, ZimmermanTool & { available: boolean; path: string }> = {};
  for (const [key, tool] of Object.entries(ZIMMERMAN_TOOLS)) {
    if (key === 'hayabusa') {
      result[key] = { ...tool, available: fs.existsSync(HAYABUSA_BIN), path: HAYABUSA_BIN };
    } else if (key === 'prefetch') {

      const scriptPath = '/app/parsers/parse_prefetch.py';
      result[key] = { ...tool, available: fs.existsSync(scriptPath), path: scriptPath };
    } else if (key === 'srum') {

      const scriptPath = '/app/parsers/parse_srum.py';
      result[key] = { ...tool, available: fs.existsSync(scriptPath), path: scriptPath };
    } else {
      const toolPath = path.join(ZIMMERMAN_DIR, tool.dll);
      result[key] = { ...tool, available: fs.existsSync(toolPath), path: toolPath };
    }
  }
  return result;
}
