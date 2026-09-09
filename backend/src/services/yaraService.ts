
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || '/app/uploads');
const YARA_BIN   = 'yara';
const YARA_TIMEOUT_MS = 300_000; // 5 min — large RAM dumps need time, but must not block event loop

export interface YaraMatch {
  identifier: string;
  offset:     number;
  data:        string;
  file:       string | null;
}

export interface YaraScanResult {
  matched: boolean;
  strings: YaraMatch[];
  error?:  string;
}

function writeTmpRule(content: string): string {
  const tmpPath = path.join(os.tmpdir(), `fl_yara_${uuidv4()}.yar`);
  fs.writeFileSync(tmpPath, content, { encoding: 'utf8' });
  return tmpPath;
}

// Async spawn wrapper — never blocks the event loop
function spawnAsync(args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(YARA_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`yara timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    child.on('close', (code: number | null) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, status: code });
    });
    child.on('error', (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export async function validateRule(content: string): Promise<{ valid: boolean; error?: string }> {
  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(content);

    let result = await spawnAsync(['--syntax-only', tmpPath, '/dev/null'], 10_000);

    if ((result.stderr || '').includes('unknown option')) {
      result = await spawnAsync([tmpPath, '/dev/null'], 10_000);
      if (result.status === 0 || result.status === 1) return { valid: true };
      const stderr = (result.stderr || '').trim();
      return { valid: false, error: stderr || 'Règle YARA invalide' };
    }
    if (result.status === 0) return { valid: true };
    const stderr = (result.stderr || '').trim();
    return { valid: false, error: stderr || 'Règle YARA invalide' };
  } catch (e: any) {
    return { valid: false, error: `yara indisponible : ${e.message}` };
  } finally {
    if (tmpPath) try { fs.unlinkSync(tmpPath); } catch {}
  }
}

export function parseYaraOutput(stdout: string): YaraMatch[] {
  const matches: YaraMatch[] = [];
  let currentFile: string | null = null;
  for (const line of String(stdout ?? '').split('\n')) {
    const m = line.match(/^0x([0-9a-f]+):(\$\S+):\s*(.+)$/i);
    if (m) {
      matches.push({
        identifier: m[2],
        offset:     parseInt(m[1], 16),
        data:       m[3].trim(),
        file:       currentFile,
      });
      continue;
    }
    const header = line.match(/^(\S+)\s+(\/\S.*)$/);
    if (header) currentFile = header[2].trim();
  }
  return matches;
}

export const SCAN_ROOTS = [
  UPLOAD_DIR,
  path.resolve(process.env.COLLECTIONS_DIR || '/app/collections'),
  path.resolve(process.env.EVIDENCE_DIR || '/app/evidence'),
];

export function isAllowedScanPath(target: string, roots: string[]): boolean {
  if (typeof target !== 'string' || target.length === 0) return false;
  if (!Array.isArray(roots) || roots.length === 0) return false;
  const resolved = path.resolve(target);
  return roots.some((root) => {
    const r = path.resolve(root);
    return resolved === r || resolved.startsWith(r + path.sep);
  });
}

export type YaraScanStatus = 'clean' | 'matches' | 'partial' | 'failed';

export interface YaraScanOutcome {
  status:  YaraScanStatus;
  message: string;
}

export function yaraScanOutcome(input: {
  rulesChecked: number;
  rulesErrored: number;
  matchCount:   number;
}): YaraScanOutcome {
  const { rulesChecked, rulesErrored, matchCount } = input;
  if (matchCount > 0) {
    return { status: 'matches', message: `${matchCount} correspondance${matchCount > 1 ? 's' : ''}` };
  }
  if (rulesChecked === 0) {
    return { status: 'failed', message: 'Aucune règle YARA active — rien n\'a été scanné' };
  }
  if (rulesErrored >= rulesChecked) {
    return { status: 'failed', message: `Scan impossible — les ${rulesChecked} règles ont toutes échoué, aucun octet n'a été lu` };
  }
  if (rulesErrored > 0) {
    return { status: 'partial', message: `Scan partiel — ${rulesErrored} règle${rulesErrored > 1 ? 's' : ''} sur ${rulesChecked} n'ont pas pu être exécutées` };
  }
  return { status: 'clean', message: `Aucune correspondance — ${rulesChecked} règles exécutées` };
}

export async function scanEvidence(
  evidencePath: string,
  ruleContent:  string,
): Promise<YaraScanResult> {

  const resolved = path.resolve(evidencePath);
  if (!isAllowedScanPath(resolved, SCAN_ROOTS)) {
    return { matched: false, strings: [], error: 'Chemin hors de la zone autorisée' };
  }
  if (!fs.existsSync(resolved)) {
    return { matched: false, strings: [], error: 'Fichier evidence introuvable' };
  }

  let isDir = false;
  try { isDir = fs.statSync(resolved).isDirectory(); } catch { isDir = false; }

  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(ruleContent);
    const args = isDir ? ['-r', '-s', tmpPath, resolved] : ['-s', tmpPath, resolved];
    const result = await spawnAsync(args, YARA_TIMEOUT_MS);

    if (!result) {
      return { matched: false, strings: [], error: 'Pas de résultat' };
    }

    const stdout = result.stdout || '';

    if (result.status === 0 && stdout.trim().length > 0) {
      return { matched: true, strings: parseYaraOutput(stdout) };
    }
    return { matched: false, strings: [] };
  } catch (e: any) {
    return { matched: false, strings: [], error: String(e.message) };
  } finally {
    if (tmpPath) try { fs.unlinkSync(tmpPath); } catch {}
  }
}
