
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

function parseYaraOutput(stdout: string): YaraMatch[] {
  const matches: YaraMatch[] = [];
  for (const line of stdout.split('\n')) {
    const m = line.match(/^0x([0-9a-f]+):(\$\S+):\s*(.+)$/i);
    if (m) {
      matches.push({
        identifier: m[2],
        offset:     parseInt(m[1], 16),
        data:       m[3].trim(),
      });
    }
  }
  return matches;
}

export async function scanEvidence(
  evidencePath: string,
  ruleContent:  string,
): Promise<YaraScanResult> {

  const resolved = path.resolve(evidencePath);
  if (!resolved.startsWith(UPLOAD_DIR + path.sep) && !resolved.startsWith(UPLOAD_DIR)) {
    return { matched: false, strings: [], error: 'Chemin hors de la zone autorisée' };
  }
  if (!fs.existsSync(resolved)) {
    return { matched: false, strings: [], error: 'Fichier evidence introuvable' };
  }

  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(ruleContent);
    const result = await spawnAsync(['-s', tmpPath, resolved], YARA_TIMEOUT_MS);

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
