
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || '/app/uploads');
const YARA_BIN   = 'yara';
const YARA_TIMEOUT_MS = 60_000;

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

export function validateRule(content: string): { valid: boolean; error?: string } {
  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(content);

    let result = spawnSync(YARA_BIN, ['--syntax-only', tmpPath, '/dev/null'], {
      timeout: 10_000,
      encoding: 'utf8',
    });

    if ((result.stderr || '').includes('unknown option')) {
      result = spawnSync(YARA_BIN, [tmpPath, '/dev/null'], {
        timeout: 10_000,
        encoding: 'utf8',
      });

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

export function scanEvidence(
  evidencePath: string,
  ruleContent:  string,
): YaraScanResult {

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
    const result = spawnSync(YARA_BIN, ['-s', tmpPath, resolved], {
      timeout:  YARA_TIMEOUT_MS,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });

    if (result.error) {
      return { matched: false, strings: [], error: String(result.error) };
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
