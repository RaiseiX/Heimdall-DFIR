
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import type { Pool } from 'pg';
import { auditLog } from '../middleware/auth';
import { deleteIndex } from './elasticsearchService';

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';

const SHRED_TIMEOUT_MS = 60 * 60 * 1000;
const CHUNK_SIZE       = 4 * 1024 * 1024;

const NODE_PASSES: Array<'random' | 'zeros'> = [
  'random', 'random', 'random', 'random', 'random', 'random', 'random', 'zeros',
];

async function nodeWipe(filePath: string): Promise<void> {
  const stat = await fs.promises.stat(filePath);
  const fileSize = stat.size;
  if (fileSize === 0) { await fs.promises.unlink(filePath); return; }

  const fd = await fs.promises.open(filePath, 'r+');
  try {
    for (const pass of NODE_PASSES) {
      let offset = 0;
      while (offset < fileSize) {
        const chunkLen = Math.min(CHUNK_SIZE, fileSize - offset);
        const buf = pass === 'zeros' ? Buffer.alloc(chunkLen, 0x00) : crypto.randomBytes(chunkLen);
        await fd.write(buf, 0, chunkLen, offset);
        offset += chunkLen;
      }
      await fd.datasync();
    }
  } finally {
    await fd.close();
  }
  await fs.promises.unlink(filePath);
}

async function dodWipe(filePath: string): Promise<'shred' | 'node'> {

  const result = spawnSync(
    'shred', ['-n', '7', '-z', '-u', filePath],
    { timeout: SHRED_TIMEOUT_MS, stdio: 'pipe' },
  );

  if (result.status === 0 && !result.error) {
    return 'shred';
  }

  logger.warn(
    '[hardDelete] shred failed (status=%d, err=%s), using Node.js fallback',
    result.status,
    result.error?.message || result.stderr?.toString()?.slice(0, 120) || 'unknown',
  );
  await nodeWipe(filePath);
  return 'node';
}

async function destroyFile(filePath: string): Promise<{ path: string; method: 'shred' | 'node' | 'unlink'; error?: string }> {
  if (!fs.existsSync(filePath)) {
    return { path: filePath, method: 'shred' };
  }
  try {
    const method = await dodWipe(filePath);
    return { path: filePath, method };
  } catch (err: any) {
    logger.warn('[hardDelete] DoD wipe failed, falling back to unlink:', err.message);
    try { await fs.promises.unlink(filePath); } catch  }
    return { path: filePath, method: 'unlink', error: err.message };
  }
}

export interface HardDeleteResult {
  caseId: string;
  caseNumber: string;
  filesDestroyed: number;
  filesErrors: string[];
}

export async function hardDeleteCase(
  pool: Pool,
  caseId: string,
  userId: string,
  ip: string,
): Promise<HardDeleteResult> {

  const caseRes = await pool.query(
    'SELECT id, case_number, title FROM cases WHERE id = $1',
    [caseId],
  );
  if (caseRes.rows.length === 0) {
    throw Object.assign(new Error('Cas introuvable'), { status: 404 });
  }
  const { case_number, title } = caseRes.rows[0];

  const evidenceRes = await pool.query(
    'SELECT id, file_path FROM evidence WHERE case_id = $1 AND file_path IS NOT NULL',
    [caseId],
  );

  const filesErrors: string[] = [];
  let filesDestroyed = 0;
  const wipeMethods: Record<string, number> = { shred: 0, node: 0, unlink: 0 };

  for (const row of evidenceRes.rows) {
    const filePath = row.file_path as string;

    const absPath = path.isAbsolute(filePath)
      ? filePath
      : path.join(UPLOAD_DIR, filePath);

    const resolved = path.resolve(absPath);
    if (!resolved.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) {
      filesErrors.push(`path_traversal_blocked:${filePath}`);
      continue;
    }

    const result = await destroyFile(resolved);
    if (result.error) {
      filesErrors.push(`${filePath}:${result.error}`);
    } else {
      filesDestroyed++;
      wipeMethods[result.method] = (wipeMethods[result.method] || 0) + 1;
    }
  }

  const caseDir = path.resolve(path.join(UPLOAD_DIR, caseId));
  if (caseDir.startsWith(path.resolve(UPLOAD_DIR) + path.sep) && fs.existsSync(caseDir)) {
    try {
      const remaining = await fs.promises.readdir(caseDir);
      if (remaining.length === 0) {
        await fs.promises.rmdir(caseDir);
      }
    } catch {

    }
  }

  await pool.query('DELETE FROM cases WHERE id = $1', [caseId]);

  await deleteIndex(caseId);

  await (auditLog as Function)(
    userId,
    'hard_delete_case',
    'case',
    caseId,
    {
      case_number,
      title,
      files_destroyed: filesDestroyed,
      files_errors: filesErrors,
      wipe_standard: 'DoD 5220.22-M',
      wipe_passes: 7,
      wipe_methods: wipeMethods,
      rgpd: true,
    },
    ip,
  );

  return { caseId, caseNumber: case_number, filesDestroyed, filesErrors };
}
