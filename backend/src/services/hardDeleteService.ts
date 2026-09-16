
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import type { Pool } from 'pg';
import { auditLog } from '../middleware/auth';
import { deleteIndex } from './elasticsearchService';
const { deleteMinioLocator } = require('./deletionStorage');
const { planEvidenceDeletion } = require('./evidenceDeletionPlan');
const { assertConfinedPath } = require('./storagePathGuard');
const {
  withCaseDeletion,
  beginDeletionOperation,
  markDeletionItem,
  markDeletionOperation,
  findCompletedDeletionOperation,
  safeErrorCode,
} = require('./caseDeletion');

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

async function destroyFile(filePath: string): Promise<{ status: 'deleted' | 'already_absent'; method: 'shred' | 'node' | 'unlink' | 'none' }> {
  if (!fs.existsSync(filePath)) {
    return { status: 'already_absent', method: 'none' };
  }
  await assertConfinedPath(UPLOAD_DIR, filePath);
  const stat = await fs.promises.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw Object.assign(new Error('Unsupported storage target'), { code: 'UNSUPPORTED_STORAGE_TARGET' });
  }
  try {
    const method = await dodWipe(filePath);
    return { status: 'deleted', method };
  } catch (err: any) {
    logger.warn('[hardDelete] DoD wipe failed, falling back to unlink:', err.message);
    await fs.promises.unlink(filePath);
    return { status: 'deleted', method: 'unlink' };
  }
}

export interface HardDeleteResult {
  caseId: string;
  caseNumber: string;
  filesDestroyed: number;
  filesAlreadyAbsent: number;
  filesErrors: string[];
  operationId: string;
}

export interface HardDeleteOptions {
  confirmation?: string;
  automated?: boolean;
}

export async function hardDeleteCase(
  pool: Pool,
  caseId: string,
  userId: string,
  ip: string,
  options: HardDeleteOptions = {},
): Promise<HardDeleteResult> {
  let operationId: string | null = null;
  let operationPrepared = false;
  try {
    const { result, auditDetails } = await withCaseDeletion(pool, caseId,
      (client: Pick<Pool, 'query'>) => deleteLockedCase(client, pool, caseId, userId, ip, options,
        id => { operationId = id; }, () => { operationPrepared = true; }));
    await (auditLog as Function)(userId, 'hard_delete_case', 'case', caseId, auditDetails, ip);
    return result;
  } catch (error) {
    if ((error as any)?.status === 404 && !operationId) {
      const completed = await findCompletedDeletionOperation(pool, {
        operationType: 'hard_delete_case', targetId: caseId,
      });
      if (completed && (options.automated || options.confirmation === completed.case_number)) {
        const context = typeof completed.context === 'string' ? JSON.parse(completed.context) : (completed.context || {});
        return {
          caseId,
          caseNumber: completed.case_number,
          filesDestroyed: Number(context.files_destroyed || 0),
          filesAlreadyAbsent: Number(context.files_already_absent || 0),
          filesErrors: [],
          operationId: completed.id,
        };
      }
    }
    if (operationId && !operationPrepared) {
      try { await markDeletionOperation(pool, operationId, 'incomplete', safeErrorCode(error)); } catch (journalError) {
        logger.error('[hardDelete] operation journal failure:', safeErrorCode(journalError));
      }
    }
    if (operationId && error && typeof error === 'object') (error as any).operationId = operationId;
    throw error;
  }
}

async function deleteLockedCase(
  client: Pick<Pool, 'query'>,
  journalPool: Pool,
  caseId: string,
  userId: string,
  ip: string,
  options: HardDeleteOptions,
  setOperationId: (id: string) => void,
  setOperationPrepared: () => void,
): Promise<{ result: HardDeleteResult; auditDetails: Record<string, unknown> }> {

  const caseRes = await client.query(
    'SELECT id, case_number, title FROM cases WHERE id = $1',
    [caseId],
  );
  if (caseRes.rows.length === 0) {
    throw Object.assign(new Error('Cas introuvable'), { status: 404 });
  }
  const { case_number, title } = caseRes.rows[0];
  if (!options.automated && options.confirmation !== case_number) {
    throw Object.assign(new Error('Destructive confirmation required'), {
      status: 400,
      code: 'DESTRUCTIVE_CONFIRMATION_REQUIRED',
    });
  }

  const evidenceRes = await client.query(
    'SELECT id, file_path, additional_files FROM evidence WHERE case_id = $1 ORDER BY id',
    [caseId],
  );

  const filesErrors: string[] = [];
  let filesDestroyed = 0;
  let filesAlreadyAbsent = 0;
  const wipeMethods: Record<string, number> = { shred: 0, node: 0, unlink: 0 };
  let targets: Array<{ kind: 'disk' | 'minio'; locator: string }> = [];
  try {
    for (const row of evidenceRes.rows) targets.push(...planEvidenceDeletion(row));
  } catch (error) {
    throw Object.assign(error as Error, { status: 502, code: 'DELETION_INCOMPLETE' });
  }
  targets = Array.from(new Map(targets.map(target => [`${target.kind}:${target.locator}`, target])).values());

  const operation = await beginDeletionOperation(journalPool, {
    operationType: 'hard_delete_case',
    caseId,
    caseNumber: case_number,
    targetId: caseId,
    requestedBy: userId,
    requestIp: ip,
    context: { evidence_count: evidenceRes.rows.length },
    items: [...targets, { kind: 'elasticsearch', locator: caseId }],
  });
  setOperationId(operation.id);

  for (const item of operation.items) {
    if (item.kind === 'elasticsearch') continue;
    if (item.status === 'deleted') {
      filesDestroyed++;
      continue;
    }
    if (item.status === 'already_absent') {
      filesAlreadyAbsent++;
      continue;
    }
    await markDeletionItem(journalPool, operation.id, item.item_key, 'running');
    try {
      let result;
      if (item.kind === 'minio') {
        result = await deleteMinioLocator(item.locator);
      } else {
        const absPath = path.isAbsolute(item.locator) ? item.locator : path.join(UPLOAD_DIR, item.locator);
        const resolved = path.resolve(absPath);
        if (!resolved.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) {
          throw Object.assign(new Error('Storage target outside upload root'), { code: 'STORAGE_PATH_REJECTED' });
        }
        result = await destroyFile(resolved);
      }
      await markDeletionItem(journalPool, operation.id, item.item_key, result.status, result.method);
      if (result.status === 'deleted') {
        filesDestroyed++;
        if (result.method !== 'minio' && result.method !== 'none') {
          wipeMethods[result.method] = (wipeMethods[result.method] || 0) + 1;
        }
      } else {
        filesAlreadyAbsent++;
      }
    } catch (error) {
      const code = safeErrorCode(error);
      filesErrors.push(code);
      try { await markDeletionItem(journalPool, operation.id, item.item_key, 'failed', null, code); } catch (journalError) {
        logger.error('[hardDelete] item journal failure:', safeErrorCode(journalError));
      }
      throw Object.assign(new Error('Deletion incomplete; database references retained'), {
        status: 502,
        code: 'DELETION_INCOMPLETE',
      });
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

  const indexItem = operation.items.find((item: { kind: string }) => item.kind === 'elasticsearch');
  try {
    if (!indexItem || (indexItem.status !== 'deleted' && indexItem.status !== 'already_absent')) {
      if (indexItem) await markDeletionItem(journalPool, operation.id, indexItem.item_key, 'running');
      await deleteIndex(caseId, { strict: true });
      if (indexItem) await markDeletionItem(journalPool, operation.id, indexItem.item_key, 'deleted', 'delete_index');
    }
  } catch (err) {
    if (indexItem) {
      try { await markDeletionItem(journalPool, operation.id, indexItem.item_key, 'failed', null, safeErrorCode(err)); } catch (journalError) {
        logger.error('[hardDelete] index journal failure:', safeErrorCode(journalError));
      }
    }
    throw Object.assign(err as Error, { status: 502, code: 'DELETION_INCOMPLETE' });
  }
  await markDeletionOperation(journalPool, operation.id, 'ready_to_commit');
  setOperationPrepared();
  await client.query('DELETE FROM cases WHERE id = $1', [caseId]);
  await markDeletionOperation(client, operation.id, 'completed', null, {
    files_destroyed: filesDestroyed,
    files_already_absent: filesAlreadyAbsent,
  });

  return {
    result: { caseId, caseNumber: case_number, filesDestroyed, filesAlreadyAbsent, filesErrors, operationId: operation.id },
    auditDetails: {
      operation_id: operation.id,
      case_number,
      title,
      files_destroyed: filesDestroyed,
      files_already_absent: filesAlreadyAbsent,
      files_errors: filesErrors,
      wipe_methods: wipeMethods,
    },
  };
}
