
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import type { Pool } from 'pg';
import { auditCritical } from '../middleware/auth';
import { deleteIndex } from './elasticsearchService';
import { destroyStorageTarget } from './storageDeletionService';
const { deleteMinioLocator } = require('./deletionStorage');
const { planEvidenceDeletion } = require('./evidenceDeletionPlan');
const { racinesDeStockage, estSousUneRacine } = require('./storagePathGuard');
const { isCaseCollectionName } = require('./storageInventory');
const {
  withCaseDeletion,
  beginDeletionOperation,
  markDeletionItem,
  markDeletionOperation,
  findCompletedDeletionOperation,
  safeErrorCode,
} = require('./caseDeletion');

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';
const COLLECTIONS_DIR = process.env.COLLECTIONS_DIR || '/app/collections';

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
  auditAction?: string;
  auditDetails?: Record<string, unknown>;
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
    return await withCaseDeletion(pool, caseId,
      (client: Pick<Pool, 'query'>) => deleteLockedCase(client, pool, caseId, userId, ip, options,
        id => { operationId = id; }, () => { operationPrepared = true; }));
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
    if ((error as any)?.auditFailure && operationId && operationPrepared) {
      Object.assign(error as object, { status: 502, code: 'DELETION_INCOMPLETE' });
    }
    if (operationId && error && typeof error === 'object') (error as any).operationId = operationId;
    throw error;
  }
}

async function readDirectoryNames(dir: string, tolerated: string[]): Promise<string[]> {
  try {
    return await fs.promises.readdir(dir);
  } catch (error) {
    if (tolerated.includes((error as NodeJS.ErrnoException)?.code || '')) return [];
    throw Object.assign(error as Error, { status: 502, code: 'DELETION_INCOMPLETE' });
  }
}

async function planCollectionTargets(
  client: Pick<Pool, 'query'>,
  caseId: string,
): Promise<Array<{ kind: 'disk'; locator: string }>> {
  const planned: Array<{ kind: 'disk'; locator: string }> = [];
  const collectionsRoot = path.resolve(COLLECTIONS_DIR);

  const importRes = await client.query(
    `SELECT COALESCE(NULLIF(output_data->>'collection_dir', ''), input_file) AS dir
       FROM parser_results WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'`,
    [caseId],
  );
  let rejected = 0;
  for (const row of importRes.rows) {
    const dir = row?.dir;
    if (typeof dir !== 'string' || !dir) {
      rejected++;
      continue;
    }
    const resolved = path.resolve(dir);
    if (path.dirname(resolved) !== collectionsRoot || !isCaseCollectionName(path.basename(resolved), caseId)) {
      rejected++;
      continue;
    }
    planned.push({ kind: 'disk', locator: resolved });
  }
  if (rejected > 0) logger.warn(`[hardDelete] ignored ${rejected} import director${rejected === 1 ? 'y' : 'ies'} outside the case collection naming`);

  for (const name of await readDirectoryNames(collectionsRoot, ['ENOENT'])) {
    if (typeof name === 'string' && isCaseCollectionName(name, caseId)) {
      planned.push({ kind: 'disk', locator: path.resolve(collectionsRoot, name) });
    }
  }

  const cacheRoot = path.join(collectionsRoot, 'rdp-cache');
  for (const name of await readDirectoryNames(cacheRoot, ['ENOENT', 'ENOTDIR'])) {
    if (typeof name === 'string' && name.toLowerCase() === caseId.toLowerCase()) {
      planned.push({ kind: 'disk', locator: path.resolve(cacheRoot, name) });
    }
  }
  return planned;
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
): Promise<HardDeleteResult> {

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
  const wipeMethods: Record<string, number> = { shred: 0, node: 0, unlink: 0, rmdir: 0 };
  let targets: Array<{ kind: 'disk' | 'minio'; locator: string }> = [];
  try {
    for (const row of evidenceRes.rows) targets.push(...planEvidenceDeletion(row));
  } catch (error) {
    throw Object.assign(error as Error, { status: 502, code: 'DELETION_INCOMPLETE' });
  }
  const evidenceKeys = new Set(targets.map(target => `${target.kind}:${target.locator}`));

  targets.push(...await planCollectionTargets(client, caseRes.rows[0].id || caseId));

  targets = Array.from(new Map(targets.map(target => [`${target.kind}:${target.locator}`, target])).values());
  const orphanTargets = targets.filter(target => !evidenceKeys.has(`${target.kind}:${target.locator}`)).length;

  const operation = await beginDeletionOperation(journalPool, {
    operationType: 'hard_delete_case',
    caseId,
    caseNumber: case_number,
    targetId: caseId,
    requestedBy: userId,
    requestIp: ip,
    context: { evidence_count: evidenceRes.rows.length, orphan_targets: orphanTargets },
    items: [...targets, { kind: 'elasticsearch', locator: caseId }],
  });
  setOperationId(operation.id);

  await auditCritical(journalPool, userId, `${options.auditAction || 'hard_delete_case'}_started`, 'case', caseId, {
    operation_id: operation.id,
    case_id: caseId,
    case_number,
    title,
    targets: operation.items.length,
  }, ip);

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
        const storageRoot = estSousUneRacine(racinesDeStockage(), resolved);
        if (!storageRoot) {
          throw Object.assign(new Error('Storage target outside configured roots'), { code: 'STORAGE_PATH_REJECTED' });
        }
        result = await destroyStorageTarget(resolved, storageRoot);
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

  await auditCritical(client, userId, options.auditAction || 'hard_delete_case', 'case', caseId, {
    ...(options.auditDetails || {}),
    operation_id: operation.id,
    case_number,
    title,
    files_destroyed: filesDestroyed,
    files_already_absent: filesAlreadyAbsent,
    files_errors: filesErrors,
    wipe_methods: wipeMethods,
  }, ip);

  return { caseId, caseNumber: case_number, filesDestroyed, filesAlreadyAbsent, filesErrors, operationId: operation.id };
}
