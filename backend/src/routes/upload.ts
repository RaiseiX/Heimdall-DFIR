
import express, { Response, NextFunction } from 'express';
import logger from '../config/logger';
import Joi from 'joi';
import { v4 as uuidv4 } from 'uuid';
import type { Pool } from 'pg';
import type { AuthRequest } from '../types/index';
import {
  initUpload,
  receiveChunk,
  completeUpload,
  abortUpload,
  getSessionStatus,
  getSessionOwner,
  isUploadError,
} from '../services/uploadService';
import { scanFile } from '../services/clamavService';
import { ingestionQueue, parserQueue, IngestionJobData } from '../config/queue';

const { canAccessCase } = require('../middleware/caseAccess');
const { auditCritical } = require('../middleware/auth');
const { removeOrphanFile } = require('../services/orphanUploadCleanup');

const ACTIVE_STATES = ['active', 'waiting', 'delayed', 'prioritized'] as any;

class IngestionConflictError extends Error {
  status = 409;
  constructor(evidenceId: string) {
    super(`Ingestion already in progress for evidence ${evidenceId}`);
    this.name = 'IngestionConflictError';
  }
}

async function hasLiveJob(queue: { getJobs: (...a: any[]) => Promise<any[]> }, evidenceId: string): Promise<boolean> {
  const jobs = await queue.getJobs(ACTIVE_STATES, 0, -1);
  return jobs.some((j: any) => j && j.data && j.data.evidenceId === evidenceId);
}

async function enqueueIngestion(data: IngestionJobData): Promise<void> {
  if (data.forceReparse) {
    if (await hasLiveJob(ingestionQueue as any, data.evidenceId) || await hasLiveJob(parserQueue as any, data.evidenceId)) {
      throw new IngestionConflictError(data.evidenceId);
    }
    await ingestionQueue.add('ingest', data, { jobId: `ingest-${data.evidenceId}-${Date.now()}` });
    return;
  }
  await ingestionQueue.add('ingest', data, { jobId: `ingest-${data.evidenceId}` });
}

const router = express.Router() as express.Router & { enqueueIngestion: typeof enqueueIngestion };
router.enqueueIngestion = enqueueIngestion;

function sessionPossedee(uploadId: unknown, userId: string): boolean {
  if (typeof uploadId !== 'string') return false;
  const owner = getSessionOwner(uploadId, UPLOAD_DIR);
  return owner !== null && owner.userId === userId;
}

const MESSAGES_ERREUR: Record<string, string> = {
  conflict: 'Etat de la session incompatible avec cette operation',
  too_large: 'Taille depassee',
  invalid: 'Taille ou empreinte non conforme',
  bad_request: 'Requete invalide',
  quota: 'Limite de sessions atteinte',
  insufficient_storage: 'Stockage insuffisant',
};

function repondreErreurUpload(err: unknown, res: Response, introuvable: string, fermer: boolean): boolean {
  if (!isUploadError(err)) return false;
  if (err.kind === 'not_found' || err.kind === 'forbidden') {
    res.status(404).json({ error: introuvable });
    return true;
  }
  if (fermer) res.setHeader('Connection', 'close');
  res.status(err.status).json({ error: MESSAGES_ERREUR[err.kind] || 'Requete refusee' });
  return true;
}

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';

function getPool(res: Response): Pool {
  return res.app.locals.pool as Pool;
}

const initSchema = Joi.object({
  originalName: Joi.string().max(255).required(),
  totalSize: Joi.number().integer().min(1).required(),
  checksumSha256: Joi.string().hex().length(64).optional(),
  caseId: Joi.string().uuid().required(),
});

const completeSchema = Joi.object({
  uploadId: Joi.string().uuid().required(),
  caseId: Joi.string().uuid().required(),
  evidenceType: Joi.string()
    .valid('log', 'memory', 'network', 'binary', 'disk', 'collection', 'config', 'text', 'registry', 'prefetch', 'browser', 'other')
    .default('other'),
  notes: Joi.string().max(2000).allow('').optional(),
});

router.post('/init', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const { error, value } = initSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    if (!(await canAccessCase(req.user, value.caseId))) {
      return res.status(404).json({ error: 'Ressource introuvable' });
    }

    const result = initUpload({
      originalName: value.originalName,
      totalSize: value.totalSize,
      checksumSha256: value.checksumSha256,
      caseId: value.caseId,
      userId: req.user.id,
      uploadDir: UPLOAD_DIR,
    });

    res.status(201).json(result);
  } catch (err) {
    if (repondreErreurUpload(err, res, 'Ressource introuvable', false)) return;
    next(err);
  }
});

router.get('/status/:uploadId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!sessionPossedee(req.params.uploadId, req.user.id)) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }
    const status = await getSessionStatus({ uploadId: req.params.uploadId, userId: req.user.id, uploadDir: UPLOAD_DIR });
    if (!status.found) return res.status(404).json({ error: 'Session non trouvée' });
    res.json(status);
  } catch (err) {
    if (repondreErreurUpload(err, res, 'Session non trouvée', false)) return;
    next(err);
  }
});

router.post('/chunk', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const uploadId = req.query['uploadId'] as string;
    const rawIndex = req.query['chunkIndex'];

    if (!uploadId || typeof uploadId !== 'string') return res.status(400).json({ error: 'uploadId requis' });
    if (typeof rawIndex !== 'string' || !/^\d{1,9}$/.test(rawIndex)) return res.status(400).json({ error: 'chunkIndex invalide' });
    const chunkIndex = parseInt(rawIndex, 10);

    if (!sessionPossedee(uploadId, req.user.id)) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }

    const rawLength = req.headers['content-length'];
    let declaredLength: number | null = null;
    if (rawLength !== undefined) {
      if (!/^\d{1,15}$/.test(rawLength)) {
        res.setHeader('Connection', 'close');
        return res.status(400).json({ error: 'Content-Length invalide' });
      }
      declaredLength = parseInt(rawLength, 10);
    }

    const ack = await receiveChunk({
      uploadId,
      chunkIndex,
      req,
      userId: req.user.id,
      uploadDir: UPLOAD_DIR,
      declaredLength,
    });

    res.json(ack);
  } catch (err) {
    if (repondreErreurUpload(err, res, 'Session non trouvée', true)) return;
    next(err);
  }
});

router.post('/complete', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const { error, value } = completeSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const owner = getSessionOwner(value.uploadId, UPLOAD_DIR);
    if (
      !owner ||
      owner.userId !== req.user.id ||
      owner.caseId !== value.caseId ||
      !(await canAccessCase(req.user, value.caseId))
    ) {
      return res.status(404).json({ error: 'Ressource introuvable' });
    }

    const pool = getPool(res);

    const caseCheck = await pool.query('SELECT id FROM cases WHERE id = $1', [value.caseId]);
    if (caseCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Cas non trouvé' });
    }

    let fileInfo: Awaited<ReturnType<typeof completeUpload>>;
    try {
      fileInfo = await completeUpload({
        uploadId: value.uploadId,
        caseId: value.caseId,
        userId: req.user.id,
        finalDir: UPLOAD_DIR,
        uploadDir: UPLOAD_DIR,
      });
    } catch (finalizeErr) {
      if (repondreErreurUpload(finalizeErr, res, 'Ressource introuvable', false)) return;
      throw finalizeErr;
    }

    const scanResult = await scanFile(fileInfo.finalPath);
    const scanStatus = scanResult.error
      ? 'error'
      : (scanResult.clean ? 'clean' : 'quarantined');
    const scanThreat = scanResult.threat ?? null;

    if (scanStatus === 'quarantined') {
      logger.warn(
        `[ClamAV] QUARANTAINE — ${fileInfo.name} — menace: ${scanThreat}`
      );
    } else if (scanStatus === 'error') {
      logger.warn(`[ClamAV] Scan indisponible pour ${fileInfo.name}: ${scanResult.error}`);
    } else {
      logger.info(`[ClamAV] Clean — ${fileInfo.name}`);
    }

    let evidence: any;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const evidenceResult = await client.query(
        `INSERT INTO evidence
           (case_id, name, original_filename, file_path, file_size,
            evidence_type, hash_md5, hash_sha1, hash_sha256,
            notes, added_by, chain_of_custody, scan_status, scan_threat)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         RETURNING *`,
        [
          value.caseId,
          fileInfo.name,
          fileInfo.name,
          fileInfo.filePath,
          fileInfo.fileSize,
          value.evidenceType,
          fileInfo.hash_md5,
          fileInfo.hash_sha1,
          fileInfo.hash_sha256,
          value.notes || null,
          req.user.id,
          JSON.stringify([{
            action: 'uploaded_chunked',
            user: req.user.full_name,
            timestamp: new Date().toISOString(),
            hash_sha256: fileInfo.hash_sha256,
          }]),
          scanStatus,
          scanThreat,
        ]
      );

      evidence = evidenceResult.rows[0];

      await auditCritical(client, req.user.id, 'upload_evidence_chunked', 'evidence', evidence.id, {
        filename:    fileInfo.name,
        size:        fileInfo.fileSize,
        hash_sha256: fileInfo.hash_sha256,
        uploadId:    value.uploadId,
        scan_status: scanStatus,
        scan_threat: scanThreat,
      }, req.ip);

      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK').catch(() => {});
      if ((txErr as any)?.auditFailure) {
        await removeOrphanFile(fileInfo.finalPath || fileInfo.filePath, { sha256: fileInfo.hash_sha256 });
      }
      throw txErr;
    } finally {
      client.release();
    }

    try {
      await enqueueIngestion({
        evidenceId:   evidence.id,
        caseId:       value.caseId,
        userId:       req.user.id,
        uploadPath:   fileInfo.filePath,
        // Use the Joi-validated value (defaulted/whitelisted), not the raw
        // body — req.body.evidenceType could be missing/malformed even after
        // validation swapped in a default, since Joi's `value` (not
        // req.body) carries defaults and coercions.
        evidenceType: value.evidenceType,
        socketId:     req.body.socketId || '',
      });
    } catch (enqueueErr) {
      logger.error(`[Ingestion] Échec de mise en file pour l'evidence ${evidence.id}: ${enqueueErr}`);
    }

    res.status(201).json({
      evidenceId:  evidence.id,
      name:        evidence.name,
      fileSize:    evidence.file_size,
      hash_md5:    evidence.hash_md5,
      hash_sha1:   evidence.hash_sha1,
      hash_sha256: evidence.hash_sha256,
      scanStatus:  evidence.scan_status,
      scanThreat:  evidence.scan_threat ?? undefined,
    });
  } catch (err) {
    if ((err as any)?.auditFailure) {
      logger.error('[upload/complete] audit failure:', (err as any).message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    next(err);
  }
});

router.delete('/:uploadId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const { uploadId } = req.params;
    if (!sessionPossedee(uploadId, req.user.id)) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }
    await abortUpload({ uploadId, userId: req.user.id, uploadDir: UPLOAD_DIR });
    res.json({ message: 'Session abandonnée', uploadId });
  } catch (err) {
    if (repondreErreurUpload(err, res, 'Session non trouvée', false)) return;
    next(err);
  }
});

export = router;
