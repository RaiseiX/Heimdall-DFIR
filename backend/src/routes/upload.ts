
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
  getSessionStatus,
} from '../services/uploadService';
import { scanFile } from '../services/clamavService';

const router = express.Router();

function getPool(res: Response): Pool {
  return res.app.locals.pool as Pool;
}

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';

const initSchema = Joi.object({
  originalName: Joi.string().max(255).required(),
  totalSize: Joi.number().integer().min(1).required(),
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

    const result = initUpload({
      originalName: value.originalName,
      totalSize: value.totalSize,
      caseId: value.caseId,
      userId: req.user.id,
      uploadDir: UPLOAD_DIR,
    });

    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
});

router.get('/status/:uploadId', (req: AuthRequest, res: Response) => {
  const status = getSessionStatus(req.params.uploadId);
  if (!status.found) return res.status(404).json({ error: 'Session non trouvée' });
  res.json(status);
});

router.post('/chunk', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const uploadId = req.query['uploadId'] as string;
    const chunkIndex = parseInt(req.query['chunkIndex'] as string, 10);

    if (!uploadId) return res.status(400).json({ error: 'uploadId requis' });
    if (isNaN(chunkIndex)) return res.status(400).json({ error: 'chunkIndex invalide' });

    const declaredSize = parseInt(req.headers['content-length'] ?? '0', 10);
    if (declaredSize > 55 * 1024 * 1024) {
      return res.status(413).json({ error: 'Chunk trop grand (max 55 Mo)' });
    }

    const ack = await receiveChunk({
      uploadId,
      chunkIndex,
      req,
      uploadDir: UPLOAD_DIR,
    });

    res.json(ack);
  } catch (err) {
    next(err);
  }
});

router.post('/complete', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const { error, value } = completeSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const pool = getPool(res);

    const caseCheck = await pool.query('SELECT id FROM cases WHERE id = $1', [value.caseId]);
    if (caseCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Cas non trouvé' });
    }

    const fileInfo = await completeUpload({
      uploadId: value.uploadId,
      caseId: value.caseId,
      userId: req.user.id,
      finalDir: UPLOAD_DIR,
    });

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

    const evidenceResult = await pool.query(
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

    const evidence = evidenceResult.rows[0];

    await pool.query(
      `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        req.user.id,
        'upload_evidence_chunked',
        'evidence',
        evidence.id,
        JSON.stringify({
          filename:    fileInfo.name,
          size:        fileInfo.fileSize,
          hash_sha256: fileInfo.hash_sha256,
          uploadId:    value.uploadId,
          scan_status: scanStatus,
          scan_threat: scanThreat,
        }),
        req.ip,
      ]
    );

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
    next(err);
  }
});

router.delete('/:uploadId', async (req: AuthRequest, res: Response) => {
  const { uploadId } = req.params;
  const status = getSessionStatus(uploadId);
  if (!status.found) return res.status(404).json({ error: 'Session non trouvée' });

  res.json({ message: 'Session abandonnée', uploadId });
});

export = router;
