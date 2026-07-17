const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const { Transform, PassThrough } = require('stream');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { processMemoryDump } = require('../services/volwebService');
const { safeBasename } = require('../services/uploadService');

const logger = require('../config/logger').default;
const router = express.Router();

const { caseAccessParam } = require('../middleware/caseAccess');
router.use(authenticate);
router.param('caseId', caseAccessParam);

// ── MinIO streaming helpers ──────────────────────────────────────────────────

let _minioStream = null;
let _bucketStream = null;

function getMinioStream() {
  if (_minioStream) return { minio: _minioStream, bucket: _bucketStream };

  const S3_ENDPOINT = (process.env.S3_ENDPOINT || 'http://minio:9000').replace(/\/$/, '');
  const ep = new URL(S3_ENDPOINT);
  _bucketStream = process.env.S3_BUCKET_NAME || 'volweb';

  const accessKey = process.env.AWS_ACCESS_KEY_ID  || process.env.MINIO_ROOT_USER     || '';
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY || process.env.MINIO_ROOT_PASSWORD || '';

  const { Client: MinioClient } = require('minio');
  _minioStream = new MinioClient({
    endPoint:  ep.hostname,
    port:      ep.port ? parseInt(ep.port, 10) : (ep.protocol === 'https:' ? 443 : 80),
    useSSL:    ep.protocol === 'https:',
    accessKey,
    secretKey,
  });
  return { minio: _minioStream, bucket: _bucketStream };
}

async function removeMinioObject(objectKey) {
  try {
    const { minio, bucket } = getMinioStream();
    await new Promise((resolve, reject) => {
      minio.removeObject(bucket, objectKey, (err) => {
        if (err && err.code !== 'NoSuchKey') return reject(err);
        resolve();
      });
    });
    logger.info(`[MinIO] Objet supprimé : ${objectKey}`);
  } catch (err) {
    logger.warn(`[MinIO] Impossible de supprimer "${objectKey}" : ${err.message}`);
  }
}

function streamPartToMinio(minio, bucket, objectKey, partStream) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    const hash_md5    = crypto.createHash('md5');
    const hash_sha1   = crypto.createHash('sha1');
    const hash_sha256 = crypto.createHash('sha256');

    const hashTransform = new Transform({
      transform(chunk, _enc, cb) {
        totalBytes += chunk.length;
        hash_md5.update(chunk);
        hash_sha1.update(chunk);
        hash_sha256.update(chunk);
        cb(null, chunk);
      },
    });

    const passThrough = new PassThrough();
    partStream.pipe(hashTransform).pipe(passThrough);

    minio.putObject(bucket, objectKey, passThrough, { 'Content-Type': 'application/octet-stream' }, (err, objInfo) => {
      if (err) return reject(new Error(`MinIO putObject failed for "${objectKey}": ${err.message}`));
      resolve({
        objectKey,
        size:   totalBytes,
        md5:    hash_md5.digest('hex'),
        sha1:   hash_sha1.digest('hex'),
        sha256: hash_sha256.digest('hex'),
        etag:   objInfo?.etag || '',
      });
    });
  });
}

// ── Legacy disk-storage upload (kept for backward compat) ───────────────────

async function verifyFileIntegrity(filePath, storedHash) {
  return new Promise((resolve) => {
    if (!storedHash) {
      return resolve({ ok: false, stored: null, computed: null, reason: 'no_stored_hash' });
    }
    const hash   = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end',  () => {
      const computed = hash.digest('hex');
      resolve({ ok: computed === storedHash, stored: storedHash, computed });
    });
    stream.on('error', (err) => {
      resolve({ ok: false, stored: storedHash, computed: null, reason: err.message });
    });
  });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(process.env.UPLOAD_DIR || '/app/uploads', req.params.caseId || 'temp');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    cb(null, `${uniqueSuffix}-${safeBasename(file.originalname)}`);
  },
});
const upload = multer({ storage, limits: { fileSize: 32 * 1024 * 1024 * 1024 } });
const uploadFields = upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'additionalFiles', maxCount: 10 },
]);

// ── Routes ───────────────────────────────────────────────────────────────────

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, u.full_name as added_by_name,
        (SELECT COUNT(*) FROM evidence_comments WHERE evidence_id = e.id) as comment_count
      FROM evidence e
      LEFT JOIN users u ON e.added_by = u.id
      WHERE e.case_id = $1
      ORDER BY e.created_at DESC
    `, [req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Legacy disk upload (files ≤ 5 GB, no additional files)
router.post('/:caseId/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    const file = req.files?.['file']?.[0];
    if (!file) return res.status(400).json({ error: 'Fichier requis' });
    const ext  = path.extname(file.filename);
    const stem = path.basename(file.filename, ext);
    const dir  = path.dirname(file.path);

    const additionalFiles = await Promise.all(
      (req.files?.['additionalFiles'] || []).map(async (f) => {
        const newExt  = path.extname(f.originalname);
        const newName = `${stem}${newExt}`;
        const newPath = path.join(dir, newName);
        await fs.promises.rename(f.path, newPath);
        return newPath;
      })
    );
    if (additionalFiles.length) {
      logger.info(`[Evidence] ${additionalFiles.length} fichier(s) additionnel(s) reçu(s) : ${additionalFiles.map(p => path.basename(p)).join(', ')}`);
    }

    logger.info(`Fichier : ${file.path}`);
    const hash_md5    = crypto.createHash('md5');
    const hash_sha1   = crypto.createHash('sha1');
    const hash_sha256 = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(file.path, { highWaterMark: 64 * 1024 });
      stream.on('data', chunk => { hash_md5.update(chunk); hash_sha1.update(chunk); hash_sha256.update(chunk); });
      stream.on('end',   resolve);
      stream.on('error', reject);
    });

    const md5    = hash_md5.digest('hex');
    const sha1   = hash_sha1.digest('hex');
    const sha256 = hash_sha256.digest('hex');

    const { evidence_type, notes } = req.body;

    const additionalFilesMeta = (req.files?.['additionalFiles'] || []).map(f => ({
      name:          path.basename(f.path),
      original_name: f.originalname,
      size:          f.size,
    }));

    const result = await pool.query(
      `INSERT INTO evidence (case_id, name, original_filename, file_path, file_size, evidence_type, hash_md5, hash_sha1, hash_sha256, notes, added_by, chain_of_custody, additional_files)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [
        req.params.caseId, file.originalname, file.originalname, file.path,
        file.size, evidence_type || 'other', md5, sha1, sha256,
        notes, req.user.id,
        JSON.stringify([{ action: 'uploaded', user: req.user.full_name, timestamp: new Date().toISOString(), hash_sha256: sha256 }]),
      ]
    );

    await auditLog(req.user.id, 'upload_evidence', 'evidence', result.rows[0].id, { filename: file.originalname, hash_sha256: sha256 }, req.ip);
    res.status(201).json(result.rows[0]);

    if ((evidence_type || '').toLowerCase() === 'memory') {
      pool.query('SELECT case_number, title FROM cases WHERE id = $1', [req.params.caseId])
        .then(caseRes => {
          if (!caseRes.rows.length) return;
          const { case_number, title } = caseRes.rows[0];
          const osGuess = /linux/i.test(file.originalname) ? 'linux'
            : /mac|osx/i.test(file.originalname) ? 'mac' : 'windows';
          processMemoryDump({
            filePath:        file.path,
            additionalFiles: additionalFiles,
            caseTitle:       title,
            caseNumber:      case_number,
            os:              req.body.dump_os || osGuess,
            heimdallCaseId:  req.params.caseId,
            evidenceId:      result.rows[0].id,
            pool,
            io:              req.app.locals.io,
          });
        })
        .catch(e => logger.warn('[VolWeb] case lookup error:', e.message));
    }
  } catch (err) {
    logger.error('Upload error:', err);
    res.status(500).json({ error: 'Erreur upload' });
  }
});

// Streaming upload direct to MinIO — supports memory dumps up to 256 GB + additional files
router.post('/:caseId/upload-stream', authenticate, async (req, res) => {
  if (!req.headers['content-type']?.includes('multipart/form-data')) {
    return res.status(400).json({ error: 'Content-Type multipart/form-data requis' });
  }

  const caseId = req.params.caseId;

  let caseRow;
  try {
    const caseRes = await pool.query('SELECT case_number, title FROM cases WHERE id = $1', [caseId]);
    if (!caseRes.rows.length) return res.status(404).json({ error: 'Cas introuvable' });
    caseRow = caseRes.rows[0];
  } catch (err) {
    return res.status(500).json({ error: 'Erreur récupération cas' });
  }

  const { case_number, title } = caseRow;
  const caseFolder = String(case_number).replace(/[^a-zA-Z0-9._-]/g, '_');
  const { minio, bucket } = getMinioStream();

  let sharedStem = null;
  const fields  = {};
  const uploads = [];
  let   bbError = false;

  const bb = require('busboy')({
    headers: req.headers,
    limits:  { fileSize: 256 * 1024 * 1024 * 1024, files: 11 },
  });

  bb.on('field', (name, value) => { fields[name] = value; });

  bb.on('file', (fieldname, fileStream, info) => {
    const { filename } = info;
    if (!filename) { fileStream.resume(); return; }

    if (!sharedStem) {
      const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
      const mainExt  = path.extname(filename);
      const mainBase = path.basename(filename, mainExt);
      sharedStem = `${uniqueSuffix}-${mainBase}`;
    }

    const ext       = path.extname(filename);
    const finalName = `${sharedStem}${ext}`;
    const objectKey = `${caseFolder}/${finalName}`;

    logger.info(`[Stream] Réception "${filename}" → ${bucket}/${objectKey}…`);

    const promise = streamPartToMinio(minio, bucket, objectKey, fileStream)
      .then(result => {
        logger.info(`[Stream] "${finalName}" ok — ${(result.size / 1024 / 1024).toFixed(1)} MB`);
        return { fieldname, filename, finalName, ...result };
      })
      .catch(err => {
        bbError = true;
        logger.error(`[Stream] Erreur upload "${filename}" : ${err.message}`);
        if (!res.headersSent) res.status(500).json({ error: err.message });
        throw err;
      });

    uploads.push(promise);
  });

  bb.on('finish', async () => {
    if (bbError) return;
    try {
      const results         = await Promise.all(uploads);
      const mainResult      = results.find(r => r.fieldname === 'file');
      const additionalResults = results.filter(r => r.fieldname === 'additionalFiles');

      if (!mainResult) return res.status(400).json({ error: 'Champ "file" manquant' });

      const dumpOs        = fields.dump_os       || 'windows';
      const evidenceType  = fields.evidence_type || 'memory';

      const additionalFilesMeta = additionalResults.map(r => ({
        name:          r.finalName,
        original_name: r.filename,
        size:          r.size,
        object_key:    r.objectKey,
      }));

      const dbResult = await pool.query(
        `INSERT INTO evidence
           (case_id, name, original_filename, file_path, file_size,
            evidence_type, hash_md5, hash_sha1, hash_sha256,
            notes, added_by, chain_of_custody, additional_files)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         RETURNING *`,
        [
          caseId,
          mainResult.filename,
          mainResult.filename,
          `minio://${bucket}/${mainResult.objectKey}`,
          mainResult.size,
          evidenceType,
          mainResult.md5,
          mainResult.sha1,
          mainResult.sha256,
          null,
          req.user.id,
          JSON.stringify([{
            action:    'uploaded_stream',
            user:      req.user.full_name,
            timestamp: new Date().toISOString(),
            objectKey: mainResult.objectKey,
            finalName: mainResult.finalName,
            hash_sha256: mainResult.sha256,
          }]),
          JSON.stringify(additionalFilesMeta),
        ]
      );

      const evidence = dbResult.rows[0];

      await auditLog(req.user.id, 'upload_evidence_stream', 'evidence', evidence.id, {
        filename:   mainResult.filename,
        objectKey:  mainResult.objectKey,
        hash_sha256: mainResult.sha256,
        additionals: additionalResults.length,
      }, req.ip);

      res.status(201).json(evidence);

      if (evidenceType === 'memory') {
        processMemoryDump({
          s3ObjectKey:    mainResult.objectKey,
          additionalKeys: additionalResults.map(r => r.objectKey),
          caseTitle:      title,
          caseNumber:     case_number,
          os:             dumpOs,
          heimdallCaseId: caseId,
          evidenceId:     evidence.id,
          pool,
          io:             req.app.locals.io,
        }).catch(e => logger.warn('[VolWeb] processMemoryDump error:', e.message));
      }
    } catch (err) {
      logger.error(`[Stream] finish error : ${err.message}`);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    }
  });

  bb.on('error', (err) => {
    logger.error(`[Stream] busboy error : ${err.message}`);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  });

  req.pipe(bb);
});

router.put('/:id/highlight', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE evidence SET is_highlighted = NOT is_highlighted, updated_at = NOW() WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /:id/hex ──────────────────────────────────────────────────────────────
router.get('/:id/hex', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT file_path, name, scan_status, hash_sha256 FROM evidence WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    if (result.rows[0].scan_status === 'quarantined') {
      return res.status(403).json({ error: 'Accès refusé — fichier en quarantaine' });
    }

    const { file_path: filePath, name, hash_sha256: storedHash } = result.rows[0];
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé sur le disque' });
    }

    const offset = parseInt(req.query.offset) || 0;
    const length = Math.min(parseInt(req.query.length) || 512, 4096);

    const fd       = fs.openSync(filePath, 'r');
    const buffer   = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buffer, 0, length, offset);
    fs.closeSync(fd);

    const stats     = fs.statSync(filePath);
    const integrity = await verifyFileIntegrity(filePath, storedHash);
    if (!integrity.ok) res.setHeader('X-Integrity-Alert', 'true');

    res.json({
      name,
      total_size:  stats.size,
      offset,
      length:      bytesRead,
      hex:   buffer.slice(0, bytesRead).toString('hex'),
      ascii: buffer.slice(0, bytesRead).toString('ascii').replace(/[^\x20-\x7E]/g, '.'),
      integrity_ok: integrity.ok,
      ...(integrity.ok ? {} : { integrity_alert: true, stored_hash: integrity.stored, computed_hash: integrity.computed }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lecture hex' });
  }
});

// ── GET /:id/strings ──────────────────────────────────────────────────────────
router.get('/:id/strings', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT file_path, scan_status, hash_sha256 FROM evidence WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    if (result.rows[0].scan_status === 'quarantined') {
      return res.status(403).json({ error: 'Accès refusé — fichier en quarantaine' });
    }

    const { file_path: filePath, hash_sha256: storedHash } = result.rows[0];
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé' });
    }

    const minLength = parseInt(req.query.min_length) || 4;
    const strings   = [];
    let   current   = '';
    let   byteOffset   = 0;
    let   currentOffset = 0;

    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
      stream.on('data', chunk => {
        if (strings.length >= 1000) { stream.destroy(); return; }
        for (let i = 0; i < chunk.length && strings.length < 1000; i++) {
          const byte = chunk[i];
          if (byte >= 0x20 && byte <= 0x7E) {
            if (current.length === 0) currentOffset = byteOffset + i;
            current += String.fromCharCode(byte);
          } else {
            if (current.length >= minLength) {
              strings.push({ offset: currentOffset, value: current, length: current.length });
            }
            current = '';
          }
        }
        byteOffset += chunk.length;
      });
      stream.on('end', () => {
        if (current.length >= minLength) strings.push({ offset: currentOffset, value: current, length: current.length });
        resolve();
      });
      stream.on('error',  reject);
      stream.on('close',  resolve);
    });

    const integrity = await verifyFileIntegrity(filePath, storedHash);
    if (!integrity.ok) res.setHeader('X-Integrity-Alert', 'true');

    res.json({
      total: strings.length,
      strings,
      integrity_ok: integrity.ok,
      ...(integrity.ok ? {} : { integrity_alert: true, stored_hash: integrity.stored, computed_hash: integrity.computed }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur extraction strings' });
  }
});

// ── GET /:id/integrity ────────────────────────────────────────────────────────
router.get('/:id/integrity', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT file_path, name, hash_sha256, scan_status FROM evidence WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    const { file_path: filePath, name, hash_sha256: storedHash } = result.rows[0];

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé sur le disque', integrity_ok: false });
    }

    const integrity = await verifyFileIntegrity(filePath, storedHash);

    res.json({
      evidence_id:   req.params.id,
      name,
      integrity_ok:  integrity.ok,
      stored_hash:   integrity.stored,
      computed_hash: integrity.computed,
      ...(integrity.reason ? { reason: integrity.reason } : {}),
    });
  } catch (err) {
    logger.error('Integrity check error:', err);
    res.status(500).json({ error: 'Erreur vérification intégrité' });
  }
});

// ── GET /:id/comments ─────────────────────────────────────────────────────────
router.get('/:id/comments', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ec.*, u.full_name as author, u.role as author_role
      FROM evidence_comments ec
      JOIN users u ON ec.user_id = u.id
      WHERE ec.evidence_id = $1
      ORDER BY ec.is_pinned DESC, ec.created_at DESC
    `, [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /:id/comments ────────────────────────────────────────────────────────
router.post('/:id/comments', authenticate, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Contenu requis' });

    const result = await pool.query(
      'INSERT INTO evidence_comments (evidence_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, req.user.id, content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── DELETE /:id ───────────────────────────────────────────────────────────────
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const row = await pool.query(
      'SELECT file_path, name, additional_files FROM evidence WHERE id = $1',
      [req.params.id]
    );
    if (row.rows.length === 0) return res.status(404).json({ error: 'Preuve introuvable' });

    const { file_path, name, additional_files } = row.rows[0];

    // ── Delete main file ──────────────────────────────────────────────────
    if (file_path) {
      if (file_path.startsWith('minio://')) {
        const objectKey = file_path.replace(/^minio:\/\/[^/]+\//, '');
        await removeMinioObject(objectKey);
      } else if (fs.existsSync(file_path)) {
        const stat = fs.statSync(file_path);
        if (stat.isDirectory()) {
          fs.rmSync(file_path, { recursive: true, force: true });
        } else {
          fs.unlinkSync(file_path);
        }
        logger.info(`[Evidence] Fichier disque supprimé : ${file_path}`);
      }
    }

    // ── Delete additional files ────────────────────────────────────────────
    let additionals = [];
    try {
      additionals = typeof additional_files === 'string'
        ? JSON.parse(additional_files)
        : (additional_files || []);
    } catch { additionals = []; }

    for (const af of additionals) {
      if (af.object_key) {
        await removeMinioObject(af.object_key);
      } else if (af.name) {
        const dir      = file_path && !file_path.startsWith('minio://') ? path.dirname(file_path) : null;
        const fullPath = dir ? path.join(dir, safeBasename(af.name)) : null;
        if (fullPath && fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
          logger.info(`[Evidence] Fichier additionnel disque supprimé : ${fullPath}`);
        }
      }
    }

    // ── Delete from DB ─────────────────────────────────────────────────────
    await pool.query('DELETE FROM evidence_comments WHERE evidence_id = $1', [req.params.id]);
    await pool.query('DELETE FROM parser_results WHERE evidence_id = $1', [req.params.id]);
    await pool.query('UPDATE timeline_events SET evidence_id = NULL WHERE evidence_id = $1', [req.params.id]);
    await pool.query('DELETE FROM evidence WHERE id = $1', [req.params.id]);

    await auditLog(req.user.id, 'delete_evidence', 'evidence', req.params.id, { name }, req.ip);
    res.json({ success: true });
  } catch (err) {
    logger.error('Delete evidence error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
