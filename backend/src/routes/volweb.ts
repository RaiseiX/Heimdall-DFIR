import express from 'express';
import logger from '../config/logger';
import path    from 'path';
import fs      from 'fs';
import crypto  from 'crypto';

const { authenticate, auditLog } = require('../middleware/auth');
const { pool }                   = require('../config/database');
const {
  generateMagicToken,
  consumeMagicToken,
  getVolWebCaseStatus,
  processMemoryDump,
  VOLWEB_PUBLIC_URL,
  VOLWEB_TOKEN_KEY,
  MAGIC_TOKEN_TTL,
} = require('../services/volwebService');

const IORedis = require('ioredis');

const router = express.Router();

const MEMORY_CHUNK_SIZE = 50 * 1024 * 1024;

let _redis: any = null;
function getRedis() {
  if (!_redis) {
    _redis = new IORedis({
      host:            process.env.REDIS_HOST    || 'redis',
      port:            Number(process.env.REDIS_PORT) || 6379,
      password:        process.env.REDIS_PASSWORD || undefined,
      enableReadyCheck: false,
      lazyConnect:     true,
    });
  }
  return _redis;
}

router.get('/magic-link', authenticate, async (req: any, res) => {
  const { caseId } = req.query as { caseId?: string };
  if (!caseId) return res.status(400).json({ error: 'caseId requis' });

  try {
    const caseRes = await pool.query(
      `SELECT id, case_number, title, volweb_case_id
       FROM cases
       WHERE id = $1
         AND (investigator_id = $2 OR created_by = $2 OR $3 = 'admin')`,
      [caseId, req.user.id, req.user.role]
    );
    if (!caseRes.rows.length) return res.status(403).json({ error: 'Accès refusé à ce cas' });

    const caseRow = caseRes.rows[0];
    if (!caseRow.volweb_case_id) {
      return res.status(404).json({
        error: 'Aucun cas VolWeb lié. Uploadez d\'abord un dump mémoire.',
        code:  'NO_VOLWEB_CASE',
      });
    }

    const token = await generateMagicToken(getRedis(), req.user.id, caseRow.volweb_case_id);
    const url   = `${VOLWEB_PUBLIC_URL}/heimdall-sso/${token}`;

    res.json({ url, expiresIn: MAGIC_TOKEN_TTL });
  } catch (err: any) {
    logger.error('[VolWeb] magic-link error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.get('/sso/:token', async (req, res) => {
  const { token } = req.params;

  const errorPage = (msg: string) => `<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Heimdall SSO</title>
<style>body{margin:0;background:#0d1117;color:#da3633;font-family:monospace;
display:flex;align-items:center;justify-content:center;height:100vh;font-size:13px}</style>
</head><body><p>⚠ ${msg}</p></body></html>`;

  if (!token || !/^[0-9a-f-]{36}$/.test(token)) {
    return res.status(400).send(errorPage('Token invalide.'));
  }

  try {
    const data = await consumeMagicToken(getRedis(), token);
    if (!data) return res.status(410).send(errorPage('Token expiré ou déjà utilisé.'));

    const { volwebCaseId, volwebJwt } = data;
    const caseUrl    = `/cases/${volwebCaseId}/`;
    const escapedJwt = JSON.stringify(String(volwebJwt));
    const escapedKey = JSON.stringify(String(VOLWEB_TOKEN_KEY));
    const escapedUrl = JSON.stringify(caseUrl);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Heimdall SSO → VolWeb</title>
  <style>
    body { margin: 0; background: #0d1117; color: #4d82c0; font-family: monospace;
           display: flex; align-items: center; justify-content: center; height: 100vh; }
    p    { font-size: 13px; opacity: 0.8; }
    .dot { animation: blink 0.8s step-end infinite; }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  </style>
</head>
<body>
  <p>Authentification Heimdall SSO<span class="dot">▌</span></p>
  <script>
    (function () {
      try {
        localStorage.setItem(${escapedKey}, ${escapedJwt});
        window.location.replace(${escapedUrl});
      } catch (e) {
        document.querySelector('p').textContent = '✗ SSO échoué : ' + e.message;
      }
    })();
  </script>
</body>
</html>`);
  } catch (err: any) {
    logger.error('[VolWeb] SSO error:', err.message);
    res.status(500).send(errorPage('Erreur serveur SSO.'));
  }
});

router.get('/status/:caseId', authenticate, async (req: any, res) => {
  try {
    const { caseId } = req.params;
    const caseRes = await pool.query(
      'SELECT volweb_case_id FROM cases WHERE id = $1',
      [caseId]
    );
    if (!caseRes.rows.length) return res.status(404).json({ error: 'Cas non trouvé' });

    const { volweb_case_id } = caseRes.rows[0];
    if (!volweb_case_id) return res.json({ linked: false });

    const [evidenceRes, volwebStatus] = await Promise.all([
      pool.query(
        `SELECT id, name, original_filename, volweb_evidence_id, volweb_status, created_at
         FROM evidence
         WHERE case_id = $1 AND evidence_type = 'memory'
         ORDER BY created_at DESC LIMIT 10`,
        [caseId]
      ),
      getVolWebCaseStatus(volweb_case_id),
    ]);

    res.json({
      linked:       true,
      volwebCaseId: volweb_case_id,
      volwebMeta:   volwebStatus,
      evidence:     evidenceRes.rows,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

const TEMP_DIR    = process.env.TEMP_DIR    || '/app/temp';
const UPLOADS_DIR = process.env.UPLOAD_DIR  || '/app/uploads';

fs.mkdirSync(TEMP_DIR,    { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

router.post('/memory/:caseId/initiate', authenticate, async (req: any, res) => {
  const { caseId } = req.params;
  const { filename, total_size, total_chunks, dump_os = 'windows' } = req.body;

  if (!filename || !total_size || !total_chunks)
    return res.status(400).json({ error: 'filename, total_size et total_chunks requis' });

  if (!['windows', 'linux', 'mac'].includes(dump_os))
    return res.status(400).json({ error: 'dump_os invalide (windows|linux|mac)' });

  try {
    const caseRes = await pool.query(
      `SELECT id FROM cases WHERE id = $1
         AND (investigator_id = $2 OR created_by = $2 OR $3 = 'admin')`,
      [caseId, req.user.id, req.user.role]
    );
    if (!caseRes.rows.length) return res.status(403).json({ error: 'Accès refusé' });

    const uploadId = crypto.randomUUID();
    const tempDir  = path.join(TEMP_DIR, `memory-${uploadId}`);
    fs.mkdirSync(tempDir, { recursive: true });
    const tempPath = path.join(tempDir, 'dump.bin');

    const fd = fs.openSync(tempPath, 'w');
    try { fs.ftruncateSync(fd, Number(total_size)); } finally { fs.closeSync(fd); }

    const result = await pool.query(
      `INSERT INTO memory_uploads
         (id, case_id, filename, total_size, dump_os, temp_path, total_chunks, chunk_size, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [uploadId, caseId, filename, total_size, dump_os, tempPath, total_chunks, MEMORY_CHUNK_SIZE, req.user.id]
    );

    res.status(201).json({
      upload_id:  result.rows[0].id,
      chunk_size: MEMORY_CHUNK_SIZE,
    });
  } catch (err: any) {
    logger.error('[MemUpload] initiate error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/memory/:caseId/chunk', authenticate, async (req: any, res) => {
  const upload_id   = (req.query.upload_id   || req.body?.upload_id)   as string;
  const chunk_index = Number(req.query.chunk_index ?? req.body?.chunk_index);

  if (!upload_id || isNaN(chunk_index))
    return res.status(400).json({ error: 'upload_id et chunk_index requis (query params)' });

  try {
    const uploadRes = await pool.query(
      `SELECT id, temp_path, total_chunks, chunk_size, total_size,
              received_chunks_set, received_chunks
       FROM memory_uploads
       WHERE id = $1 AND case_id = $2 AND status = 'uploading'`,
      [upload_id, req.params.caseId]
    );
    if (!uploadRes.rows.length)
      return res.status(404).json({ error: 'Upload non trouvé ou déjà terminé' });

    const upload = uploadRes.rows[0];

    if (chunk_index < 0 || chunk_index >= upload.total_chunks)
      return res.status(400).json({ error: `chunk_index hors limites (0..${upload.total_chunks - 1})` });

    const receivedSet: number[] = upload.received_chunks_set || [];
    if (receivedSet.includes(chunk_index)) {
      const count = receivedSet.length;
      return res.json({
        received: count,
        total:    upload.total_chunks,
        progress: Math.round((count / upload.total_chunks) * 100),
      });
    }

    const chunkSize = Number(upload.chunk_size) || MEMORY_CHUNK_SIZE;
    const offset    = chunk_index * chunkSize;
    const maxBytes  = chunkSize + 1024;
    let bytesReceived = 0;

    const writeStream = fs.createWriteStream(upload.temp_path, { flags: 'r+', start: offset });

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      function fail(err: Error) {
        if (settled) return;
        settled = true;
        writeStream.destroy();
        req.destroy();
        reject(err);
      }

      req.on('data', (buf: Buffer) => {
        bytesReceived += buf.length;
        if (bytesReceived > maxBytes) {
          fail(new Error(`Chunk trop grand : ${bytesReceived} octets reçus (max ${maxBytes})`));
        }
      });

      req.pipe(writeStream);
      writeStream.on('finish', () => { settled = true; resolve(); });
      writeStream.on('error', fail);
      req.on('error', fail);
      req.on('close', () => {
        if (!req.readableEnded) fail(new Error('Connexion interrompue par le client'));
      });
    });

    const updateRes = await pool.query(
      `UPDATE memory_uploads
       SET received_chunks_set = array_append(received_chunks_set, $1),
           received_chunks     = array_length(array_append(received_chunks_set, $1), 1),
           updated_at          = NOW()
       WHERE id = $2
       RETURNING array_length(received_chunks_set, 1) AS count`,
      [chunk_index, upload_id]
    );

    const count = updateRes.rows[0]?.count || receivedSet.length + 1;
    res.json({
      received: count,
      total:    upload.total_chunks,
      progress: Math.round((count / upload.total_chunks) * 100),
    });
  } catch (err: any) {
    logger.error('[MemUpload] chunk error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/memory/:caseId/complete', authenticate, async (req: any, res) => {
  const { upload_id } = req.body;
  if (!upload_id) return res.status(400).json({ error: 'upload_id requis' });

  try {
    const uploadRes = await pool.query(
      `SELECT * FROM memory_uploads WHERE id = $1 AND case_id = $2`,
      [upload_id, req.params.caseId]
    );
    if (!uploadRes.rows.length) return res.status(404).json({ error: 'Upload non trouvé' });
    const upload = uploadRes.rows[0];

    const receivedSet: number[] = upload.received_chunks_set || [];
    const missing: number[] = [];
    for (let i = 0; i < upload.total_chunks; i++) {
      if (!receivedSet.includes(i)) missing.push(i);
    }
    if (missing.length > 0) {
      return res.status(409).json({
        error: `Upload incomplet : ${receivedSet.length}/${upload.total_chunks} chunks reçus`,
        missing_chunks: missing.slice(0, 20),
      });
    }

    await pool.query(
      "UPDATE memory_uploads SET status = 'hashing', updated_at = NOW() WHERE id = $1",
      [upload_id]
    );

    const finalDir  = path.join(UPLOADS_DIR, req.params.caseId);
    fs.mkdirSync(finalDir, { recursive: true });
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const finalPath = path.join(finalDir, `${uniqueSuffix}-${upload.filename}`);

    try {
      await fs.promises.rename(upload.temp_path, finalPath);
    } catch (renameErr: any) {
      if (renameErr.code === 'EXDEV') {
        await fs.promises.copyFile(upload.temp_path, finalPath);
        await fs.promises.unlink(upload.temp_path);
      } else {
        throw renameErr;
      }
    }

    const tempDir = path.dirname(upload.temp_path);
    fs.rmSync(tempDir, { recursive: true, force: true });

    const hashMd5    = crypto.createHash('md5');
    const hashSha1   = crypto.createHash('sha1');
    const hashSha256 = crypto.createHash('sha256');
    await new Promise<void>((resolve, reject) => {
      const stream = fs.createReadStream(finalPath, { highWaterMark: 64 * 1024 });
      stream.on('data', chunk => {
        hashMd5.update(chunk);
        hashSha1.update(chunk);
        hashSha256.update(chunk);
      });
      stream.on('end',   resolve);
      stream.on('error', reject);
    });
    const md5    = hashMd5.digest('hex');
    const sha1   = hashSha1.digest('hex');
    const sha256 = hashSha256.digest('hex');

    const evidenceRes = await pool.query(
      `INSERT INTO evidence
         (case_id, name, original_filename, file_path, file_size, evidence_type,
          hash_md5, hash_sha1, hash_sha256, added_by, volweb_status, chain_of_custody)
       VALUES ($1, $2, $3, $4, $5, 'memory', $6, $7, $8, $9, 'uploading', $10)
       RETURNING *`,
      [
        req.params.caseId,
        upload.filename,
        upload.filename,
        finalPath,
        upload.total_size,
        md5, sha1, sha256,
        req.user.id,
        JSON.stringify([{
          action:     'uploaded',
          user:       req.user.full_name,
          timestamp:  new Date().toISOString(),
          hash_sha256: sha256,
        }]),
      ]
    );
    const evidence = evidenceRes.rows[0];

    await pool.query(
      "UPDATE memory_uploads SET evidence_id = $1, status = 'forwarding', updated_at = NOW() WHERE id = $2",
      [evidence.id, upload_id]
    );

    await auditLog(req.user.id, 'upload_memory_dump', 'evidence', evidence.id,
      { filename: upload.filename, hash_sha256: sha256 }, req.ip);

    res.status(201).json(evidence);

    const caseRes = await pool.query(
      'SELECT case_number, title FROM cases WHERE id = $1',
      [req.params.caseId]
    );
    if (!caseRes.rows.length) return;

    const { case_number, title } = caseRes.rows[0];
    const io = req.app.locals.io;

    processMemoryDump({
      filePath:       finalPath,
      caseTitle:      title,
      caseNumber:     case_number,
      os:             upload.dump_os,
      heimdallCaseId: req.params.caseId,
      evidenceId:     evidence.id,
      pool,
      io,
      onResult: async (err: any, result: any) => {
        const volwebStatus = err ? 'error' : 'processing';
        const uploadStatus = err ? 'error' : 'forwarding';

        pool.query(
          'UPDATE memory_uploads SET status = $1, error_message = $2, updated_at = NOW() WHERE id = $3',
          [uploadStatus, err?.message || null, upload_id]
        ).catch(e => logger.warn('[MemUpload] memory_uploads update failed:', e.message));

        await pool.query(
          'UPDATE evidence SET volweb_status = $1, volweb_evidence_id = $2, updated_at = NOW() WHERE id = $3',
          [volwebStatus, result?.evidenceId ?? null, evidence.id]
        ).catch(e => logger.warn('[MemUpload] evidence update failed:', e.message));

        if (io) {
          const emitEvent = err ? 'volweb:ready' : 'volweb:processing';
          io.to(`case:${req.params.caseId}`).emit(emitEvent, {
            caseId:     req.params.caseId,
            evidenceId: evidence.id,
            status:     volwebStatus,
            error:      err?.message || null,
            url:        result?.url || null,
          });
        }
      },
    });

  } catch (err: any) {
    logger.error('[MemUpload] complete error:', err.message);
    await pool.query(
      "UPDATE memory_uploads SET status = 'error', error_message = $1, updated_at = NOW() WHERE id = $2",
      [err.message, upload_id]
    ).catch(() => {});
    res.status(500).json({ error: err.message });
  }
});

router.get('/memory/:caseId/status/:uploadId', authenticate, async (req: any, res) => {
  try {
    const { caseId, uploadId } = req.params;
    const r = await pool.query(
      `SELECT id, status, total_chunks, chunk_size, received_chunks_set, total_size, filename
       FROM memory_uploads
       WHERE id = $1 AND case_id = $2`,
      [uploadId, caseId]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Upload non trouvé' });

    const u = r.rows[0];
    res.json({
      upload_id:           u.id,
      status:              u.status,
      total_chunks:        u.total_chunks,
      chunk_size:          Number(u.chunk_size),
      received_chunks_set: u.received_chunks_set || [],
      total_size:          Number(u.total_size),
      filename:            u.filename,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/evidence-progress/:caseId/:evidenceId', authenticate, async (req: any, res) => {
  const { caseId, evidenceId } = req.params;
  try {
    const evRes = await pool.query(
      `SELECT volweb_evidence_id, volweb_status
       FROM evidence WHERE id = $1 AND case_id = $2`,
      [evidenceId, caseId]
    );
    if (!evRes.rows.length) return res.status(404).json({ error: 'Evidence non trouvée' });
    const ev = evRes.rows[0];

    if (!ev.volweb_evidence_id) {
      return res.json({ volweb_status: ev.volweb_status, progress: null });
    }

    const { getAdminToken } = require('../services/volwebService');
    const VOLWEB_URL = (process.env.VOLWEB_URL || 'http://hel-api:8000').replace(/\/$/, '');

    const token = await getAdminToken();
    const http  = require('http');
    const https = require('https');

    const fetchJson = (url: string, authToken: string) => new Promise<any>((resolve, reject) => {
      const parsed = new URL(url);
      const lib    = parsed.protocol === 'https:' ? https : http;
      const opts   = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   'GET',
        headers:  { Authorization: `Bearer ${authToken}` },
      };
      const req2 = lib.request(opts, (r: any) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => {
          try { resolve({ status: r.statusCode, data: JSON.parse(Buffer.concat(chunks).toString()) }); }
          catch { resolve({ status: r.statusCode, data: null }); }
        });
      });
      req2.on('error', reject);
      req2.end();
    });

    const [evDetail, tasksDetail] = await Promise.all([
      fetchJson(`${VOLWEB_URL}/api/evidences/${ev.volweb_evidence_id}/`, token),
      fetchJson(`${VOLWEB_URL}/api/evidences/${ev.volweb_evidence_id}/tasks/`, token),
    ]);

    const statusMap: Record<number, string> = { [-2]: 'awaiting', 0: 'running', 100: 'completed', [-1]: 'error' };
    const rawStatus   = evDetail.data?.status;
    const tasks       = Array.isArray(tasksDetail.data) ? tasksDetail.data
                      : (tasksDetail.data?.results ?? []);
    const tasksDone   = tasks.filter((t: any) => t.status === 100 || t.finished_at).length;
    const tasksTotal  = tasks.length;

    res.json({
      volweb_status:      ev.volweb_status,
      volweb_evidence_id: ev.volweb_evidence_id,
      progress: {
        volweb_raw_status: rawStatus,
        status_label:      statusMap[rawStatus] ?? String(rawStatus),
        tasks_done:        tasksDone,
        tasks_total:       tasksTotal,
        pct:               tasksTotal > 0 ? Math.round((tasksDone / tasksTotal) * 100) : 0,
        plugins:           tasks.map((t: any) => ({
          name:     t.plugin_name || t.name,
          status:   t.status,
          done:     t.status === 100 || !!t.finished_at,
        })),
      },
    });
  } catch (err: any) {
    logger.error('[VolWeb] evidence-progress error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/memory/:caseId/retry/:evidenceId', authenticate, async (req: any, res) => {
  const { caseId, evidenceId } = req.params;

  try {
    const caseRes = await pool.query(
      `SELECT id, case_number, title FROM cases
       WHERE id = $1 AND (investigator_id = $2 OR created_by = $2 OR $3 = 'admin')`,
      [caseId, req.user.id, req.user.role]
    );
    if (!caseRes.rows.length) return res.status(403).json({ error: 'Accès refusé' });
    const { case_number, title } = caseRes.rows[0];

    const evRes = await pool.query(
      `SELECT id, file_path, original_filename, volweb_status
       FROM evidence
       WHERE id = $1 AND case_id = $2 AND evidence_type = 'memory'`,
      [evidenceId, caseId]
    );
    if (!evRes.rows.length) return res.status(404).json({ error: 'Evidence non trouvée' });
    const ev = evRes.rows[0];

    if (!fs.existsSync(ev.file_path)) {
      return res.status(410).json({ error: `Fichier introuvable sur le disque : ${ev.file_path}` });
    }

    await pool.query(
      "UPDATE evidence SET volweb_status = 'uploading', updated_at = NOW() WHERE id = $1",
      [evidenceId]
    );

    res.json({ message: 'Pipeline VolWeb relancé', evidenceId });

    const io = req.app.locals.io;
    processMemoryDump({
      filePath:       ev.file_path,
      caseTitle:      title,
      caseNumber:     case_number,
      os:             'windows',
      heimdallCaseId: caseId,
      evidenceId,
      pool,
      io,
      onResult: async (err: any, result: any) => {
        const volwebStatus = err ? 'error' : 'processing';
        await pool.query(
          'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
          [volwebStatus, evidenceId]
        ).catch(e => logger.warn('[VolWeb] retry onResult DB update failed:', e.message));

        if (io) {
          io.to(`case:${caseId}`).emit(err ? 'volweb:ready' : 'volweb:processing', {
            caseId, evidenceId,
            status: volwebStatus,
            error:  err?.message || null,
            url:    result?.url || null,
          });
        }
      },
    });

  } catch (err: any) {
    logger.error('[VolWeb] retry error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

export = router;
