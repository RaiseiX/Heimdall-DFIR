'use strict';

const fs       = require('fs');
const path     = require('path');
const http     = require('http');
const https    = require('https');
const FormData = require('form-data');
const { v4: uuidv4 } = require('uuid');
const logger = require('../config/logger').default;

const VOLWEB_URL        = (process.env.VOLWEB_URL || 'http://hel-api:8000').replace(/\/$/, '');
const VOLWEB_USER       = process.env.VOLWEB_USER       || 'admin';
const VOLWEB_PASSWORD   = process.env.VOLWEB_PASSWORD   || '';
const VOLWEB_PUBLIC_URL = (process.env.VOLWEB_PUBLIC_URL || 'http://localhost:8888').replace(/\/$/, '');
const VOLWEB_TOKEN_KEY  = process.env.VOLWEB_TOKEN_KEY  || 'access_token';

const S3_ENDPOINT    = (process.env.AWS_ENDPOINT_HOST || 'minio:9000').replace(/\/$/, '');
const S3_ACCESS_KEY  = process.env.AWS_ACCESS_KEY_ID      || 'admin';
const S3_SECRET_KEY  = process.env.AWS_SECRET_ACCESS_KEY  || '';
const S3_REGION      = process.env.AWS_REGION             || 'us-east-1';
const S3_FORCE_PATH  = process.env.S3_FORCE_PATH         !== 'true';
const S3_SELF_SIGNED = process.env.S3_SELF_SIGNED        !== 'true';

let _adminTokenCache   = null;
let _adminTokenExpires = 0;

// ─── HTTP helper ─────────────────────────────────────────────────────────────

function request(method, url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed   = new URL(url);
    const lib      = parsed.protocol === 'https:' ? https : http;
    const isBuffer = body instanceof Buffer;
    const reqBody  = isBuffer ? body : (body ? JSON.stringify(body) : null);

    const opts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': isBuffer ? 'application/octet-stream' : 'application/json',
        ...(reqBody ? { 'Content-Length': isBuffer ? reqBody.length : Buffer.byteLength(reqBody) } : {}),
        ...headers,
      },
    };

    const req = lib.request(opts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8');
        try { resolve({ status: res.statusCode, data: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, data: raw }); }
      });
    });
    req.on('error', reject);
    if (reqBody) req.write(reqBody);
    req.end();
  });
}

const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

function clearAdminTokenCache() {
  _adminTokenCache   = null;
  _adminTokenExpires = 0;
}

async function getAdminToken({ forceRefresh = false } = {}) {
  if (!VOLWEB_PASSWORD) throw new Error('VOLWEB_PASSWORD non configuré');
  const now = Date.now();
  if (!forceRefresh && _adminTokenCache && now < _adminTokenExpires) return _adminTokenCache;

  const res = await request('POST', `${VOLWEB_URL}/core/token/`,
    { username: VOLWEB_USER, password: VOLWEB_PASSWORD });
  if (!res.data?.access) throw new Error(`VolWeb auth failed: ${JSON.stringify(res.data)}`);

  _adminTokenCache   = res.data.access;
  _adminTokenExpires = now + 8 * 60 * 1000;
  return _adminTokenCache;
}

async function requestWithRetry(method, url, body, headers = {}) {
  const res = await request(method, url, body, headers);
  if (res.status === 401) {
    logger.warn('[VolWeb] 401 received — clearing token cache and retrying');
    clearAdminTokenCache();
    const freshToken = await getAdminToken();
    return request(method, url, body, { ...headers, Authorization: `Bearer ${freshToken}` });
  }
  return res;
}

const getToken = getAdminToken;

// ─── VolWeb case management ───────────────────────────────────────────────────

async function createVolWebCase(token, name, description) {
  const res = await requestWithRetry('POST', `${VOLWEB_URL}/api/cases/`,
    { name, description: description || 'Importé depuis Heimdall' }, authHeader(token));

  if (res.status === 201 && res.data?.id) return res.data;

  if (res.status === 409 || res.status === 400) {
    logger.warn(`[VolWeb] Cas creation returned ${res.status} for "${name}", recherche par nom…`);
    const listRes = await request('GET', `${VOLWEB_URL}/api/cases/`, null, authHeader(token));
    const cases = Array.isArray(listRes.data) ? listRes.data : (listRes.data?.results ?? []);
    const existing = cases.find(c => c.name === name);
    if (existing?.id) {
      logger.info(`[VolWeb] Cas retrouvé par nom : id=${existing.id}`);
      return existing;
    }
    throw new Error(`VolWeb case create failed (${res.status}) et introuvable dans la liste`);
  }

  throw new Error(`VolWeb case create failed (${res.status}): ${JSON.stringify(res.data)}`);
}

async function getVolWebCase(token, volwebCaseId) {
  const res = await requestWithRetry('GET', `${VOLWEB_URL}/api/cases/${volwebCaseId}/`, null, authHeader(token));
  if (res.status !== 200)
    throw new Error(`getVolWebCase failed (${res.status}): ${JSON.stringify(res.data)}`);
  return res.data;
}

// ─── Lazy MinIO client ────────────────────────────────────────────────────────

let _minioClient = null;

function getMinioClient() {
  if (_minioClient) return _minioClient;
  const { Client: MinioClient } = require('minio');
  const ep = new URL(S3_ENDPOINT.startsWith('http') ? S3_ENDPOINT : `http://${S3_ENDPOINT}`);
  _minioClient = new MinioClient({
    endPoint:  ep.hostname,
    port:      ep.port ? parseInt(ep.port) : (ep.protocol === 'https:' ? 443 : 80),
    useSSL:    ep.protocol === 'https:',
    accessKey: S3_ACCESS_KEY,
    secretKey: S3_SECRET_KEY,
    region:    S3_REGION,
    pathStyle: S3_FORCE_PATH,
  });
  return _minioClient;
}

// ─── Helper : upload d'un seul fichier vers MinIO ────────────────────────────

async function uploadFileToMinio(localPath, caseFolder, bucket) {
  const filename  = path.basename(localPath);
  const objectKey = `${caseFolder}/${filename}`;
  const stat      = await fs.promises.stat(localPath);
  const sizeMB    = (stat.size / 1024 / 1024).toFixed(1);

  logger.info(`[VolWeb/S3] Uploading "${filename}" (${sizeMB} MB) → ${bucket}/${objectKey}`);

  await getMinioClient().fPutObject(bucket, objectKey, localPath, {
    'Content-Type': 'application/octet-stream',
  }).catch(err => {
    throw new Error(`MinIO fPutObject failed for "${filename}": ${err.message}`);
  });

  logger.info(`[VolWeb/S3] Upload complete → ${objectKey}`);
  return objectKey;
}

// ─── uploadDump ───────────────────────────────────────────────────────────────

async function uploadDump(token, filePath, volwebCaseId, os = 'windows', caseNumber) {
  const filename   = path.basename(filePath);
  const bucket     = process.env.S3_BUCKET_NAME || 'volweb';
  const caseFolder = String(caseNumber).replace(/[^a-zA-Z0-9._-]/g, '_');
  const objectKey  = `${caseFolder}/${filename}`;

  // 1. Upload → MinIO
  await uploadFileToMinio(filePath, caseFolder, bucket);

  // 2. ETag
  const objStat = await getMinioClient().statObject(bucket, objectKey);
  const etag    = objStat.etag;
  if (!etag) throw new Error(`ETag not found for "${filename}" in bucket "${bucket}"`);
  logger.info(`[VolWeb/S3] ETag: ${etag}`);

  // 3. Enregistrement VolWeb
  const evidenceBody = {
    name:          filename,
    etag,
    os:            os.toLowerCase(),
    linked_case:   volwebCaseId,
    source:        'MINIO',
    endpoint:      S3_ENDPOINT,
    url:           `s3://${bucket}/${objectKey}`,
    access_key_id: S3_ACCESS_KEY,
    access_key:    S3_SECRET_KEY,
  };

  logger.info(`[VolWeb/S3] Registering evidence via POST /api/evidences/…`);
  const evidenceRes = await requestWithRetry('POST', `${VOLWEB_URL}/api/evidences/`, evidenceBody, authHeader(token));

  if (evidenceRes.status >= 400)
    throw new Error(`Register evidence failed (${evidenceRes.status}): ${JSON.stringify(evidenceRes.data)}`);

  logger.info(`[VolWeb/S3] Evidence registered: id=${evidenceRes.data?.id}`);

  // 4. Suppression fichier local
  try {
    await fs.promises.unlink(filePath);
    logger.info(`[VolWeb/S3] Fichier local supprimé : ${filePath}`);
  } catch (unlinkErr) {
    logger.warn(`[VolWeb/S3] Impossible de supprimer "${filePath}": ${unlinkErr.message}`);
  }

  const evidence = evidenceRes.data;
  if (!evidence.evidence_id && evidence.id) evidence.evidence_id = evidence.id;
  return evidence;
}

// ─── uploadAdditionalFiles ────────────────────────────────────────────────────
/**
 * Upload les fichiers additionnels (symbols .vmsn, .json, .isf, .pdb, etc.)
 * dans le MÊME dossier S3 que le dump principal.
 *
 * Le dossier S3 est dérivé du caseNumber, exactement comme dans uploadDump :
 *   bucket/<caseNumber sanitisé>/<filename>
 *
 * Non bloquant : un échec sur un fichier individuel est loggué mais
 * ne fait pas échouer le pipeline.
 *
 * @param {string[]} filePaths   Chemins absolus sur le disque
 * @param {string}   caseNumber  Numéro du cas Heimdall (ex: "CASE-2026-004")
 * @returns {Promise<string[]>}  ObjectKeys MinIO des fichiers uploadés
 */
async function uploadAdditionalFiles(filePaths, caseNumber) {
  if (!filePaths || filePaths.length === 0) return [];

  const bucket     = process.env.S3_BUCKET_NAME || 'volweb';
  const caseFolder = String(caseNumber).replace(/[^a-zA-Z0-9._-]/g, '_');
  const uploadedKeys = [];

  for (const filePath of filePaths) {
    if (!filePath) continue;

    if (!fs.existsSync(filePath)) {
      logger.warn(`[VolWeb/S3] Fichier additionnel introuvable, ignoré : ${filePath}`);
      continue;
    }

    try {
      const objectKey = await uploadFileToMinio(filePath, caseFolder, bucket);
      uploadedKeys.push(objectKey);

      // Supprimer le fichier local après upload réussi
      try {
        await fs.promises.unlink(filePath);
        logger.info(`[VolWeb/S3] Fichier additionnel local supprimé : ${filePath}`);
      } catch (unlinkErr) {
        logger.warn(`[VolWeb/S3] Impossible de supprimer "${filePath}": ${unlinkErr.message}`);
      }
    } catch (err) {
      logger.warn(`[VolWeb/S3] Upload additionnel échoué pour "${path.basename(filePath)}": ${err.message}`);
    }
  }

  if (uploadedKeys.length > 0) {
    logger.info(`[VolWeb/S3] ${uploadedKeys.length} fichier(s) additionnel(s) uploadé(s) : ${uploadedKeys.join(', ')}`);
  }

  return uploadedKeys;
}

// ─── submitForm ───────────────────────────────────────────────────────────────

function submitForm(method, url, form, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    form.getLength((lenErr, length) => {
      if (lenErr) return reject(new Error(`form.getLength failed: ${lenErr.message}`));
      const parsed = new URL(url);
      const lib    = parsed.protocol === 'https:' ? https : http;
      const opts   = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        headers:  { ...form.getHeaders(), 'Content-Length': length, ...extraHeaders },
        timeout:  600_000,
      };
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          try { resolve({ status: res.statusCode, data: JSON.parse(raw) }); }
          catch { resolve({ status: res.statusCode, data: raw }); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(new Error('Request timeout')); });
      form.pipe(req);
    });
  });
}

// ─── triggerAnalysis ─────────────────────────────────────────────────────────

async function triggerAnalysis(token, evidenceId) {
  const plugRes = await requestWithRetry(
    'GET', `${VOLWEB_URL}/api/evidence/${evidenceId}/available-plugins/`,
    null, authHeader(token)
  );
  if (plugRes.status >= 400)
    throw new Error(`Available-plugins fetch failed (${plugRes.status}): ${JSON.stringify(plugRes.data)}`);

  const categories  = plugRes.data?.categories || {};
  const pluginNames = Object.values(categories).flat().map(p => p.name).filter(Boolean);
  if (!pluginNames.length)
    throw new Error(`No plugins available for evidence ${evidenceId} — cannot trigger analysis`);

  logger.info(`[VolWeb] triggering analysis for evidence ${evidenceId} (${pluginNames.length} plugins)`);

  const res = await requestWithRetry(
    'POST', `${VOLWEB_URL}/api/evidence/tasks/selective-extraction/`,
    { id: evidenceId, plugins: pluginNames, run_timeliner: true },
    authHeader(token)
  );
  if (res.status >= 400)
    throw new Error(`Trigger analysis failed (${res.status}): ${JSON.stringify(res.data)}`);
  logger.info(`[VolWeb] analysis triggered for evidence ${evidenceId}`);
}

// ─── getVolWebCaseStatus ──────────────────────────────────────────────────────

async function getVolWebCaseStatus(volwebCaseId) {
  try {
    const token = await getAdminToken();
    const res = await request('GET', `${VOLWEB_URL}/api/cases/${volwebCaseId}/`, null, authHeader(token));
    if (res.status !== 200) return null;
    return res.data;
  } catch {
    return null;
  }
}

// ─── Magic token ──────────────────────────────────────────────────────────────

const MAGIC_TOKEN_TTL = 90;

async function generateMagicToken(redisClient, userId, volwebCaseId) {
  const token     = uuidv4();
  const volwebJwt = await getAdminToken({ forceRefresh: true });
  await redisClient.setex(
    `volweb:magic:${token}`,
    MAGIC_TOKEN_TTL,
    JSON.stringify({ userId, volwebCaseId, volwebJwt })
  );
  return token;
}

async function consumeMagicToken(redisClient, token) {
  const key = `volweb:magic:${token}`;
  const raw = await redisClient.getdel(key);
  if (!raw) return null;
  try { return JSON.parse(raw); }
  catch { return null; }
}

// ─── pollEvidenceStatus ───────────────────────────────────────────────────────

async function pollEvidenceStatus({
  volwebEvidenceId, heimdallEvidenceId, heimdallCaseId,
  pool, io,
  maxWaitMs  = 4 * 3600 * 1000,
  intervalMs = 30_000,
}) {
  const startedAt = Date.now();
  const poll = async () => {
    try {
      const token = await getAdminToken();
      const res   = await request('GET',
        `${VOLWEB_URL}/api/evidences/${volwebEvidenceId}/`, null, authHeader(token));

      if (res.status !== 200) {
        logger.warn(`[VolWeb] poll evidence ${volwebEvidenceId}: HTTP ${res.status}`);
        return;
      }

      const evidenceStatus = res.data?.status;
      logger.info(`[VolWeb] poll evidence ${volwebEvidenceId}: status=${evidenceStatus}`);

      if (evidenceStatus === 100 || evidenceStatus === -1) {
        clearInterval(timer);
        const volwebStatus = evidenceStatus === 100 ? 'ready' : 'error';

        if (pool && heimdallEvidenceId) {
          await pool.query(
            'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
            [volwebStatus, heimdallEvidenceId]
          );
        }
        if (io && heimdallCaseId) {
          io.to(`case:${heimdallCaseId}`).emit('volweb:completed', {
            caseId: heimdallCaseId, evidenceId: heimdallEvidenceId, status: volwebStatus,
          });
        }
        logger.info(`[VolWeb] analysis ${volwebStatus} for evidence ${volwebEvidenceId}`);
        return;
      }

      if (Date.now() - startedAt > maxWaitMs) {
        clearInterval(timer);
        logger.warn(`[VolWeb] analysis timeout after ${maxWaitMs / 1000}s for ${volwebEvidenceId}`);
        if (pool && heimdallEvidenceId) {
          await pool.query(
            'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
            ['error', heimdallEvidenceId]
          );
        }
      }
    } catch (err) {
      logger.warn(`[VolWeb] poll error: ${err.message}`);
    }
  };

  const timer = setInterval(poll, intervalMs);
  setTimeout(poll, 10_000);
}

// ─── processMemoryDump ────────────────────────────────────────────────────────

async function processMemoryDump({
  s3ObjectKey,      // ex: "CASE-2026-004/1778757142410-04ffb84853e7-image.vmem"
  additionalKeys = [], // object keys MinIO des fichiers additionnels, déjà uploadés
  caseTitle,
  caseNumber,
  os = 'windows',
  heimdallCaseId,
  evidenceId,
  pool,
  io,
  onResult,
}) {
  if (!VOLWEB_PASSWORD) {
    const err = new Error('VOLWEB_PASSWORD non configuré — analyse VolWeb ignorée');
    logger.warn(`[VolWeb] ${err.message}`);
    if (pool && evidenceId) {
      await pool.query(
        "UPDATE evidence SET volweb_status = 'error', updated_at = NOW() WHERE id = $1",
        [evidenceId]
      ).catch(() => {});
    }
    onResult?.(err, null);
    return;
  }
 
  const bucket = process.env.S3_BUCKET_NAME || 'volweb';
 
  try {
    logger.info(`[VolWeb/S3] Pipeline S3 démarré pour ${s3ObjectKey}`);
    if (additionalKeys.length > 0) {
      logger.info(`[VolWeb/S3] Fichiers additionnels déjà dans MinIO (${additionalKeys.length}) : ${additionalKeys.join(', ')}`);
    }
 
    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
        ['processing', evidenceId]
      );
    }
 
    const token  = await getAdminToken();
    const vwCase = await createVolWebCase(
      token,
      `[${caseNumber}] ${caseTitle}`,
      `Importé depuis Heimdall — ${caseNumber}`
    );
    logger.info(`[VolWeb/S3] Cas VolWeb créé/retrouvé : id=${vwCase.id} name="${vwCase.name}"`);
 
    if (pool && heimdallCaseId) {
      await pool.query(
        'UPDATE cases SET volweb_case_id = $1, updated_at = NOW() WHERE id = $2',
        [vwCase.id, heimdallCaseId]
      );
    }
 
    // ── 1. Récupérer l'ETag du dump depuis MinIO (déjà uploadé) ──────────
    logger.info(`[VolWeb/S3] Récupération ETag pour ${bucket}/${s3ObjectKey}…`);
    const objStat = await getMinioClient().statObject(bucket, s3ObjectKey);
    const etag    = objStat.etag;
    if (!etag) throw new Error(`ETag introuvable pour "${s3ObjectKey}" dans le bucket "${bucket}"`);
    logger.info(`[VolWeb/S3] ETag: ${etag}`);
 
    // ── 2. Enregistrer l'evidence dans VolWeb ────────────────────────────
    const filename     = path.basename(s3ObjectKey);
    const evidenceBody = {
      name:          filename,
      etag,
      os:            os.toLowerCase(),
      linked_case:   vwCase.id,
      source:        'MINIO',
      endpoint:      S3_ENDPOINT,
      url:           `s3://${bucket}/${s3ObjectKey}`,
      access_key_id: S3_ACCESS_KEY,
      access_key:    S3_SECRET_KEY,
    };
 
    logger.info(`[VolWeb/S3] Enregistrement evidence VolWeb pour "${filename}"…`);
    const evidenceRes = await requestWithRetry(
      'POST', `${VOLWEB_URL}/api/evidences/`, evidenceBody, authHeader(token)
    );
 
    if (evidenceRes.status >= 400) {
      throw new Error(`Register evidence failed (${evidenceRes.status}): ${JSON.stringify(evidenceRes.data)}`);
    }
 
    const volwebEvidence   = evidenceRes.data;
    const volwebEvidenceId = volwebEvidence?.evidence_id || volwebEvidence?.id;
    if (!volwebEvidenceId)
      throw new Error(`VolWeb n'a pas retourné d'evidence_id : ${JSON.stringify(volwebEvidence)}`);
 
    logger.info(`[VolWeb/S3] Evidence enregistrée : id=${volwebEvidenceId}`);
 
    // ── 3. Mettre à jour Heimdall ────────────────────────────────────────
    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_evidence_id = $1, volweb_status = $2, updated_at = NOW() WHERE id = $3',
        [volwebEvidenceId, 'processing', evidenceId]
      );
    }
 
    // ── 4. Déclencher l'analyse ───────────────────────────────────────────
    await triggerAnalysis(token, volwebEvidenceId);
 
    if (io && heimdallCaseId) {
      io.to(`case:${heimdallCaseId}`).emit('volweb:processing', {
        caseId:          heimdallCaseId,
        evidenceId,
        volwebCaseId:    vwCase.id,
        volwebEvidenceId,
        message:         'Analyse Volatility 3 en cours…',
      });
    }
 
    const volwebUrl = `${VOLWEB_PUBLIC_URL}/cases/${vwCase.id}/`;
    onResult?.(null, { volwebCaseId: vwCase.id, evidenceId: volwebEvidenceId, url: volwebUrl });
    logger.info(`[VolWeb/S3] Pipeline complet → ${volwebUrl}`);
 
    pollEvidenceStatus({
      volwebEvidenceId,
      heimdallEvidenceId: evidenceId,
      heimdallCaseId,
      pool, io,
    }).catch(e => logger.warn('[VolWeb] pollEvidenceStatus failed:', e.message));
 
  } catch (err) {
    logger.error(`[VolWeb/S3] Erreur pipeline : ${err?.message || String(err)}`);
    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
        ['error', evidenceId]
      ).catch(() => {});
    }
    onResult?.(err, null);
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  getToken,
  getAdminToken,
  createVolWebCase,
  uploadDump,
  uploadAdditionalFiles,
  triggerAnalysis,
  getVolWebCaseStatus,
  pollEvidenceStatus,
  generateMagicToken,
  consumeMagicToken,
  processMemoryDump,
  VOLWEB_PUBLIC_URL,
  VOLWEB_TOKEN_KEY,
  MAGIC_TOKEN_TTL,
};