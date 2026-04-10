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
const CHUNK_SIZE        = 10 * 1024 * 1024;

let _adminTokenCache   = null;
let _adminTokenExpires = 0;

function request(method, url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
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

async function createVolWebCase(token, name, description) {
  const res = await requestWithRetry('POST', `${VOLWEB_URL}/api/cases/`,
    { name, description: description || 'Importé depuis Heimdall' }, authHeader(token));

  if (res.status === 201 && res.data?.id) return res.data;

  if (res.status === 409 || res.status === 400) {
    logger.warn(`[VolWeb] Cas creation returned ${res.status} for "${name}", recherche par nom…`);
    const listRes = await request('GET', `${VOLWEB_URL}/api/cases/`, null, authHeader(token));
    const cases = Array.isArray(listRes.data)
      ? listRes.data
      : (listRes.data?.results ?? []);
    const existing = cases.find(c => c.name === name);
    if (existing?.id) {
      logger.info(`[VolWeb] Cas retrouvé par nom : id=${existing.id}`);
      return existing;
    }
    throw new Error(`VolWeb case create failed (${res.status}) et introuvable dans la liste`);
  }

  throw new Error(`VolWeb case create failed (${res.status}): ${JSON.stringify(res.data)}`);
}

function submitForm(method, url, form, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    form.getLength((lenErr, length) => {
      if (lenErr) return reject(new Error(`form.getLength failed: ${lenErr.message}`));

      const parsed  = new URL(url);
      const lib     = parsed.protocol === 'https:' ? https : http;
      const opts = {
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

async function uploadDump(token, filePath, volwebCaseId, os = 'windows') {
  const filename   = path.basename(filePath);
  const stat       = await fs.promises.stat(filePath);
  const totalParts = Math.ceil(stat.size / CHUNK_SIZE);

  const initRes = await request('POST', `${VOLWEB_URL}/api/cases/upload/initiate/`,
    { filename, case_id: volwebCaseId, os }, authHeader(token));
  if (!initRes.data?.upload_id)
    throw new Error(`Initiate upload failed (${initRes.status}): ${JSON.stringify(initRes.data)}`);
  const uploadId = initRes.data.upload_id;

  for (let part = 1; part <= totalParts; part++) {
    const offset  = (part - 1) * CHUNK_SIZE;
    const size    = Math.min(CHUNK_SIZE, stat.size - offset);
    const maxTries = 3;

    let lastErr;
    let currentToken = token;
    for (let attempt = 0; attempt < maxTries; attempt++) {
      const form = new FormData();
      form.append('upload_id',   uploadId);
      form.append('part_number', String(part));
      form.append('chunk', fs.createReadStream(filePath, {
        start:         offset,
        end:           offset + size - 1,
        highWaterMark: 64 * 1024,
      }), { filename: `chunk_${part}`, contentType: 'application/octet-stream', knownLength: size });

      const res = await submitForm('POST', `${VOLWEB_URL}/api/cases/upload/chunk/`,
        form, authHeader(currentToken));

      if (res.status < 400) { lastErr = null; break; }

      if (res.status === 401 && attempt < maxTries - 1) {
        clearAdminTokenCache();
        currentToken = await getAdminToken();
        continue;
      }

      lastErr = new Error(`Chunk ${part}/${totalParts} failed (${res.status}): ${JSON.stringify(res.data)}`);
      if (attempt < maxTries - 1) {
        const delay = 5000 * Math.pow(2, attempt);
        logger.warn(`[VolWeb] chunk ${part}/${totalParts} attempt ${attempt + 1} failed — retrying in ${delay / 1000}s`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
    if (lastErr) throw lastErr;
    logger.info(`[VolWeb] upload chunk ${part}/${totalParts}`);
  }

  const completeRes = await request('POST', `${VOLWEB_URL}/api/cases/upload/complete/`,
    { upload_id: uploadId }, authHeader(token));
  if (completeRes.status >= 400)
    throw new Error(`Complete upload failed (${completeRes.status}): ${JSON.stringify(completeRes.data)}`);
  return completeRes.data;
}

async function triggerAnalysis(token, evidenceId) {
  const plugRes = await requestWithRetry(
    'GET', `${VOLWEB_URL}/api/evidence/${evidenceId}/available-plugins/`,
    null, authHeader(token)
  );
  if (plugRes.status >= 400)
    throw new Error(`Available-plugins fetch failed (${plugRes.status}): ${JSON.stringify(plugRes.data)}`);

  const categories = plugRes.data?.categories || {};
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

async function pollEvidenceStatus({
  volwebEvidenceId, heimdallEvidenceId, heimdallCaseId,
  pool, io,
  maxWaitMs = 4 * 3600 * 1000,
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
        const isSuccess = evidenceStatus === 100;
        const volwebStatus = isSuccess ? 'ready' : 'error';

        if (pool && heimdallEvidenceId) {
          await pool.query(
            'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
            [volwebStatus, heimdallEvidenceId]
          );
        }
        if (io && heimdallCaseId) {
          io.to(`case:${heimdallCaseId}`).emit('volweb:completed', {
            caseId:     heimdallCaseId,
            evidenceId: heimdallEvidenceId,
            status:     volwebStatus,
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

async function processMemoryDump({
  filePath, caseTitle, caseNumber, os = 'windows',
  heimdallCaseId, evidenceId, pool, io, onResult,
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
  if (!fs.existsSync(filePath)) {
    const err = new Error(`Fichier introuvable : ${filePath}`);
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

  try {
    logger.info(`[VolWeb] Pipeline démarré pour ${path.basename(filePath)}`);

    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
        ['uploading', evidenceId]
      );
    }

    const token  = await getAdminToken();
    const vwCase = await createVolWebCase(
      token,
      `[${caseNumber}] ${caseTitle}`,
      `Importé depuis Heimdall — ${caseNumber}`
    );
    logger.info(`[VolWeb] Cas créé : id=${vwCase.id} name="${vwCase.name}"`);

    if (pool && heimdallCaseId) {
      await pool.query(
        'UPDATE cases SET volweb_case_id = $1, updated_at = NOW() WHERE id = $2',
        [vwCase.id, heimdallCaseId]
      );
    }

    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
        ['uploading', evidenceId]
      );
    }

    const uploadResult = await uploadDump(token, filePath, vwCase.id, os);
    const volwebEvidenceId = uploadResult?.evidence_id || uploadResult?.id;
    if (!volwebEvidenceId) throw new Error(`Upload n'a pas retourné d'evidence_id : ${JSON.stringify(uploadResult)}`);
    logger.info(`[VolWeb] Dump uploadé : evidence_id=${volwebEvidenceId}`);

    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_evidence_id = $1, volweb_status = $2, updated_at = NOW() WHERE id = $3',
        [volwebEvidenceId, 'processing', evidenceId]
      );
    }

    await triggerAnalysis(token, volwebEvidenceId);

    if (io && heimdallCaseId) {
      io.to(`case:${heimdallCaseId}`).emit('volweb:processing', {
        caseId: heimdallCaseId,
        evidenceId,
        volwebCaseId: vwCase.id,
        volwebEvidenceId,
        message: 'Analyse Volatility 3 en cours…',
      });
    }

    const volwebUrl = `${VOLWEB_PUBLIC_URL}/cases/${vwCase.id}/`;
    onResult?.(null, { volwebCaseId: vwCase.id, evidenceId: volwebEvidenceId, url: volwebUrl });
    logger.info(`[VolWeb] Pipeline complet → ${volwebUrl}`);

    pollEvidenceStatus({
      volwebEvidenceId,
      heimdallEvidenceId: evidenceId,
      heimdallCaseId,
      pool, io,
    }).catch(e => logger.warn('[VolWeb] pollEvidenceStatus failed:', e.message));

  } catch (err) {
    logger.error(`[VolWeb] Erreur pipeline : ${err?.message || String(err)}`);

    if (pool && evidenceId) {
      await pool.query(
        'UPDATE evidence SET volweb_status = $1, updated_at = NOW() WHERE id = $2',
        ['error', evidenceId]
      ).catch(() => {});
    }
    onResult?.(err, null);
  }
}

module.exports = {
  getToken,
  getAdminToken,
  createVolWebCase,
  uploadDump,
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
