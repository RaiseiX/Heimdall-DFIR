const express = require('express');
const rateLimit = require('express-rate-limit');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { canAccessCase } = require('../middleware/caseAccess');
const { integrityQueue } = require('../config/queue');
const { enqueueIntegrity, integrityJobId } = require('../services/integrityScheduler');
const { latestIntegrityChecks } = require('../services/reportIntegrity');
const logger = require('../config/logger').default;

const router = express.Router({ mergeParams: true });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[0-9a-f]{64}$/i;

const launchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.INTEGRITY_RATE_LIMIT_MAX || 10),
  keyGenerator: (req) => String(req.user.id),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { code: 'rate_limited', error: 'Trop de contrôles lancés. Réessayez dans quelques minutes.' },
});

function lowerCaseId(value) {
  return String(value).toLowerCase();
}

function toIso(value) {
  if (value == null) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function isStale(evidenceHash, expected) {
  if (typeof expected !== 'string' || !SHA256_RE.test(expected)) return false;
  if (typeof evidenceHash !== 'string' || !SHA256_RE.test(evidenceHash)) return false;
  return evidenceHash.toLowerCase() !== expected.toLowerCase();
}

function publicProgress(progress) {
  if (!progress || typeof progress !== 'object') return null;
  return { done: Number(progress.done) || 0, total: Number(progress.total) || 0 };
}

router.use(authenticate);
router.use(async (req, res, next) => {
  try {
    if (await canAccessCase(req.user, lowerCaseId(req.params.caseId))) return next();
    return res.status(404).json({ error: 'Dossier introuvable.' });
  } catch (err) {
    logger.error('[integrity] contrôle d\'accès impossible', { error: err.message });
    return res.status(500).json({ error: 'Une erreur est survenue, réessayez dans un instant.' });
  }
});

router.post('/', launchLimiter, async (req, res) => {
  const caseId = lowerCaseId(req.params.caseId);
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  let evidenceId = body.evidenceId == null ? null : body.evidenceId;

  if (evidenceId !== null && (typeof evidenceId !== 'string' || !UUID_RE.test(evidenceId))) {
    return res.status(400).json({ error: 'Identifiant de preuve invalide.' });
  }
  if (evidenceId !== null) evidenceId = lowerCaseId(evidenceId);

  try {
    if (evidenceId) {
      const owned = await pool.query('SELECT 1 FROM evidence WHERE id = $1 AND case_id = $2', [evidenceId, caseId]);
      if (owned.rows.length === 0) return res.status(404).json({ error: 'Preuve introuvable dans ce dossier.' });
    }
  } catch (err) {
    logger.error('[integrity] lecture de la preuve impossible', { caseId, error: err.message });
    return res.status(500).json({ error: 'Une erreur est survenue, réessayez dans un instant.' });
  }

  try {
    const result = await enqueueIntegrity(integrityQueue(), {
      caseId, evidenceId, userId: req.user.id, trigger: 'manual',
    });
    if (result.status === 'running') return res.status(409).json({ jobId: result.jobId });
    return res.status(202).json({ jobId: result.jobId });
  } catch (err) {
    logger.error('[integrity] mise en file impossible', { caseId, error: err.message });
    return res.status(503).json({ error: 'Le service de contrôle est momentanément indisponible, réessayez dans un instant.' });
  }
});

router.get('/', async (req, res) => {
  const caseId = lowerCaseId(req.params.caseId);
  try {
    const evidence = await pool.query('SELECT id, hash_sha256 FROM evidence WHERE case_id = $1', [caseId]);
    const hashes = new Map(evidence.rows.map((r) => [String(r.id), r.hash_sha256]));

    let job = null;
    try {
      const found = await integrityQueue().getJob(integrityJobId(caseId));
      if (found) job = { state: await found.getState(), progress: publicProgress(found.progress) };
    } catch (err) {
      logger.warn('[integrity] état du job indisponible', { caseId, error: err.message });
    }

    const latest = await latestIntegrityChecks(pool, [...hashes.keys()]);
    const checks = {};
    for (const [id, check] of latest) {
      if (!hashes.has(id)) continue;
      checks[id] = {
        status: check.status,
        checked_at: toIso(check.checked_at),
        stale: isStale(hashes.get(id), check.expected_sha256),
        last_mismatch_at: toIso(check.last_mismatch_at),
      };
    }
    return res.json({ job, checks });
  } catch (err) {
    logger.error('[integrity] lecture des contrôles impossible', { caseId, error: err.message });
    return res.status(500).json({ error: 'Une erreur est survenue, réessayez dans un instant.' });
  }
});

module.exports = router;
