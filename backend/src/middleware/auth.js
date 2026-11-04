const jwt = require('jsonwebtoken');
const logger = require('../config/logger').default;
const crypto = require('crypto');
const { pool } = require('../config/database');
const { verifierSession, MESSAGE_SESSION_INVALIDE } = require('../services/sessionGuard');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requis' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const session = await verifierSession(token, { secret: JWT_SECRET, pool: req.app?.locals?.pool || pool });

    if (!session.ok) {
      if (session.raison === 'revoque') return res.status(401).json({ error: 'Token révoqué' });
      if (session.raison === 'inactif') return res.status(401).json({ error: MESSAGE_SESSION_INVALIDE });
      if (session.raison === 'remplace') return res.status(401).json({ error: 'Token remplacé', code: 'session_remplacee' });
      if (session.raison === 'indisponible') {
        return res.status(503).json({ error: 'Service temporairement indisponible', code: 'session_indisponible' });
      }
      if (session.raison === 'expiree') {
        return res.status(401).json({ error: 'Token invalide ou expiré', code: 'session_expiree' });
      }
      return res.status(401).json({ error: 'Token invalide ou expiré' });
    }

    req.user = session.user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

// Hierarchical roles: admin ⊃ team_lead ⊃ analyst. A user passes if their rank is
// at least the lowest rank among the allowed roles — so requireRole('analyst','admin')
// also admits team_lead, while requireRole('admin') stays admin-only.
const ROLE_RANK = { analyst: 1, team_lead: 2, admin: 3 };
function requireRole(...roles) {
  const minRank = Math.min(...roles.map(r => ROLE_RANK[r] ?? 99));
  return (req, res, next) => {
    const rank = ROLE_RANK[req.user?.role] ?? 0;
    if (!req.user || rank < minRank) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }
    next();
  };
}

// Canonical form lives in services/auditChain so the chained and legacy schemes
// can never drift apart on key ordering.
const { appendAuditRow, canonicalize } = require('../services/auditChain');

function computeAuditHmac({ user_id, action, entity_type, entity_id, details, ts }) {
  const payload = JSON.stringify(canonicalize({ user_id, action, entity_type, entity_id, details, ts }));
  return crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
}

// Legacy scheme (pre-canonicalization): insertion-order top-level keys, details as-is.
function computeAuditHmacLegacy({ user_id, action, entity_type, entity_id, details, ts }) {
  const payload = JSON.stringify({ user_id, action, entity_type, entity_id, details, ts });
  return crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
}

let auditFailures = 0;
let lastAuditFailureAt = null;
let lastAuditFailureAction = null;

function getAuditFailureCount() {
  return auditFailures;
}

function getAuditFailureStats() {
  return { failures: auditFailures, last_failure_at: lastAuditFailureAt, last_failure_action: lastAuditFailureAction };
}

function recordAuditFailure(action, err) {
  auditFailures += 1;
  lastAuditFailureAt = new Date().toISOString();
  lastAuditFailureAction = typeof action === 'string' ? action : null;
  logger.error(`Audit log write failed for action "${action}" (failures: ${auditFailures}):`, err);
}

async function auditLog(userId, action, entityType, entityId, details = {}, ipAddress) {
  try {
    await appendAuditRow(pool, { userId, action, entityType, entityId, details, ipAddress: ipAddress ?? null });
  } catch (err) {
    recordAuditFailure(action, err);
  }
}

async function auditCritical(db, userId, action, entityType, entityId, details = {}, ipAddress) {
  try {
    return await appendAuditRow(db || pool, { userId, action, entityType, entityId, details, ipAddress: ipAddress ?? null });
  } catch (err) {
    recordAuditFailure(action, err);
    if (err && typeof err === 'object') err.auditFailure = true;
    throw err;
  }
}

module.exports = {
  authenticate, requireRole, auditLog, auditCritical, getAuditFailureCount, getAuditFailureStats,
  computeAuditHmac, computeAuditHmacLegacy, JWT_SECRET,
};
