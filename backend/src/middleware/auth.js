const jwt = require('jsonwebtoken');
const logger = require('../config/logger').default;
const crypto = require('crypto');
const { pool } = require('../config/database');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requis' });
  }

  try {
    const token   = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.jti) {
      try {
        const { getRedis } = require('../config/redis');
        const redis = getRedis();
        if (redis) {
          const blacklisted = await redis.get(`bl:jti:${decoded.jti}`);
          if (blacklisted) return res.status(401).json({ error: 'Token révoqué' });
        }
      } catch (_e) {}
    }

    req.user = decoded;
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

/**
 * Append an audit entry to the tamper-evident chain.
 *
 * Failures stay swallowed on purpose: a broken audit write must not take down the
 * request that triggered it. The verify endpoint is what surfaces gaps — and a
 * missing entry now shows up as a chain break rather than silently vanishing.
 *
 * @param {string|null|undefined} [ipAddress]
 */
async function auditLog(userId, action, entityType, entityId, details = {}, ipAddress = null) {
  try {
    await appendAuditRow(pool, { userId, action, entityType, entityId, details, ipAddress });
  } catch (err) {
    logger.error('Audit log error:', err);
  }
}

module.exports = { authenticate, requireRole, auditLog, computeAuditHmac, computeAuditHmacLegacy, JWT_SECRET };
