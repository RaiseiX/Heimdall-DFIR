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

// Recursively sort object keys so the HMAC payload survives JSONB key reordering
// (jsonb does not preserve insertion order; canonical form makes verification deterministic).
function canonicalize(v) {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = canonicalize(v[k]); return acc; }, {});
  }
  return v;
}

function computeAuditHmac({ user_id, action, entity_type, entity_id, details, ts }) {
  const payload = JSON.stringify(canonicalize({ user_id, action, entity_type, entity_id, details, ts }));
  return crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
}

// Legacy scheme (pre-canonicalization): insertion-order top-level keys, details as-is.
function computeAuditHmacLegacy({ user_id, action, entity_type, entity_id, details, ts }) {
  const payload = JSON.stringify({ user_id, action, entity_type, entity_id, details, ts });
  return crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
}

async function auditLog(userId, action, entityType, entityId, details = {}, ipAddress = null) {
  try {
    const ts = new Date().toISOString();
    const hmac = computeAuditHmac({ user_id: userId, action, entity_type: entityType, entity_id: entityId, details, ts });
    await pool.query(
      'INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, created_at, hmac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [userId, action, entityType, entityId, JSON.stringify(details), ipAddress, ts, hmac]
    );
  } catch (err) {
    logger.error('Audit log error:', err);
  }
}

module.exports = { authenticate, requireRole, auditLog, computeAuditHmac, computeAuditHmacLegacy, JWT_SECRET };
