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

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }
    next();
  };
}

async function auditLog(userId, action, entityType, entityId, details = {}, ipAddress = null) {
  try {
    const ts = new Date().toISOString();
    const payload = JSON.stringify({ user_id: userId, action, entity_type: entityType, entity_id: entityId, details, ts });
    const hmac = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    await pool.query(
      'INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, created_at, hmac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [userId, action, entityType, entityId, JSON.stringify(details), ipAddress, ts, hmac]
    );
  } catch (err) {
    logger.error('Audit log error:', err);
  }
}

module.exports = { authenticate, requireRole, auditLog, JWT_SECRET };
