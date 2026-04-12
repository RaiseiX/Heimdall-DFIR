const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog, JWT_SECRET } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

const REFRESH_TOKEN_EXPIRY_DAYS = 30;
const ACCESS_TOKEN_EXPIRY       = '8h';

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function issueRefreshToken(userId, pool) {
  const raw      = crypto.randomBytes(48).toString('hex');
  const hash     = hashToken(raw);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 86400_000);
  await pool.query(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, hash, expiresAt]
  );
  return raw;
}

const SESSION_KEY_TTL = REFRESH_TOKEN_EXPIRY_DAYS * 86400;

async function getRedis() {
  const { getRedis: _get } = require('../config/redis');
  return _get();
}

async function evictOldSession(userId, redis) {
  if (!redis) return;
  try {
    const oldJti = await redis.get(`user_session:${userId}`);
    if (oldJti) {

      await redis.set(`bl:jti:${oldJti}`, '1', { EX: 28800 });
    }
  } catch (_e) {}
}

async function storeActiveSession(userId, jti, redis) {
  if (!redis) return;
  try {
    await redis.set(`user_session:${userId}`, jti, { EX: SESSION_KEY_TTL });
  } catch (_e) {}
}

async function clearActiveSession(userId, redis) {
  if (!redis) return;
  try {
    await redis.del(`user_session:${userId}`);
  } catch (_e) {}
}

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username et password requis' });
    }

    const result = await pool.query(
      'SELECT id, username, email, password_hash, full_name, role, is_active, preferences FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      await auditLog(null, 'login_failed', 'user', null, { username, reason: 'user_not_found' }, req.ip);
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const user = result.rows[0];
    if (!user.is_active) {
      await auditLog(user.id, 'login_blocked', 'user', user.id, { username, reason: 'account_disabled' }, req.ip);
      return res.status(403).json({ error: 'Compte désactivé' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await auditLog(user.id, 'login_failed', 'user', user.id, { username, reason: 'wrong_password' }, req.ip);
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const redis = await getRedis();

    await evictOldSession(user.id, redis);

    await pool.query(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE',
      [user.id]
    );

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const jti   = crypto.randomUUID();
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, full_name: user.full_name, jti },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    const refreshToken = await issueRefreshToken(user.id, pool);

    await storeActiveSession(user.id, jti, redis);

    await auditLog(user.id, 'login', 'user', user.id, {}, req.ip);

    res.json({
      token,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        preferences: user.preferences || {}
      }
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, full_name, role, last_login, created_at, preferences FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken requis' });

    const hash = hashToken(refreshToken);
    const result = await pool.query(
      `SELECT rt.*, u.username, u.role, u.full_name, u.is_active
       FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1 AND rt.revoked = FALSE AND rt.expires_at > NOW()`,
      [hash]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Token de renouvellement invalide ou expiré' });
    }

    const rt   = result.rows[0];
    if (!rt.is_active) return res.status(403).json({ error: 'Compte désactivé' });

    await pool.query('UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1', [rt.id]);

    const jti      = crypto.randomUUID();
    const newToken = jwt.sign(
      { id: rt.user_id, username: rt.username, role: rt.role, full_name: rt.full_name, jti },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    const newRefreshToken = await issueRefreshToken(rt.user_id, pool);

    const redis = await getRedis();
    await storeActiveSession(rt.user_id, jti, redis);

    await auditLog(rt.user_id, 'token_refresh', 'user', rt.user_id, { username: rt.username }, req.ip);
    res.json({ token: newToken, refreshToken: newRefreshToken });
  } catch (err) {
    logger.error('[refresh]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/logout', authenticate, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (refreshToken) {
      const hash = hashToken(refreshToken);
      await pool.query('UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1', [hash]);
    }

    if (req.user?.jti) {
      try {
        const redis = await getRedis();
        if (redis) {
          const decoded = req.user;
          const ttl = decoded.exp ? Math.max(0, decoded.exp - Math.floor(Date.now() / 1000)) : 900;
          await redis.set(`bl:jti:${decoded.jti}`, '1', { EX: ttl });
          await clearActiveSession(decoded.id, redis);
        }
      } catch (_e) {}
    }

    await auditLog(req.user.id, 'logout', 'user', req.user.id, {}, req.ip);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/register', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { username, password, full_name, role } = req.body;
    if (!username || !password || !full_name) {
      return res.status(400).json({ error: 'username, password et full_name requis' });
    }
    const password_hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      'INSERT INTO users (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, username, full_name, role',
      [username, password_hash, full_name, role || 'analyst']
    );

    await auditLog(req.user.id, 'create_user', 'user', result.rows[0].id, { username, role: role || 'analyst' }, req.ip);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Utilisateur déjà existant' });
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
