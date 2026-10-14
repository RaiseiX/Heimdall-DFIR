const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const rateLimit = require('express-rate-limit');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog, JWT_SECRET } = require('../middleware/auth');
const { getSecurityPolicy } = require('../services/securityPolicy');
const { revoquerJti, lireSessionActive, ecrireSessionActive, normaliserId, appelRedis, causeRevocation, CAUSE_REMPLACE, CAUSE_REVOQUE } = require('../services/sessionGuard');
const { couperSessionsUtilisateur } = require('../services/sessionRevocation');

const logger = require('../config/logger').default;
const router = express.Router();

// IP-based throttle on the public auth endpoints. Complements the per-username
// account lockout: stops credential stuffing / password spraying and volumetric
// abuse from a single source (the lockout only protects one account at a time).
// Successful logins don't count, so legitimate users are never throttled.
const authLimiter = rateLimit({
  windowMs:                15 * 60 * 1000,                       // 15 minutes
  limit:                   Number(process.env.AUTH_RATE_LIMIT || 30),
  standardHeaders:         'draft-7',
  legacyHeaders:           false,
  skipSuccessfulRequests:  true,
  message:                 { code: 'rate_limited', error: 'Trop de tentatives depuis cette adresse. Réessayez plus tard.' },
});

const REFRESH_TOKEN_EXPIRY_DAYS = 30;   // fallback if policy unset
const ACCESS_TOKEN_EXPIRY       = '8h';

// ── Account lockout (Redis-backed; gracefully no-ops if Redis is unavailable) ─
async function isLockedOut(username, redis, policy) {
  if (!redis || !policy.lockoutThreshold) return false;
  const r = await appelRedis((c) => c.get(`login_fail:${username}`), 'verrouillage ignore', redis, { lecture: true });
  if (!r.ok) return false;
  return parseInt(r.valeur || '0', 10) >= policy.lockoutThreshold;
}
async function recordLoginFailure(username, redis, policy) {
  if (!redis || !policy.lockoutThreshold) return;
  const key = `login_fail:${username}`;
  const r = await appelRedis((c) => c.incr(key), 'echec de connexion non compte', redis);
  if (r.ok && r.valeur === 1) {
    await appelRedis((c) => c.expire(key, policy.lockoutWindowMin * 60), 'fenetre de verrouillage non posee', redis);
  }
}
async function clearLoginFailures(username, redis) {
  if (!redis) return;
  await appelRedis((c) => c.del(`login_fail:${username}`), 'compteur d echecs non efface', redis);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function issueRefreshToken(userId, pool, sessionHours) {
  const hours    = Number(sessionHours) > 0 ? Number(sessionHours) : REFRESH_TOKEN_EXPIRY_DAYS * 24;
  const raw      = crypto.randomBytes(48).toString('hex');
  const hash     = hashToken(raw);
  const expiresAt = new Date(Date.now() + hours * 3600_000);
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

async function evictOldSession(userId, redis, cause = CAUSE_REVOQUE) {
  if (!redis) return;
  const oldJti = await lireSessionActive(userId, redis, { pourEcriture: true });
  if (oldJti) await revoquerJti(oldJti, 28800, redis, cause);
}

async function storeActiveSession(userId, jti, redis) {
  if (!redis) return;
  await ecrireSessionActive(userId, jti, SESSION_KEY_TTL, redis);
}

router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ code: 'missing_fields', error: 'Username et password requis' });
    }

    const policy = await getSecurityPolicy();
    const redis  = await getRedis();

    // Account lockout — keyed by username (also throttles user enumeration).
    if (await isLockedOut(username, redis, policy)) {
      await auditLog(null, 'login_blocked', 'user', null, { username, reason: 'lockout' }, req.ip);
      return res.status(429).json({
        code: 'account_locked',
        windowMin: policy.lockoutWindowMin,
        error: `Compte temporairement verrouillé après trop de tentatives. Réessayez dans ${policy.lockoutWindowMin} min.`,
      });
    }

    const result = await pool.query(
      'SELECT id, username, email, password_hash, full_name, role, is_active, preferences FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      await recordLoginFailure(username, redis, policy);
      await auditLog(null, 'login_failed', 'user', null, { username, reason: 'user_not_found' }, req.ip);
      return res.status(401).json({ code: 'invalid_credentials', error: 'Identifiants invalides' });
    }

    const user = result.rows[0];
    if (!user.is_active) {
      await auditLog(user.id, 'login_blocked', 'user', user.id, { username, reason: 'account_disabled' }, req.ip);
      return res.status(403).json({ code: 'account_disabled', error: 'Compte désactivé' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await recordLoginFailure(username, redis, policy);
      await auditLog(user.id, 'login_failed', 'user', user.id, { username, reason: 'wrong_password' }, req.ip);
      return res.status(401).json({ code: 'invalid_credentials', error: 'Identifiants invalides' });
    }


    await Promise.all([clearLoginFailures(username, redis), evictOldSession(user.id, redis)]);

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

    const refreshToken = await issueRefreshToken(user.id, pool, policy.sessionDurationH);

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

router.post('/refresh', authLimiter, async (req, res) => {
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

    const policy = await getSecurityPolicy();

    const consomme = await pool.query(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1 AND revoked = FALSE RETURNING id',
      [rt.id]
    );
    if (!consomme.rows || consomme.rows.length === 0) {
      return res.status(401).json({ error: 'Token de renouvellement invalide ou expiré' });
    }

    const jti      = crypto.randomUUID();
    const newToken = jwt.sign(
      { id: rt.user_id, username: rt.username, role: rt.role, full_name: rt.full_name, jti },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    const newRefreshToken = await issueRefreshToken(rt.user_id, pool, policy.sessionDurationH);

    const redis = await getRedis();
    await evictOldSession(rt.user_id, redis, CAUSE_REMPLACE);
    await storeActiveSession(rt.user_id, jti, redis);

    await auditLog(rt.user_id, 'token_refresh', 'user', rt.user_id, { username: rt.username }, req.ip);
    res.json({ token: newToken, refreshToken: newRefreshToken });
  } catch (err) {
    logger.error('[refresh]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

function lireJetonAcces(req) {
  const entete = req.headers.authorization;
  if (!entete || !entete.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(entete.split(' ')[1], JWT_SECRET, { ignoreExpiration: true });
  } catch (_e) {
    return null;
  }
}

const logoutLimiter = rateLimit({
  windowMs:        60 * 1000,
  limit:           Number(process.env.LOGOUT_RATE_LIMIT || 30),
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
  message:         { code: 'rate_limited', error: 'Trop de tentatives depuis cette adresse. Réessayez plus tard.' },
});

async function accesActifValide(acces, redis, maintenant) {
  if (!acces || !acces.jti || !acces.id || !acces.exp || acces.exp <= maintenant) return false;
  if (await causeRevocation(acces.jti, redis)) return false;
  const actif = await lireSessionActive(acces.id, redis);
  return actif === acces.jti;
}

router.post('/logout', logoutLimiter, async (req, res) => {
  try {
    const corps = req.body || {};
    const refresh = corps.refresh_token ?? corps.refreshToken;
    const io = req.app.locals.io;
    const redis = await getRedis();
    const maintenant = Math.floor(Date.now() / 1000);

    let userRefresh = null;
    if (typeof refresh === 'string' && refresh) {
      const r = await pool.query(
        'UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW() RETURNING user_id',
        [hashToken(refresh)]
      );
      userRefresh = r.rows && r.rows[0] ? normaliserId(String(r.rows[0].user_id)) : null;
    }

    const acces = lireJetonAcces(req);
    const userAcces = (await accesActifValide(acces, redis, maintenant)) ? normaliserId(String(acces.id)) : null;

    const identifies = new Set([userRefresh, userAcces].filter(Boolean));
    for (const userId of identifies) {
      await couperSessionsUtilisateur(io, userId);
      await auditLog(userId, 'logout', 'user', userId, {}, req.ip);
    }

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
    const policy = await getSecurityPolicy();
    if (password.length < policy.passwordMinLength) {
      return res.status(400).json({ error: `Mot de passe : ${policy.passwordMinLength} caractères minimum` });
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
