'use strict';

const jwt = require('jsonwebtoken');
const logger = require('../config/logger').default;
const { pool: poolParDefaut } = require('../config/database');

const TTL_JTI_DEFAUT = 28800;
const DELAI_REDIS_MS = 500;
const FENETRE_AVERTISSEMENT_MS = 60000;
const DUREE_DISJONCTEUR_MS = 2000;
const CAUSE_REMPLACE = 'remplace';
const CAUSE_REVOQUE = 'revoque';
const MESSAGE_SESSION_INVALIDE = 'Session invalide';

const derniersAvertissements = new Map();
let disjoncteurJusqua = 0;

function avertir(cle, message, meta) {
  const maintenant = Date.now();
  const dernier = derniersAvertissements.get(cle);
  if (dernier !== undefined && maintenant - dernier < FENETRE_AVERTISSEMENT_MS) return;
  derniersAvertissements.set(cle, maintenant);
  logger.warn(message, meta);
}

function reinitialiserAvertissements() {
  derniersAvertissements.clear();
  disjoncteurJusqua = 0;
}

function avecDelai(promesse, ms = DELAI_REDIS_MS) {
  let minuterie;
  const delai = new Promise((_resolve, reject) => {
    minuterie = setTimeout(() => reject(new Error('delai depasse')), ms);
  });
  return Promise.race([Promise.resolve(promesse), delai]).finally(() => clearTimeout(minuterie));
}

function clientRedis() {
  try {
    return require('../config/redis').getRedis() || null;
  } catch (_e) {
    return null;
  }
}

function normaliserId(id) {
  return typeof id === 'string' ? id.toLowerCase() : id;
}

function motifRedis(err) {
  return err && err.message === 'delai depasse' ? 'delai depasse' : 'erreur';
}

async function appelRedis(operation, contexte, redis, { lecture = false } = {}) {
  const client = redis === undefined ? clientRedis() : redis;
  if (!client) {
    avertir('redis-absent', `[sessionGuard] Redis indisponible, ${contexte}`);
    return { ok: false };
  }
  if (lecture && Date.now() < disjoncteurJusqua) return { ok: false };
  try {
    return { ok: true, valeur: await avecDelai(operation(client)) };
  } catch (err) {
    if (lecture && motifRedis(err) === 'delai depasse') disjoncteurJusqua = Date.now() + DUREE_DISJONCTEUR_MS;
    avertir(`redis-${motifRedis(err)}`, `[sessionGuard] Redis ${motifRedis(err)}, ${contexte}`, { error: err.message });
    return { ok: false };
  }
}

async function causeRevocation(jti, redis) {
  if (!jti) return null;
  const r = await appelRedis((c) => c.get(`bl:jti:${jti}`), 'controle de revocation ignore', redis, { lecture: true });
  if (!r.ok || !r.valeur) return null;
  return r.valeur === CAUSE_REMPLACE ? CAUSE_REMPLACE : CAUSE_REVOQUE;
}

async function jetonRevoque(jti, redis) {
  return (await causeRevocation(jti, redis)) !== null;
}

async function lireUtilisateur(userId, pool = poolParDefaut) {
  const r = await pool.query(
    'SELECT id, username, full_name, role, is_active FROM users WHERE id = $1',
    [userId]
  );
  return r.rows && r.rows.length ? r.rows[0] : null;
}

async function verifierSession(token, { secret = process.env.JWT_SECRET, pool = poolParDefaut, redis } = {}) {
  let decoded;
  try {
    decoded = jwt.verify(token, secret);
  } catch (err) {
    return { ok: false, raison: err && err.name === 'TokenExpiredError' ? 'expiree' : 'invalide' };
  }
  const cause = await causeRevocation(decoded.jti, redis);
  if (cause === CAUSE_REMPLACE) return { ok: false, raison: 'remplace' };
  if (cause) return { ok: false, raison: 'revoque' };
  let ligne;
  try {
    ligne = await lireUtilisateur(decoded.id, pool);
  } catch (err) {
    logger.warn('[sessionGuard] Lecture utilisateur impossible', { error: err.message });
    return { ok: false, raison: 'indisponible' };
  }
  if (!ligne || ligne.is_active === false) return { ok: false, raison: 'inactif' };
  const user = {
    ...decoded,
    id: ligne.id,
    username: ligne.username,
    full_name: ligne.full_name,
    role: ligne.role,
  };
  return { ok: true, user, jti: decoded.jti, exp: decoded.exp };
}

async function revoquerJti(jti, ttl = TTL_JTI_DEFAUT, redis, cause = CAUSE_REVOQUE) {
  if (!jti) return false;
  const duree = Math.max(1, Math.floor(ttl));
  const r = await appelRedis(
    (c) => (cause === CAUSE_REMPLACE
      ? c.set(`bl:jti:${jti}`, CAUSE_REMPLACE, 'EX', duree, 'NX')
      : c.set(`bl:jti:${jti}`, '1', 'EX', duree)),
    'jeton non blackliste',
    redis
  );
  return r.ok;
}

async function lireSessionActive(userId, redis, { pourEcriture = false } = {}) {
  const r = await appelRedis((c) => c.get(`user_session:${normaliserId(userId)}`), 'session active illisible', redis, { lecture: !pourEcriture });
  return r.ok ? r.valeur || null : null;
}

async function ecrireSessionActive(userId, jti, ttl, redis) {
  const r = await appelRedis((c) => c.set(`user_session:${normaliserId(userId)}`, jti, 'EX', ttl), 'session active non enregistree', redis);
  return r.ok;
}

async function effacerSessionActive(userId, redis) {
  const r = await appelRedis((c) => c.del(`user_session:${normaliserId(userId)}`), 'session active non effacee', redis);
  return r.ok;
}

async function revoquerSessionActive(userId, redis) {
  const jti = await lireSessionActive(userId, redis, { pourEcriture: true });
  if (!jti) return false;
  const ok = await revoquerJti(jti, TTL_JTI_DEFAUT, redis);
  if (!ok) {
    avertir('pointeur-conserve', '[sessionGuard] Blacklist en echec, pointeur de session conserve', { userId: normaliserId(userId) });
    return false;
  }
  await effacerSessionActive(userId, redis);
  return true;
}

module.exports = {
  verifierSession,
  lireUtilisateur,
  revoquerJti,
  revoquerSessionActive,
  lireSessionActive,
  ecrireSessionActive,
  effacerSessionActive,
  jetonRevoque,
  causeRevocation,
  appelRedis,
  CAUSE_REMPLACE,
  CAUSE_REVOQUE,
  avecDelai,
  normaliserId,
  reinitialiserAvertissements,
  MESSAGE_SESSION_INVALIDE,
  TTL_JTI_DEFAUT,
  DELAI_REDIS_MS,
};
