// Reads the security policy from system_settings ('security') with safe defaults.
// 60s cache so the login path doesn't hit the DB on every attempt.
const { pool } = require('../config/database');

const DEFAULTS = {
  passwordMinLength:    8,
  lockoutThreshold:     5,
  lockoutWindowMin:     15,
  sessionDurationH:     168,
  inactivityTimeoutMin: 0,
};

let cache = null;
let cacheAt = 0;
const TTL = 60_000;

async function getSecurityPolicy() {
  const now = Date.now();
  if (cache && now - cacheAt < TTL) return cache;
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'security'`);
    cache = { ...DEFAULTS, ...(r.rows[0]?.value || {}) };
  } catch {
    cache = { ...DEFAULTS };
  }
  cacheAt = now;
  return cache;
}

module.exports = { getSecurityPolicy, SECURITY_DEFAULTS: DEFAULTS };
