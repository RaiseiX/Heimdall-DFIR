// Enrichment API keys lookup: env var first, then system_settings ('integrations').
// 60s cache so enrichment bursts don't hammer the DB.
const { pool } = require('../config/database');

let cache = null;
let cacheAt = 0;
const TTL = 60_000;

async function loadFromDb() {
  const now = Date.now();
  if (cache && now - cacheAt < TTL) return cache;
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'integrations'`);
    cache = r.rows[0]?.value || {};
  } catch {
    cache = {};
  }
  cacheAt = now;
  return cache;
}

/** Returns the API key for 'virustotal' | 'abuseipdb' | 'shodan' (env wins), or null. */
async function getIntegrationKey(name) {
  const envVal = process.env[`${name.toUpperCase()}_API_KEY`];
  if (envVal) return envVal;
  const db = await loadFromDb();
  return typeof db[name] === 'string' && db[name] ? db[name] : null;
}

module.exports = { getIntegrationKey };
