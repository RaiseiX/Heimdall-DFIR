// Automatic retention purge — fail-safe by design.
// Eligible = status 'closed' AND closed_at older than N days AND NOT legal_hold
// AND NOT retention_exempt. Cases without a closed_at are NEVER eligible.
const { pool } = require('../config/database');
const { hardDeleteCase } = require('./hardDeleteService');
const { auditLog } = require('../middleware/auth');
const logger = require('../config/logger').default;

// Idempotent: per-case manual exemption flag.
pool.query(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS retention_exempt BOOLEAN NOT NULL DEFAULT FALSE`)
  .catch(err => logger.error('retention_exempt DDL:', err.message));

async function getRetentionConfig() {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'retention'`);
    const v = r.rows[0]?.value || {};
    return { enabled: v.enabled === true, days: Number(v.days) > 0 ? Math.round(Number(v.days)) : 365 };
  } catch { return { enabled: false, days: 365 }; }
}

// Returns the list of cases that WOULD be purged for a given threshold (days).
async function findEligible(days) {
  const r = await pool.query(
    `SELECT id, case_number, title, closed_at,
            EXTRACT(DAY FROM (NOW() - closed_at))::int AS days_closed
     FROM cases
     WHERE status = 'closed'
       AND closed_at IS NOT NULL
       AND closed_at < NOW() - ($1 || ' days')::interval
       AND COALESCE(legal_hold, FALSE) = FALSE
       AND COALESCE(retention_exempt, FALSE) = FALSE
     ORDER BY closed_at ASC`,
    [String(days)]
  );
  return r.rows;
}

// dryRun=true → just return the eligible list. Otherwise purge each (irreversible).
async function runRetentionPurge({ dryRun = false, actorId = null, ip = null } = {}) {
  const cfg = await getRetentionConfig();
  const eligible = await findEligible(cfg.days);
  if (dryRun) return { dryRun: true, config: cfg, eligible, purged: 0 };

  let purged = 0;
  const errors = [];
  for (const c of eligible) {
    try {
      await hardDeleteCase(pool, c.id, actorId, ip);
      await auditLog(actorId, 'retention_auto_purge', 'case', c.id,
        { case_number: c.case_number, days_closed: c.days_closed, policy_days: cfg.days }, ip);
      purged++;
    } catch (err) {
      logger.error(`[retention] purge ${c.case_number} failed:`, err.message);
      errors.push({ case_number: c.case_number, error: err.message });
    }
  }
  if (purged > 0 || errors.length) logger.info(`[retention] auto-purge: ${purged} purged, ${errors.length} errors`);
  return { dryRun: false, config: cfg, eligible, purged, errors };
}

// Daily scheduler entry point — only acts when explicitly enabled.
async function retentionTick() {
  const cfg = await getRetentionConfig();
  if (!cfg.enabled) return;
  await runRetentionPurge({ dryRun: false, actorId: null, ip: 'system:cron' });
}

module.exports = { getRetentionConfig, findEligible, runRetentionPurge, retentionTick };
