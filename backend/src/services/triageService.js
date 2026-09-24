// Persistent triage alert layer — the "inbox" that automation feeds into.
// Auto-triage, IOC hits, watchlists, YARA/Sigma matches etc. call createAlert();
// analysts then work each alert through its lifecycle (new → in_progress →
// resolved | dismissed). De-duplication coalesces repeats of the same finding.
const { pool } = require('../config/database');
const logger = require('../config/logger').default;

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['new', 'in_progress', 'resolved', 'dismissed'];
const SEV_RANK   = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

let _ready = false;
async function ensureTable() {
  if (_ready) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS triage_alerts (
      id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      title          TEXT NOT NULL,
      description    TEXT,
      source         VARCHAR(40)  NOT NULL DEFAULT 'manual',
      severity       VARCHAR(12)  NOT NULL DEFAULT 'medium',
      status         VARCHAR(16)  NOT NULL DEFAULT 'new',
      dedup_key      VARCHAR(255),
      hit_count      INTEGER      NOT NULL DEFAULT 1,
      case_id        UUID REFERENCES cases(id) ON DELETE SET NULL,
      entity_type    VARCHAR(20),
      entity_value   VARCHAR(500),
      assignee       UUID REFERENCES users(id) ON DELETE SET NULL,
      dismiss_reason TEXT,
      metadata       JSONB DEFAULT '{}'::jsonb,
      created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
      first_seen     TIMESTAMPTZ DEFAULT NOW(),
      last_seen      TIMESTAMPTZ DEFAULT NOW(),
      created_at     TIMESTAMPTZ DEFAULT NOW(),
      updated_at     TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_triage_status   ON triage_alerts(status, severity);
    CREATE INDEX IF NOT EXISTS idx_triage_case     ON triage_alerts(case_id);
    -- One OPEN alert per dedup_key; resolved/dismissed ones don't block new alerts.
    CREATE UNIQUE INDEX IF NOT EXISTS idx_triage_dedup_open
      ON triage_alerts(dedup_key)
      WHERE dedup_key IS NOT NULL AND status IN ('new', 'in_progress');
  `);
  _ready = true;
}

/**
 * Create a triage alert, coalescing repeats of the same finding.
 * If an OPEN alert with the same dedup_key exists, bump its hit_count / last_seen
 * (and escalate severity if the new one is higher) instead of inserting a duplicate.
 * @returns the created or updated alert row.
 */
async function createAlert(a = {}) {
  await ensureTable();
  const severity = SEVERITIES.includes(a.severity) ? a.severity : 'medium';
  const dedup    = a.dedup_key ? String(a.dedup_key).slice(0, 255) : null;

  if (dedup) {
    const upd = await pool.query(
      `UPDATE triage_alerts
          SET hit_count = hit_count + 1,
              last_seen = NOW(),
              updated_at = NOW(),
              severity  = $2,
              case_id   = COALESCE(case_id, $3)
        WHERE dedup_key = $1 AND status IN ('new', 'in_progress')
        RETURNING *`,
      [dedup, severity, a.case_id || null],
    ).catch(e => { logger.warn('[triage] dedup update failed', { error: e.message }); return { rowCount: 0 }; });
    if (upd.rowCount) return upd.rows[0];
  }

  const ins = await pool.query(
    `INSERT INTO triage_alerts
       (title, description, source, severity, dedup_key, case_id, entity_type, entity_value, metadata, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     RETURNING *`,
    [
      String(a.title || 'Alerte').slice(0, 500),
      a.description || null,
      a.source || 'manual',
      severity,
      dedup,
      a.case_id || null,
      a.entity_type || null,
      a.entity_value ? String(a.entity_value).slice(0, 500) : null,
      a.metadata || {},
      a.created_by || null,
    ],
  );
  return ins.rows[0];
}

/**
 * Downgrade an open triage alert to 'info' when enrichment confirms noise.
 * If no open alert matches the dedup_key, this is a no-op.
 * @param {string} dedupKey  - dedup_key of the alert to downgrade
 * @param {string} reason    - human-readable noise reason from assessNoise()
 */
async function denoiseAlert(dedupKey, reason) {
  if (!dedupKey) return;
  await ensureTable();
  await pool.query(
    `UPDATE triage_alerts
        SET severity   = 'info',
            description = COALESCE(description, '') || E'\n[Noise] ' || $2,
            updated_at  = NOW()
      WHERE dedup_key = $1
        AND status IN ('new', 'in_progress')
        AND severity != 'info'`,
    [dedupKey, reason || 'Benign background traffic'],
  ).catch(e => logger.warn('[triage] denoiseAlert failed', { error: e.message }));
}

/**
 * Downgrade any open alert whose entity_value matches, when no dedup_key is available.
 * Used by IOC enrichment to retroactively quiet noise-confirmed indicators.
 */
async function denoiseByEntity(entityValue, reason) {
  if (!entityValue) return;
  await ensureTable();
  await pool.query(
    `UPDATE triage_alerts
        SET severity    = 'info',
            description = COALESCE(description, '') || E'\n[Noise] ' || $2,
            updated_at  = NOW()
      WHERE entity_value = $1
        AND status IN ('new', 'in_progress')
        AND severity != 'info'`,
    [String(entityValue).slice(0, 500), reason || 'Benign background traffic'],
  ).catch(e => logger.warn('[triage] denoiseByEntity failed', { error: e.message }));
}

module.exports = { ensureTable, createAlert, denoiseAlert, denoiseByEntity, SEVERITIES, STATUSES, SEV_RANK };
