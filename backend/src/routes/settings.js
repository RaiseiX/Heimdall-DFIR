// frontend dashboard / platform settings — key/JSONB store.
// Read: any authenticated analyst (dashboard needs SLA thresholds to render).
// Write: admin only.
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');
const logger = require('../config/logger').default;

const router = express.Router();

// ── Idempotent schema (project pattern: DDL at module load) ──────────────────
pool.query(`
  CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID
  )
`).catch(err => logger.error('system_settings DDL error:', err.message));

// ── Platform defaults (hours). SLA buckets for the dashboard deadline widget. ─
const DEFAULT_DASHBOARD = {
  sla: { urgentH: 24, warningH: 72, upcomingH: 168 }, // ≤24h, ≤72h, ≤7d
};

// Clamp + validate SLA thresholds so a bad PUT can't break the widget.
function sanitizeSla(input = {}) {
  const def = DEFAULT_DASHBOARD.sla;
  const num = (v, d) => {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 && n <= 24 * 365 ? Math.round(n) : d;
  };
  let urgentH   = num(input.urgentH,   def.urgentH);
  let warningH  = num(input.warningH,  def.warningH);
  let upcomingH = num(input.upcomingH, def.upcomingH);
  // Enforce strict ordering urgent < warning < upcoming.
  if (warningH  <= urgentH)  warningH  = urgentH + 1;
  if (upcomingH <= warningH) upcomingH = warningH + 1;
  return { urgentH, warningH, upcomingH };
}

// ── Security policy defaults ─────────────────────────────────────────────────
// Stored under 'security'. NOT yet enforced by auth — this endpoint only persists
// the policy; wiring into login/JWT/inactivity is a separate, validated step.
const DEFAULT_SECURITY = {
  passwordMinLength:    8,    // current hard floor
  lockoutThreshold:     5,    // failed logins before lock (0 = disabled)
  lockoutWindowMin:     15,   // lock duration, minutes
  sessionDurationH:     168,  // refresh-session lifetime, hours (7d)
  inactivityTimeoutMin: 0,    // auto-logout after N idle minutes (0 = disabled)
};

function sanitizeSecurity(input = {}) {
  const d = DEFAULT_SECURITY;
  const clamp = (v, def, min, max) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= min && n <= max ? Math.round(n) : def;
  };
  return {
    passwordMinLength:    clamp(input.passwordMinLength,    d.passwordMinLength,    8, 128),
    lockoutThreshold:     clamp(input.lockoutThreshold,     d.lockoutThreshold,     0, 100),
    lockoutWindowMin:     clamp(input.lockoutWindowMin,     d.lockoutWindowMin,     1, 1440),
    sessionDurationH:     clamp(input.sessionDurationH,     d.sessionDurationH,     1, 24 * 90),
    inactivityTimeoutMin: clamp(input.inactivityTimeoutMin, d.inactivityTimeoutMin, 0, 1440),
  };
}

// GET — admin only (security policy is sensitive)
router.get('/security', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'security'`);
    res.json(sanitizeSecurity(r.rows[0]?.value || {}));
  } catch (err) {
    logger.error('settings.security GET error:', err.message);
    res.json(DEFAULT_SECURITY);
  }
});

router.put('/security', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const value = sanitizeSecurity(req.body || {});
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at, updated_by)
       VALUES ('security', $1, NOW(), $2)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW(), updated_by = $2`,
      [JSON.stringify(value), req.user.id]
    );
    await auditLog(req.user.id, 'update_settings', 'system', null, { key: 'security', value }, req.ip);
    res.json(value);
  } catch (err) {
    logger.error('settings.security PUT error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Client-safe subset of the security policy — any authenticated user (for the
// front-end idle-logout). Never exposes lockout/password internals.
router.get('/security/client', authenticate, async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'security'`);
    const s = sanitizeSecurity(r.rows[0]?.value || {});
    res.json({ inactivityTimeoutMin: s.inactivityTimeoutMin });
  } catch {
    res.json({ inactivityTimeoutMin: 0 });
  }
});

// GET — readable by any authenticated user
router.get('/dashboard', authenticate, async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'dashboard'`);
    const stored = r.rows[0]?.value || {};
    res.json({ sla: sanitizeSla(stored.sla) });
  } catch (err) {
    logger.error('settings.dashboard GET error:', err.message);
    res.json(DEFAULT_DASHBOARD); // resilient — never block the dashboard
  }
});

// PUT — admin only
router.put('/dashboard', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const value = { sla: sanitizeSla(req.body?.sla) };
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at, updated_by)
       VALUES ('dashboard', $1, NOW(), $2)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW(), updated_by = $2`,
      [JSON.stringify(value), req.user.id]
    );
    await auditLog(req.user.id, 'update_settings', 'system', null, { key: 'dashboard', value }, req.ip);
    res.json(value);
  } catch (err) {
    logger.error('settings.dashboard PUT error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── AI settings (active LLM model, chosen in the Opérations tab) ─────────────
// Persisted server-side so every AI feature (case chat, report, agentic) uses
// the same model the operator selected — not a client-only localStorage choice.
router.get('/ai', authenticate, async (_req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'ai'`);
    res.json({ active_model: r.rows[0]?.value?.active_model || null });
  } catch (err) {
    logger.error('settings.ai GET error:', err.message);
    res.json({ active_model: null });
  }
});

router.put('/ai', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const active_model = (req.body?.active_model && String(req.body.active_model).trim()) || null;
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at, updated_by)
       VALUES ('ai', $1, NOW(), $2)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW(), updated_by = $2`,
      [JSON.stringify({ active_model }), req.user.id]
    );
    await auditLog(req.user.id, 'update_settings', 'system', null, { key: 'ai', active_model }, req.ip);
    res.json({ active_model });
  } catch (err) {
    logger.error('settings.ai PUT error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Enrichment integrations (VirusTotal / AbuseIPDB / Shodan) ────────────────
// Keys are stored in system_settings under 'integrations'. GET never returns
// the raw key — only configured state + last 4 chars. Env vars take precedence
// at enrichment time (see services/integrationKeys.js).
const INTEGRATION_KEYS = ['virustotal', 'abuseipdb', 'shodan'];

router.get('/integrations', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'integrations'`);
    const stored = r.rows[0]?.value || {};
    const out = {};
    for (const k of INTEGRATION_KEYS) {
      const envSet = Boolean(process.env[`${k.toUpperCase()}_API_KEY`]);
      const dbVal  = typeof stored[k] === 'string' ? stored[k] : '';
      out[k] = {
        configured: envSet || dbVal.length > 0,
        source: envSet ? 'env' : (dbVal ? 'db' : null),
        last4: dbVal ? dbVal.slice(-4) : null,
      };
    }
    res.json(out);
  } catch (err) {
    logger.error('settings.integrations GET error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/integrations', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'integrations'`);
    const stored = r.rows[0]?.value || {};
    for (const k of INTEGRATION_KEYS) {
      if (req.body[k] === undefined) continue;          // untouched
      const v = String(req.body[k] || '').trim();
      if (v === '') delete stored[k];                   // empty string = clear
      else stored[k] = v;
    }
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at, updated_by)
       VALUES ('integrations', $1, NOW(), $2)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW(), updated_by = $2`,
      [JSON.stringify(stored), req.user.id]
    );
    await auditLog(req.user.id, 'update_settings', 'system', null, { key: 'integrations', fields: Object.keys(req.body) }, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('settings.integrations PUT error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Automatic retention purge (opt-in, fail-safe) ───────────────────────────
const { findEligible, runRetentionPurge } = require('../services/retentionService');

router.get('/retention', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'retention'`);
    const v = r.rows[0]?.value || {};
    res.json({ enabled: v.enabled === true, days: Number(v.days) > 0 ? Math.round(Number(v.days)) : 365 });
  } catch (err) {
    logger.error('settings.retention GET:', err.message);
    res.json({ enabled: false, days: 365 });
  }
});

router.put('/retention', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const enabled = req.body?.enabled === true;
    const days = Number(req.body?.days) >= 1 && Number(req.body?.days) <= 36500 ? Math.round(Number(req.body.days)) : 365;
    const value = { enabled, days };
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at, updated_by)
       VALUES ('retention', $1, NOW(), $2)
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW(), updated_by = $2`,
      [JSON.stringify(value), req.user.id]
    );
    await auditLog(req.user.id, 'update_settings', 'system', null, { key: 'retention', value }, req.ip);
    res.json(value);
  } catch (err) {
    logger.error('settings.retention PUT:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Dry-run preview: which closed cases WOULD be purged at a given threshold.
router.get('/retention/preview', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const days = Number(req.query.days) >= 1 ? Math.round(Number(req.query.days)) : null;
    let effectiveDays = days;
    if (effectiveDays == null) {
      const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'retention'`);
      effectiveDays = Number(r.rows[0]?.value?.days) > 0 ? Math.round(Number(r.rows[0].value.days)) : 365;
    }
    const eligible = await findEligible(effectiveDays);
    res.json({ days: effectiveDays, count: eligible.length, eligible });
  } catch (err) {
    logger.error('settings.retention preview:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Toggle per-case exemption from auto-purge.
router.patch('/retention/exempt/:caseId', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const exempt = req.body?.exempt === true;
    const r = await pool.query(
      `UPDATE cases SET retention_exempt = $1 WHERE id = $2 RETURNING id, case_number`,
      [exempt, req.params.caseId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });
    await auditLog(req.user.id, 'update_settings', 'case', req.params.caseId, { retention_exempt: exempt, case_number: r.rows[0].case_number }, req.ip);
    res.json({ id: r.rows[0].id, retention_exempt: exempt });
  } catch (err) {
    logger.error('settings.retention exempt:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Manual "run now" — purges eligible cases immediately (admin, audited).
router.post('/retention/run', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await runRetentionPurge({ dryRun: false, actorId: req.user.id, ip: req.ip });
    await auditLog(req.user.id, 'retention_run_manual', 'system', null, { purged: result.purged, days: result.config.days }, req.ip);
    res.json(result);
  } catch (err) {
    logger.error('settings.retention run:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
