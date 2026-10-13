// Cross-case triage queue — "what needs attention now?".
// Aggregates the reliably-queryable signals: urgent deadlines, quarantined evidence,
// and critical/high persisted detections. Returns a flat, severity-sorted item list.
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');
const logger = require('../config/logger').default;
const triageSvc = require('../services/triageService');
const { caseListFilter, canAccessCase, ELEVATED } = require('../middleware/caseAccess');

const router = express.Router();

// Ensure the persistent alert table exists (lazy, once).
let _alertTableInit = false;
router.use((req, res, next) => {
  if (!_alertTableInit) {
    _alertTableInit = true;
    triageSvc.ensureTable().catch(e => logger.error('[triage] ensureTable error:', e.message));
  }
  next();
});

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// SLA thresholds (hours) from system_settings, with safe defaults.
async function slaThresholds() {
  try {
    const r = await pool.query(`SELECT value FROM system_settings WHERE key = 'dashboard'`);
    const sla = r.rows[0]?.value?.sla || {};
    return {
      urgentH:   Number(sla.urgentH)   > 0 ? Number(sla.urgentH)   : 24,
      warningH:  Number(sla.warningH)  > 0 ? Number(sla.warningH)  : 72,
      upcomingH: Number(sla.upcomingH) > 0 ? Number(sla.upcomingH) : 168,
    };
  } catch { return { urgentH: 24, warningH: 72, upcomingH: 168 }; }
}

router.get('/', authenticate, async (req, res) => {
  try {
    const sla = await slaThresholds();
    const accEch = caseListFilter(req.user, 'c', 2);
    const acc = caseListFilter(req.user, 'c', 1);
    const [deadlines, quarantine, detections] = await Promise.all([
      pool.query(`
        SELECT c.id, c.case_number, c.title,
               EXTRACT(EPOCH FROM (c.report_deadline - NOW())) / 3600 AS hours_remaining
        FROM cases c
        WHERE c.report_deadline IS NOT NULL
          AND c.report_deadline >= NOW()
          AND c.report_deadline <= NOW() + ($1 || ' hours')::interval
          AND c.status <> 'closed'${accEch.sql}
        ORDER BY c.report_deadline ASC
      `, [String(sla.upcomingH), ...accEch.params]).catch(() => ({ rows: [] })),
      pool.query(`
        SELECT e.id, e.name, c.id AS case_id, c.case_number, c.title
        FROM evidence e JOIN cases c ON c.id = e.case_id
        WHERE e.scan_status = 'quarantined'${acc.sql}
        ORDER BY e.created_at DESC NULLS LAST
        LIMIT 100
      `, acc.params).catch(() => ({ rows: [] })),
      pool.query(`
        SELECT ct.case_id, c.case_number, c.title,
               COUNT(*) FILTER (WHERE lower(d->>'severity') = 'critical')::int AS crit,
               COUNT(*) FILTER (WHERE lower(d->>'severity') = 'high')::int     AS high
        FROM collection_timeline ct
        JOIN cases c ON c.id = ct.case_id
        CROSS JOIN LATERAL jsonb_array_elements(ct.detections) AS d
        WHERE ct.detections IS NOT NULL AND jsonb_typeof(ct.detections) = 'array'${acc.sql}
        GROUP BY ct.case_id, c.case_number, c.title
        HAVING COUNT(*) FILTER (WHERE lower(d->>'severity') IN ('critical','high')) > 0
      `, acc.params).catch(() => ({ rows: [] })),
    ]);

    const items = [];

    for (const d of detections.rows) {
      if (d.crit > 0) items.push({ type: 'detection', severity: 'critical', case_id: d.case_id, case_number: d.case_number, title: d.title, count: d.crit, tab: 'detections' });
      if (d.high > 0) items.push({ type: 'detection', severity: 'high',     case_id: d.case_id, case_number: d.case_number, title: d.title, count: d.high, tab: 'detections' });
    }

    for (const q of quarantine.rows) {
      items.push({ type: 'quarantine', severity: 'high', case_id: q.case_id, case_number: q.case_number, title: q.title, evidence: q.name, tab: 'evidence' });
    }

    for (const dl of deadlines.rows) {
      const h = parseFloat(dl.hours_remaining);
      const sev = h <= sla.urgentH ? 'critical' : h <= sla.warningH ? 'high' : 'medium';
      items.push({ type: 'deadline', severity: sev, case_id: dl.id, case_number: dl.case_number, title: dl.title, hours_remaining: Math.round(h), tab: 'evidence' });
    }

    items.sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || (a.type < b.type ? -1 : 1));

    res.json({ items, sla, generated_at: new Date().toISOString() });
  } catch (err) {
    logger.error('triage queue error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Persistent alert inbox ───────────────────────────────────────────────

// Stats for the inbox tabs / nav badge.
router.get('/alerts/stats', authenticate, async (req, res) => {
  try {
    const acc = caseListFilter(req.user, 'c', 1);
    const { rows } = await pool.query(`
      SELECT a.status,
             COUNT(*)::int                                                    AS n,
             COUNT(*) FILTER (WHERE a.severity = 'critical')::int             AS critical,
             COUNT(*) FILTER (WHERE a.severity = 'high')::int                 AS high
        FROM triage_alerts a
        LEFT JOIN cases c ON c.id = a.case_id
       WHERE TRUE${acc.sql}
       GROUP BY a.status`, acc.params);
    const byStatus = { new: 0, in_progress: 0, resolved: 0, dismissed: 0 };
    let openCritical = 0, openHigh = 0;
    for (const r of rows) {
      byStatus[r.status] = r.n;
      if (r.status === 'new' || r.status === 'in_progress') { openCritical += r.critical; openHigh += r.high; }
    }
    res.json({ byStatus, open: byStatus.new + byStatus.in_progress, openCritical, openHigh });
  } catch (err) {
    logger.error('triage stats error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// List alerts with filters + pagination.
router.get('/alerts', authenticate, async (req, res) => {
  try {
    const { status, severity, source, case_id, q } = req.query;
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const where = [];
    const params = [];
    let i = 1;
    if (status)   { where.push(`a.status = $${i++}`);   params.push(status); }
    if (severity) { where.push(`a.severity = $${i++}`); params.push(severity); }
    if (source)   { where.push(`a.source = $${i++}`);   params.push(source); }
    if (case_id)  { where.push(`a.case_id = $${i++}`);  params.push(case_id); }
    if (q)        { where.push(`(a.title ILIKE $${i} OR a.entity_value ILIKE $${i})`); params.push(`%${q}%`); i++; }
    const acc = caseListFilter(req.user, 'c', i);
    const clause = `WHERE TRUE${where.map((w) => ` AND ${w}`).join('')}${acc.sql}`;
    params.push(...acc.params);

    const totalR = await pool.query(`SELECT COUNT(*)::int AS n FROM triage_alerts a LEFT JOIN cases c ON c.id = a.case_id ${clause}`, params);
    const rowsR  = await pool.query(
      `SELECT a.*, c.case_number, u.full_name AS assignee_name
         FROM triage_alerts a
         LEFT JOIN cases c ON c.id = a.case_id
         LEFT JOIN users u ON u.id = a.assignee
         ${clause}
         ORDER BY (CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END),
                  a.last_seen DESC
         LIMIT ${limit} OFFSET ${(page - 1) * limit}`,
      params,
    );
    res.json({ results: rowsR.rows, total: totalR.rows[0].n, page, limit });
  } catch (err) {
    logger.error('triage list error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function resoudreAlerteAutorisee(req, res) {
  const id = req.params.id;
  if (typeof id !== 'string' || !UUID_RE.test(id)) {
    res.status(404).json({ error: 'Alerte non trouvée' });
    return null;
  }
  const r = await pool.query('SELECT id, case_id FROM triage_alerts WHERE id = $1', [id]);
  const caseId = r.rows[0] ? r.rows[0].case_id : null;
  const autorise = r.rows[0]
    ? (caseId ? await canAccessCase(req.user, String(caseId)) : ELEVATED.has(req.user.role))
    : false;
  if (!autorise) {
    res.status(404).json({ error: 'Alerte non trouvée' });
    return null;
  }
  return { caseId: caseId ? String(caseId) : null };
}

// Create an alert (manual, or programmatic from services).
router.post('/alerts', authenticate, requireRole('analyst', 'admin'), async (req, res) => {
  try {
    const demande = req.body && req.body.case_id ? req.body.case_id : null;
    if (demande) {
      if (typeof demande !== 'string' || !UUID_RE.test(demande) || !(await canAccessCase(req.user, demande))) {
        return res.status(404).json({ error: 'Ressource introuvable' });
      }
    } else if (!ELEVATED.has(req.user.role)) {
      return res.status(403).json({ error: 'Action réservée aux rôles élevés' });
    }
    const alert = await triageSvc.createAlert({ ...req.body, case_id: demande, created_by: req.user.id });
    await auditLog(req.user.id, 'create_triage_alert', 'triage_alert', alert.id, { source: alert.source, severity: alert.severity }, req.ip);
    res.status(201).json(alert);
  } catch (err) {
    if (err && err.code === '23505') return res.status(409).json({ error: 'Alerte déjà ouverte' });
    logger.error('triage create error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Update status / assignee / severity.
router.patch('/alerts/:id', authenticate, requireRole('analyst', 'admin'), async (req, res) => {
  try {
    const { status, assignee, severity } = req.body;
    if (status && !triageSvc.STATUSES.includes(status))     return res.status(400).json({ error: 'Statut invalide' });
    if (severity && !triageSvc.SEVERITIES.includes(severity)) return res.status(400).json({ error: 'Sévérité invalide' });
    const cible = await resoudreAlerteAutorisee(req, res);
    if (!cible) return;
    const sets = [], params = []; let i = 1;
    if (status   !== undefined) { sets.push(`status = $${i++}`);   params.push(status); }
    if (severity !== undefined) { sets.push(`severity = $${i++}`); params.push(severity); }
    if (assignee !== undefined) { sets.push(`assignee = $${i++}`); params.push(assignee || null); }
    if (!sets.length) return res.status(400).json({ error: 'Rien à mettre à jour' });
    sets.push('updated_at = NOW()');
    params.push(req.params.id);
    let portee = ' AND case_id IS NULL';
    if (cible.caseId) { params.push(cible.caseId); portee = ` AND case_id = $${i + 1}`; }
    const r = await pool.query(`UPDATE triage_alerts SET ${sets.join(', ')} WHERE id = $${i}${portee} RETURNING *`, params);
    if (!r.rowCount) return res.status(404).json({ error: 'Alerte non trouvée' });
    res.json(r.rows[0]);
  } catch (err) {
    logger.error('triage patch error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Dismiss as false positive (feeds the future FP-tuning loop).
router.post('/alerts/:id/dismiss', authenticate, requireRole('analyst', 'admin'), async (req, res) => {
  try {
    const cible = await resoudreAlerteAutorisee(req, res);
    if (!cible) return;
    const r = await pool.query(
      `UPDATE triage_alerts SET status = 'dismissed', dismiss_reason = $1, updated_at = NOW()
       WHERE id = $2 AND ${cible.caseId ? 'case_id = $3' : 'case_id IS NULL'}
       RETURNING id, source, severity, entity_type, entity_value, dedup_key`,
      cible.caseId ? [req.body.reason || null, req.params.id, cible.caseId] : [req.body.reason || null, req.params.id],
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Alerte non trouvée' });
    await auditLog(req.user.id, 'dismiss_triage_alert', 'triage_alert', req.params.id, { reason: req.body.reason || null, ...r.rows[0] }, req.ip);
    res.json({ success: true });
  } catch (err) {
    logger.error('triage dismiss error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/alerts/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const r = await pool.query(`DELETE FROM triage_alerts WHERE id = $1 RETURNING source, severity`, [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Alerte non trouvée' });
    await auditLog(req.user.id, 'delete_triage_alert', 'triage_alert', req.params.id, r.rows[0], req.ip);
    res.json({ success: true });
  } catch (err) {
    logger.error('triage delete error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
