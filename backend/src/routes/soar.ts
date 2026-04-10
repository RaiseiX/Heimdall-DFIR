
import { Router, Request, Response } from 'express';
import { Pool } from 'pg';
import { AuthRequest } from '../types/index';
import { runSoarAsync } from '../services/soarService';

const router = Router({ mergeParams: true });

function pool(res: Response): Pool { return res.app.locals.pool; }
function io(res: Response)   { return res.app.locals.io; }

const { authenticate, requireRole, auditLog } = require('../middleware/auth');

router.get('/alerts', authenticate, async (req: AuthRequest, res: Response) => {
  const { caseId } = req.params;
  const { type, severity, ack, limit = '100' } = req.query as Record<string, string>;

  try {
    let q = `
      SELECT a.*, u.username AS acknowledged_by_name
      FROM automated_hunt_alerts a
      LEFT JOIN users u ON u.id = a.acknowledged_by
      WHERE a.case_id = $1
    `;
    const params: unknown[] = [caseId];
    let i = 2;

    if (type)     { q += ` AND a.type = $${i++}`;         params.push(type); }
    if (severity) { q += ` AND a.severity = $${i++}`;     params.push(severity); }
    if (ack !== undefined) {
      q += ` AND a.acknowledged = $${i++}`;
      params.push(ack === 'true');
    }

    q += ` ORDER BY
      CASE a.severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
        ELSE 5
      END,
      a.created_at DESC
      LIMIT $${i++}`;
    params.push(Math.min(parseInt(limit, 10) || 100, 500));

    const result = await pool(res).query(q, params);

    const summary = await pool(res).query(
      `SELECT
         COUNT(*) FILTER (WHERE NOT acknowledged)                                  AS total_unack,
         COUNT(*) FILTER (WHERE severity = 'critical' AND NOT acknowledged)        AS critical,
         COUNT(*) FILTER (WHERE severity = 'high'     AND NOT acknowledged)        AS high,
         COUNT(*) FILTER (WHERE severity = 'medium'   AND NOT acknowledged)        AS medium
       FROM automated_hunt_alerts
       WHERE case_id = $1`,
      [caseId],
    );

    res.json({ alerts: result.rows, summary: summary.rows[0] });
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/alerts/:alertId/ack', authenticate, async (req: AuthRequest, res: Response) => {
  const { caseId, alertId } = req.params;
  const { acknowledged = true } = req.body;
  try {
    const r = await pool(res).query(
      `UPDATE automated_hunt_alerts
         SET acknowledged     = $1,
             acknowledged_by  = $2,
             acknowledged_at  = $3
       WHERE id = $4 AND case_id = $5
       RETURNING *`,
      [!!acknowledged,
       acknowledged ? req.user!.id : null,
       acknowledged ? new Date()   : null,
       alertId, caseId],
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Alerte introuvable' });
    res.json(r.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/alerts/ack-all', authenticate, async (req: AuthRequest, res: Response) => {
  const { caseId } = req.params;
  try {
    const r = await pool(res).query(
      `UPDATE automated_hunt_alerts
         SET acknowledged = TRUE, acknowledged_by = $1, acknowledged_at = NOW()
       WHERE case_id = $2 AND acknowledged = FALSE`,
      [req.user!.id, caseId],
    );
    res.json({ acknowledged_count: r.rowCount });
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/run', authenticate, async (req: AuthRequest, res: Response) => {
  const { caseId } = req.params;
  try {
    const caseCheck = await pool(res).query('SELECT id FROM cases WHERE id = $1', [caseId]);
    if (!caseCheck.rows.length) return res.status(404).json({ error: 'Cas introuvable' });

    runSoarAsync(caseId, pool(res), 'manual', io(res));

    await auditLog(req.user!.id, 'soar_run', 'case', caseId, { triggered_by: 'manual' }, req.ip);
    res.json({ message: 'Analyse SOAR démarrée', case_id: caseId });
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

export = router;
