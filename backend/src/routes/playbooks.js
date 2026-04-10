
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, COUNT(s.id)::int AS step_count
      FROM playbooks p
      LEFT JOIN playbook_steps s ON s.playbook_id = p.id
      WHERE p.is_active = TRUE
      GROUP BY p.id
      ORDER BY p.incident_type, p.title
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/cases/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT cp.*, p.title, p.incident_type, p.description,
             u.username as started_by_name,
             (SELECT COUNT(*)::int FROM playbook_steps s WHERE s.playbook_id = p.id) AS total_steps,
             (SELECT COUNT(*)::int FROM case_playbook_steps cps WHERE cps.case_playbook_id = cp.id AND cps.completed = TRUE) AS done_steps
      FROM case_playbooks cp
      JOIN playbooks p ON p.id = cp.playbook_id
      LEFT JOIN users u ON u.id = cp.started_by
      WHERE cp.case_id = $1
      ORDER BY cp.started_at DESC
    `, [req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/cases/:caseId/:instanceId/steps', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*,
             cps.id      AS instance_step_id,
             cps.completed,
             cps.note,
             cps.completed_at,
             u.username  AS completed_by_name
      FROM playbook_steps s
      JOIN case_playbooks cp ON cp.id = $1 AND cp.case_id = $2
      LEFT JOIN case_playbook_steps cps ON cps.step_id = s.id AND cps.case_playbook_id = $1
      LEFT JOIN users u ON u.id = cps.completed_by
      WHERE s.playbook_id = (SELECT playbook_id FROM case_playbooks WHERE id = $1)
      ORDER BY s.step_order
    `, [req.params.instanceId, req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/cases/:caseId/start', authenticate, async (req, res) => {
  try {
    const { playbook_id } = req.body;
    if (!playbook_id) return res.status(400).json({ error: 'playbook_id requis' });

    const pbCheck = await pool.query('SELECT id FROM playbooks WHERE id = $1 AND is_active = TRUE', [playbook_id]);
    if (pbCheck.rows.length === 0) return res.status(404).json({ error: 'Playbook non trouvé' });

    const result = await pool.query(
      `INSERT INTO case_playbooks (case_id, playbook_id, started_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (case_id, playbook_id) DO UPDATE SET started_at = NOW(), started_by = $3, completed_at = NULL
       RETURNING *`,
      [req.params.caseId, playbook_id, req.user.id]
    );

    await auditLog(req.user.id, 'start_playbook', 'case', req.params.caseId,
      { playbook_id }, req.ip);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/cases/:caseId/:instanceId/steps/:stepId', authenticate, async (req, res) => {
  try {
    const { completed, note } = req.body;
    const { instanceId, stepId, caseId } = req.params;

    if (completed) {
      const stepCheck = await pool.query('SELECT note_required FROM playbook_steps WHERE id = $1', [stepId]);
      if (stepCheck.rows[0]?.note_required && !note?.trim()) {
        return res.status(400).json({ error: 'Cette étape requiert une note avant d\'être cochée' });
      }
    }

    const result = await pool.query(`
      INSERT INTO case_playbook_steps (case_playbook_id, step_id, completed, note, completed_by, completed_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (case_playbook_id, step_id) DO UPDATE
        SET completed    = $3,
            note         = COALESCE($4, case_playbook_steps.note),
            completed_by = $5,
            completed_at = $6
      RETURNING *
    `, [instanceId, stepId, !!completed, note || null,
        completed ? req.user.id : null,
        completed ? new Date() : null]);

    const progress = await pool.query(`
      SELECT COUNT(s.id) AS total,
             COUNT(cps.id) FILTER (WHERE cps.completed = TRUE) AS done
      FROM playbook_steps s
      JOIN case_playbooks cp ON cp.id = $1
      LEFT JOIN case_playbook_steps cps ON cps.step_id = s.id AND cps.case_playbook_id = $1
      WHERE s.playbook_id = cp.playbook_id
    `, [instanceId]);
    const { total, done } = progress.rows[0];
    if (parseInt(done) >= parseInt(total)) {
      await pool.query('UPDATE case_playbooks SET completed_at = NOW() WHERE id = $1 AND completed_at IS NULL', [instanceId]);
    } else {
      await pool.query('UPDATE case_playbooks SET completed_at = NULL WHERE id = $1', [instanceId]);
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:id', authenticate, async (req, res) => {
  try {
    const [pb, steps] = await Promise.all([
      pool.query('SELECT * FROM playbooks WHERE id = $1', [req.params.id]),
      pool.query('SELECT * FROM playbook_steps WHERE playbook_id = $1 ORDER BY step_order', [req.params.id]),
    ]);
    if (pb.rows.length === 0) return res.status(404).json({ error: 'Playbook non trouvé' });
    res.json({ ...pb.rows[0], steps: steps.rows });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
