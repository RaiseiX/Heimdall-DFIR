// backend/src/routes/investigation.js
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { navigatorLayer } = require('../services/killChain');
const { canAccessCase } = require('../middleware/caseAccess');

const router = express.Router({ mergeParams: true });

router.use(authenticate);
router.use(async (req, res, next) => {
  try {
    if (await canAccessCase(req.user, req.params.caseId)) return next();
    return res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' });
  } catch { return res.status(500).json({ error: "Erreur de contrôle d'accès." }); }
});

const DEFAULT_PHASES = [
  { phase: 'acquisition', title: 'Acquisition des preuves' },
  { phase: 'examination', title: 'Examen technique' },
  { phase: 'analysis',    title: 'Analyse & corrélation' },
  { phase: 'reporting',   title: 'Rédaction du rapport' },
];

router.get('/', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const [steps, findings] = await Promise.all([
      pool.query(
        `SELECT s.*, u.full_name AS assignee_name
           FROM investigation_steps s LEFT JOIN users u ON u.id = s.assignee_id
          WHERE s.case_id = $1 ORDER BY s.phase, s.position, s.created_at`, [caseId]),
      pool.query(
        `SELECT id, title, mitre_tactic, mitre_technique, confidence, significance, links_to
           FROM timeline_bookmarks WHERE case_id = $1`, [caseId]),
    ]);
    res.json({ steps: steps.rows, findings: findings.rows });
  } catch (err) { res.status(500).json({ error: 'Erreur chargement investigation' }); }
});

router.post('/seed', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const existing = await pool.query('SELECT 1 FROM investigation_steps WHERE case_id=$1 LIMIT 1', [caseId]);
    if (existing.rows.length) return res.json({ seeded: false });
    for (let i = 0; i < DEFAULT_PHASES.length; i++) {
      const p = DEFAULT_PHASES[i];
      await pool.query(
        `INSERT INTO investigation_steps (case_id, phase, title, status, position, created_by)
         VALUES ($1,$2,$3,'todo',$4,$5)`, [caseId, p.phase, p.title, i, req.user.id]);
    }
    res.json({ seeded: true });
  } catch (err) { res.status(500).json({ error: 'Erreur seed investigation' }); }
});

router.post('/steps', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { phase, title, status, position, finding_ref, assignee_id } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Titre requis' });
    const r = await pool.query(
      `INSERT INTO investigation_steps
         (case_id, phase, title, status, position, finding_ref, assignee_id, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [caseId, phase || 'analysis', title.trim(), status || 'todo', position || 0,
       finding_ref || null, assignee_id || null, req.user.id]);
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erreur création étape' }); }
});

router.put('/steps/:id', authenticate, async (req, res) => {
  try {
    const { caseId, id } = req.params;
    const { phase, title, status, position, finding_ref, assignee_id } = req.body;
    const r = await pool.query(
      `UPDATE investigation_steps SET
         phase=COALESCE($1,phase), title=COALESCE($2,title), status=COALESCE($3,status),
         position=COALESCE($4,position), finding_ref=$5, assignee_id=$6, updated_at=NOW()
       WHERE id=$7 AND case_id=$8 RETURNING *`,
      [phase || null, title || null, status || null, position != null ? position : null,
       finding_ref || null, assignee_id || null, id, caseId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Étape non trouvée' });
    res.json(r.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erreur mise à jour étape' }); }
});

router.delete('/steps/:id', authenticate, async (req, res) => {
  try {
    const { caseId, id } = req.params;
    await pool.query('DELETE FROM investigation_steps WHERE id=$1 AND case_id=$2', [id, caseId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Erreur suppression étape' }); }
});

router.get('/navigator', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const [c, f] = await Promise.all([
      pool.query('SELECT case_number FROM cases WHERE id=$1', [caseId]),
      pool.query(`SELECT mitre_technique, mitre_tactic, confidence
                    FROM timeline_bookmarks WHERE case_id=$1 AND mitre_technique IS NOT NULL`, [caseId]),
    ]);
    const layer = navigatorLayer(f.rows, c.rows[0]?.case_number || 'Heimdall');
    await auditLog(req.user.id, 'export_navigator', 'case', caseId, {}, req.ip);
    res.setHeader('Content-Disposition', `attachment; filename="killchain-${caseId}.json"`);
    res.json(layer);
  } catch (err) { res.status(500).json({ error: 'Erreur export Navigator' }); }
});

module.exports = router;
