const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { canAccessCase } = require('../middleware/caseAccess');

const router = express.Router({ mergeParams: true });
router.use(authenticate);
router.use(async (req, res, next) => {           // case-access guard (savedSearches.js pattern)
  try {
    if (await canAccessCase(req.user, req.params.caseId)) return next();
    return res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' });
  } catch { return res.status(500).json({ error: "Erreur de contrôle d'accès." }); }
});

// attached scenarios + progress
router.get('/', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT cd.id AS instance_id, cd.scenario_id, s.title, s.dfiq_id,
              (SELECT COUNT(*)::int FROM dfiq_questions q WHERE q.scenario_id = s.id) AS total,
              (SELECT COUNT(*)::int FROM case_dfiq_answers a WHERE a.case_dfiq_id = cd.id AND a.status = 'answered') AS answered
         FROM case_dfiq cd JOIN dfiq_scenarios s ON s.id = cd.scenario_id
        WHERE cd.case_id = $1 ORDER BY s.title`, [req.params.caseId]);
    res.json(r.rows);
  } catch { res.status(500).json({ error: 'Erreur chargement DFIQ du cas' }); }
});

router.post('/attach', async (req, res) => {
  try {
    const { scenario_id } = req.body;
    if (!scenario_id) return res.status(400).json({ error: 'scenario_id requis' });
    const r = await pool.query(
      `INSERT INTO case_dfiq (case_id, scenario_id, started_by) VALUES ($1,$2,$3)
       ON CONFLICT (case_id, scenario_id) DO UPDATE SET started_by = $3 RETURNING *`,
      [req.params.caseId, scenario_id, req.user.id]);
    await auditLog(req.user.id, 'attach_dfiq', 'case', req.params.caseId, { scenario_id }, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Scénario inconnu' });
    res.status(500).json({ error: "Erreur d'attachement DFIQ" });
  }
});

// load an instance owned by this case: guard helper
async function instanceInCase(instanceId, caseId) {
  const r = await pool.query('SELECT id FROM case_dfiq WHERE id=$1 AND case_id=$2', [instanceId, caseId]);
  return r.rows.length > 0;
}

router.delete('/:instanceId', async (req, res) => {
  try {
    if (!await instanceInCase(req.params.instanceId, req.params.caseId)) return res.status(404).json({ error: 'Instance introuvable' });
    await pool.query('DELETE FROM case_dfiq WHERE id=$1 AND case_id=$2', [req.params.instanceId, req.params.caseId]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Erreur détachement' }); }
});

router.get('/:instanceId/answers', async (req, res) => {
  try {
    if (!await instanceInCase(req.params.instanceId, req.params.caseId)) return res.status(404).json({ error: 'Instance introuvable' });
    const r = await pool.query(
      `SELECT q.id AS question_id, q.text, q.facet_name, q.position,
              a.id AS answer_id, COALESCE(a.status,'todo') AS status, a.note,
              COALESCE(json_agg(json_build_object('bookmark_id', e.bookmark_id))
                       FILTER (WHERE e.bookmark_id IS NOT NULL), '[]') AS evidence
         FROM case_dfiq cd
         JOIN dfiq_questions q ON q.scenario_id = cd.scenario_id
         LEFT JOIN case_dfiq_answers a ON a.case_dfiq_id = cd.id AND a.question_id = q.id
         LEFT JOIN case_dfiq_evidence e ON e.case_dfiq_answer_id = a.id
        WHERE cd.id = $1
        GROUP BY q.id, a.id ORDER BY q.position`, [req.params.instanceId]);
    res.json(r.rows);
  } catch { res.status(500).json({ error: 'Erreur chargement réponses' }); }
});

router.put('/:instanceId/answers/:questionId', async (req, res) => {
  try {
    if (!await instanceInCase(req.params.instanceId, req.params.caseId)) return res.status(404).json({ error: 'Instance introuvable' });
    const { status = 'todo', note = null } = req.body;
    if (!['todo', 'answered', 'not_applicable'].includes(status)) return res.status(400).json({ error: 'status invalide' });
    const r = await pool.query(
      `INSERT INTO case_dfiq_answers (case_dfiq_id, question_id, status, note, answered_by, answered_at)
       VALUES ($1,$2,$3,$4,$5,NOW())
       ON CONFLICT (case_dfiq_id, question_id)
         DO UPDATE SET status=$3, note=$4, answered_by=$5, answered_at=NOW() RETURNING *`,
      [req.params.instanceId, req.params.questionId, status, note, req.user.id]);
    res.json(r.rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Question inconnue' });
    res.status(500).json({ error: 'Erreur enregistrement réponse' });
  }
});

router.post('/:instanceId/answers/:questionId/evidence', async (req, res) => {
  try {
    if (!await instanceInCase(req.params.instanceId, req.params.caseId)) return res.status(404).json({ error: 'Instance introuvable' });
    const { bookmark_id } = req.body;
    if (!bookmark_id) return res.status(400).json({ error: 'bookmark_id requis' });
    const bm = await pool.query('SELECT id FROM timeline_bookmarks WHERE id=$1 AND case_id=$2', [bookmark_id, req.params.caseId]);
    if (!bm.rows.length) return res.status(400).json({ error: 'Bookmark hors de ce cas' });   // same-case enforcement
    const ans = await pool.query(
      `INSERT INTO case_dfiq_answers (case_dfiq_id, question_id, status)
       VALUES ($1,$2,'answered') ON CONFLICT (case_dfiq_id, question_id) DO UPDATE SET status = case_dfiq_answers.status
       RETURNING id`, [req.params.instanceId, req.params.questionId]);
    await pool.query(
      `INSERT INTO case_dfiq_evidence (case_dfiq_answer_id, bookmark_id, added_by) VALUES ($1,$2,$3)
       ON CONFLICT DO NOTHING`, [ans.rows[0].id, bookmark_id, req.user.id]);
    res.status(201).json({ success: true });
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Question inconnue' });   // FK: bad question_id (consistent with /attach + /answers handlers)
    res.status(500).json({ error: 'Erreur ajout preuve' });
  }
});

router.delete('/:instanceId/answers/:questionId/evidence/:bookmarkId', async (req, res) => {
  try {
    if (!await instanceInCase(req.params.instanceId, req.params.caseId)) return res.status(404).json({ error: 'Instance introuvable' });
    await pool.query(
      `DELETE FROM case_dfiq_evidence e USING case_dfiq_answers a
        WHERE e.case_dfiq_answer_id = a.id AND a.case_dfiq_id = $1 AND a.question_id = $2 AND e.bookmark_id = $3`,
      [req.params.instanceId, req.params.questionId, req.params.bookmarkId]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Erreur suppression preuve' }); }
});

module.exports = router;
