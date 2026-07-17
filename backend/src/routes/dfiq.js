const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { ELEVATED } = require('../middleware/caseAccess');

const router = express.Router();
router.use(authenticate);
const requireElevated = (req, res, next) =>
  ELEVATED.has(req.user.role) ? next() : res.status(403).json({ error: 'Rôle élevé requis' });

// list scenarios with question counts
router.get('/scenarios', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT s.id, s.dfiq_id, s.title, s.description, s.tags, s.is_custom,
              (SELECT COUNT(*)::int FROM dfiq_questions q WHERE q.scenario_id = s.id) AS question_count
         FROM dfiq_scenarios s ORDER BY s.is_custom, s.title`);
    res.json(r.rows);
  } catch { res.status(500).json({ error: 'Erreur chargement scénarios DFIQ' }); }
});

// one scenario + questions (facet-grouped by the client) + approaches
router.get('/scenarios/:id', async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM dfiq_scenarios WHERE id = $1', [req.params.id]);
    if (!s.rows.length) return res.status(404).json({ error: 'Scénario introuvable' });
    const q = await pool.query('SELECT * FROM dfiq_questions WHERE scenario_id = $1 ORDER BY position', [req.params.id]);
    const a = await pool.query(
      `SELECT a.* FROM dfiq_approaches a JOIN dfiq_questions q ON q.id = a.question_id
        WHERE q.scenario_id = $1 ORDER BY a.position`, [req.params.id]);
    res.json({ scenario: s.rows[0], questions: q.rows, approaches: a.rows });
  } catch { res.status(500).json({ error: 'Erreur chargement scénario DFIQ' }); }
});

// create custom scenario
router.post('/scenarios', requireElevated, async (req, res) => {
  try {
    const { title, description = null, tags = [] } = req.body;
    if (!title?.trim() || title.trim().length > 300) return res.status(400).json({ error: 'title requis (1–300)' });
    const r = await pool.query(
      `INSERT INTO dfiq_scenarios (title, description, tags, is_custom, source, created_by)
       VALUES ($1,$2,$3,TRUE,'custom',$4) RETURNING *`,
      [title.trim(), description, Array.isArray(tags) ? tags : [], req.user.id]);
    await auditLog(req.user.id, 'create_dfiq_scenario', 'dfiq_scenario', r.rows[0].id, { title: title.trim() }, req.ip);
    res.status(201).json(r.rows[0]);
  } catch { res.status(500).json({ error: 'Erreur création scénario' }); }
});

// helper: mutations only on custom rows
async function assertCustomScenario(id) {
  const r = await pool.query('SELECT is_custom FROM dfiq_scenarios WHERE id = $1', [id]);
  if (!r.rows.length) return { code: 404, error: 'Scénario introuvable' };
  if (!r.rows[0].is_custom) return { code: 403, error: 'Scénario public en lecture seule' };
  return null;
}

router.put('/scenarios/:id', requireElevated, async (req, res) => {
  try {
    const guard = await assertCustomScenario(req.params.id);
    if (guard) return res.status(guard.code).json({ error: guard.error });
    const { title, description, tags } = req.body;
    const fields = [], vals = []; let pi = 1;
    if (title !== undefined) { if (!title?.trim()) return res.status(400).json({ error: 'title invalide' }); fields.push(`title=$${pi++}`); vals.push(title.trim()); }
    if (description !== undefined) { fields.push(`description=$${pi++}`); vals.push(description); }
    if (tags !== undefined) { fields.push(`tags=$${pi++}`); vals.push(Array.isArray(tags) ? tags : []); }
    if (!fields.length) return res.status(400).json({ error: 'Aucun champ' });
    fields.push('updated_at=NOW()'); vals.push(req.params.id);
    const r = await pool.query(`UPDATE dfiq_scenarios SET ${fields.join(', ')} WHERE id=$${pi} RETURNING *`, vals);
    res.json(r.rows[0]);
  } catch { res.status(500).json({ error: 'Erreur mise à jour scénario' }); }
});

router.delete('/scenarios/:id', requireElevated, async (req, res) => {
  try {
    const guard = await assertCustomScenario(req.params.id);
    if (guard) return res.status(guard.code).json({ error: guard.error });
    await pool.query('DELETE FROM dfiq_scenarios WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Erreur suppression scénario' }); }
});

// add a custom question to a custom scenario
router.post('/scenarios/:id/questions', requireElevated, async (req, res) => {
  try {
    const guard = await assertCustomScenario(req.params.id);
    if (guard) return res.status(guard.code).json({ error: guard.error });
    const { text, facet_name = null } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'text requis' });
    const pos = await pool.query('SELECT COALESCE(MAX(position),-1)+1 AS p FROM dfiq_questions WHERE scenario_id=$1', [req.params.id]);
    const r = await pool.query(
      `INSERT INTO dfiq_questions (scenario_id, facet_name, text, position, is_custom)
       VALUES ($1,$2,$3,$4,TRUE) RETURNING *`, [req.params.id, facet_name, text.trim(), pos.rows[0].p]);
    res.status(201).json(r.rows[0]);
  } catch { res.status(500).json({ error: 'Erreur création question' }); }
});

router.put('/questions/:id', requireElevated, async (req, res) => {
  try {
    const chk = await pool.query('SELECT is_custom FROM dfiq_questions WHERE id=$1', [req.params.id]);
    if (!chk.rows.length) return res.status(404).json({ error: 'Question introuvable' });
    if (!chk.rows[0].is_custom) return res.status(403).json({ error: 'Question publique en lecture seule' });
    const { text, facet_name } = req.body;
    const fields = [], vals = []; let pi = 1;
    if (text !== undefined) { if (!text?.trim()) return res.status(400).json({ error: 'text invalide' }); fields.push(`text=$${pi++}`); vals.push(text.trim()); }
    if (facet_name !== undefined) { fields.push(`facet_name=$${pi++}`); vals.push(facet_name); }
    if (!fields.length) return res.status(400).json({ error: 'Aucun champ' });
    vals.push(req.params.id);
    const r = await pool.query(`UPDATE dfiq_questions SET ${fields.join(', ')} WHERE id=$${pi} RETURNING *`, vals);
    res.json(r.rows[0]);
  } catch { res.status(500).json({ error: 'Erreur mise à jour question' }); }
});

router.delete('/questions/:id', requireElevated, async (req, res) => {
  try {
    const chk = await pool.query('SELECT is_custom FROM dfiq_questions WHERE id=$1', [req.params.id]);
    if (!chk.rows.length) return res.status(404).json({ error: 'Question introuvable' });
    if (!chk.rows[0].is_custom) return res.status(403).json({ error: 'Question publique en lecture seule' });
    await pool.query('DELETE FROM dfiq_questions WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Erreur suppression question' }); }
});

module.exports = router;
