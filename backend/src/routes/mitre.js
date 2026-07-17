const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { caseAccessParam } = require('../middleware/caseAccess');

const logger = require('../config/logger').default;
const router = express.Router();
router.use(authenticate);
router.param('caseId', caseAccessParam);

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM case_mitre_techniques
       WHERE case_id = $1
       ORDER BY tactic, technique_id`,
      [req.params.caseId]
    );
    res.json(result.rows);
  } catch (err) {
    logger.error('MITRE GET error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId', authenticate, async (req, res) => {
  try {
    const { technique_id, tactic, technique_name, sub_technique_name, confidence, notes, significance, links_to } = req.body;
    if (!technique_id || !tactic || !technique_name) {
      return res.status(400).json({ error: 'technique_id, tactic, technique_name requis' });
    }

    const dup = await pool.query(
      'SELECT id FROM case_mitre_techniques WHERE case_id = $1 AND technique_id = $2',
      [req.params.caseId, technique_id]
    );
    if (dup.rows.length > 0) {
      return res.status(409).json({ error: 'Technique déjà mappée à ce cas' });
    }

    const result = await pool.query(
      `INSERT INTO case_mitre_techniques
         (case_id, technique_id, tactic, technique_name, sub_technique_name, confidence, notes, significance, links_to, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        req.params.caseId,
        technique_id,
        tactic,
        technique_name,
        sub_technique_name || null,
        confidence || 'medium',
        notes || null,
        significance || null,
        links_to || null,
        req.user.id,
      ]
    );

    await auditLog(
      req.user.id, 'add_mitre_technique', 'case', req.params.caseId,
      { technique_id, technique_name }, req.ip
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('MITRE POST error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.patch('/:caseId/:id', authenticate, async (req, res) => {
  try {
    // PATCH semantics: only update the keys actually present in the body, so
    // an explicit null/'' clears the field (COALESCE would silently keep it).
    const has = (k) => Object.prototype.hasOwnProperty.call(req.body, k);
    const sets = [];
    const vals = [];
    for (const k of ['confidence', 'notes', 'significance', 'links_to']) {
      if (has(k)) { vals.push(req.body[k] === '' ? null : req.body[k]); sets.push(`${k} = $${vals.length}`); }
    }
    if (!sets.length) return res.status(400).json({ error: 'Aucun champ à mettre à jour' });
    vals.push(req.params.id, req.params.caseId);
    const result = await pool.query(
      `UPDATE case_mitre_techniques SET ${sets.join(', ')}
       WHERE id = $${vals.length - 1} AND case_id = $${vals.length}
       RETURNING *`,
      vals
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Non trouvé' });
    const { confidence, notes } = req.body;
    await auditLog(req.user.id, 'update_mitre_technique', 'case', req.params.caseId,
      { technique_entry_id: req.params.id, confidence, notes }, req.ip);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:caseId/:id', authenticate, async (req, res) => {
  try {
    const deleted = await pool.query(
      'DELETE FROM case_mitre_techniques WHERE id = $1 AND case_id = $2 RETURNING technique_id, technique_name',
      [req.params.id, req.params.caseId]
    );
    if (deleted.rows.length > 0) {
      await auditLog(req.user.id, 'delete_mitre_technique', 'case', req.params.caseId,
        { technique_id: deleted.rows[0].technique_id, technique_name: deleted.rows[0].technique_name }, req.ip);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
