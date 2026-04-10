const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

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
    const { technique_id, tactic, technique_name, sub_technique_name, confidence, notes } = req.body;
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
         (case_id, technique_id, tactic, technique_name, sub_technique_name, confidence, notes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        req.params.caseId,
        technique_id,
        tactic,
        technique_name,
        sub_technique_name || null,
        confidence || 'medium',
        notes || null,
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
    const { confidence, notes } = req.body;
    const result = await pool.query(
      `UPDATE case_mitre_techniques
       SET confidence = COALESCE($1, confidence),
           notes      = COALESCE($2, notes)
       WHERE id = $3 AND case_id = $4
       RETURNING *`,
      [confidence || null, notes !== undefined ? notes : null, req.params.id, req.params.caseId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Non trouvé' });
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
