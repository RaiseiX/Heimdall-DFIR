
const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

const VALID_ARTIFACT_TYPES = [
  'evtx',
  'hayabusa',
  'prefetch',
  'mft',
  'lnk',
  'registry',
  'amcache',
  'srum',
  'shellbags',
  'jumplist',
  'bits',
  'recyclebin',
];

router.get('/', authenticate, async (req, res) => {
  try {
    const { artifact_type, case_id } = req.query;
    let query = 'SELECT * FROM user_artifact_column_prefs WHERE user_id = $1';
    const params = [req.user.id];
    let pi = 2;

    if (artifact_type) {
      if (!VALID_ARTIFACT_TYPES.includes(artifact_type)) {
        return res.status(400).json({ error: 'Invalid artifact_type' });
      }
      query += ` AND artifact_type = $${pi++}`;
      params.push(artifact_type);
    }

    if (case_id) {
      query += ` AND (case_id = $${pi++} OR case_id IS NULL)`;
      params.push(case_id);
    }

    query += ' ORDER BY artifact_type ASC, scope ASC';

    const r = await pool.query(query, params);
    res.json({ prefs: r.rows });
  } catch (err) {
    logger.error('[column-prefs] GET error:', err.message);
    res.status(500).json({ error: 'Erreur récupération des préférences' });
  }
});

router.put('/:artifact_type', authenticate, async (req, res) => {
  try {
    const { artifact_type } = req.params;
    const { prefs, scope = 'global', case_id } = req.body;

    if (!VALID_ARTIFACT_TYPES.includes(artifact_type)) {
      return res.status(400).json({ error: 'Invalid artifact_type' });
    }

    if (!['global', 'case'].includes(scope)) {
      return res.status(400).json({ error: 'scope must be "global" or "case"' });
    }

    if (scope === 'case' && !case_id) {
      return res.status(400).json({ error: 'case_id required for scope="case"' });
    }

    const finalCaseId = scope === 'global' ? null : case_id;

    const r = await pool.query(
      `INSERT INTO user_artifact_column_prefs (user_id, case_id, artifact_type, prefs, scope, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id, case_id, artifact_type, scope)
       DO UPDATE SET prefs = EXCLUDED.prefs, updated_at = NOW()
       RETURNING *`,
      [req.user.id, finalCaseId, artifact_type, JSON.stringify(prefs || {}), scope]
    );

    res.json({ pref: r.rows[0] });
  } catch (err) {
    logger.error('[column-prefs] PUT error:', err.message);
    res.status(500).json({ error: 'Erreur mise à jour des préférences' });
  }
});

router.delete('/:artifact_type', authenticate, async (req, res) => {
  try {
    const { artifact_type } = req.params;
    const { scope = 'global', case_id } = req.query;

    if (!VALID_ARTIFACT_TYPES.includes(artifact_type)) {
      return res.status(400).json({ error: 'Invalid artifact_type' });
    }

    if (!['global', 'case'].includes(scope)) {
      return res.status(400).json({ error: 'scope must be "global" or "case"' });
    }

    if (scope === 'case' && !case_id) {
      return res.status(400).json({ error: 'case_id required for scope="case"' });
    }

    const finalCaseId = scope === 'global' ? null : case_id;

    const r = await pool.query(
      `DELETE FROM user_artifact_column_prefs
       WHERE user_id = $1 AND artifact_type = $2 AND case_id IS NOT DISTINCT FROM $3 AND scope = $4
       RETURNING id`,
      [req.user.id, artifact_type, finalCaseId, scope]
    );

    if (!r.rows.length) {
      return res.status(404).json({ error: 'Préférence non trouvée' });
    }

    res.json({ deleted: r.rows[0].id });
  } catch (err) {
    logger.error('[column-prefs] DELETE error:', err.message);
    res.status(500).json({ error: 'Erreur suppression des préférences' });
  }
});

module.exports = router;
