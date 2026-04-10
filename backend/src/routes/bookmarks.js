const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const router = express.Router({ mergeParams: true });

router.get('/', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await pool.query(
      `SELECT b.id, b.case_id, b.artifact_ref, b.event_timestamp, b.title, b.description,
              b.mitre_technique, b.mitre_tactic, b.color, b.author_id, b.created_at,
              u.full_name as author_name, u.username,
              'bookmark' as source
       FROM timeline_bookmarks b
       LEFT JOIN users u ON b.author_id = u.id
       WHERE b.case_id = $1

       UNION ALL

       SELECT m.id, m.case_id, NULL as artifact_ref, NULL as event_timestamp,
              m.technique_name as title,
              COALESCE(m.notes, m.sub_technique_name) as description,
              m.technique_id as mitre_technique,
              CASE m.tactic
                WHEN 'TA0043' THEN 'Reconnaissance'
                WHEN 'TA0042' THEN 'Resource Development'
                WHEN 'TA0001' THEN 'Initial Access'
                WHEN 'TA0002' THEN 'Execution'
                WHEN 'TA0003' THEN 'Persistence'
                WHEN 'TA0004' THEN 'Privilege Escalation'
                WHEN 'TA0005' THEN 'Defense Evasion'
                WHEN 'TA0006' THEN 'Credential Access'
                WHEN 'TA0007' THEN 'Discovery'
                WHEN 'TA0008' THEN 'Lateral Movement'
                WHEN 'TA0009' THEN 'Collection'
                WHEN 'TA0011' THEN 'Command and Control'
                WHEN 'TA0010' THEN 'Exfiltration'
                WHEN 'TA0040' THEN 'Impact'
                ELSE m.tactic
              END as mitre_tactic,
              '#8b72d6' as color,
              m.created_by as author_id, m.created_at,
              u.full_name as author_name, u.username,
              'mitre' as source
       FROM case_mitre_techniques m
       LEFT JOIN users u ON m.created_by = u.id
       WHERE m.case_id = $1

       ORDER BY event_timestamp ASC NULLS LAST, created_at ASC`,
      [caseId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur chargement bookmarks' });
  }
});

router.post('/', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { artifact_ref, event_timestamp, title, description, mitre_technique, mitre_tactic, color } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Titre requis' });

    const result = await pool.query(
      `INSERT INTO timeline_bookmarks
         (case_id, artifact_ref, event_timestamp, title, description, mitre_technique, mitre_tactic, color, author_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [caseId, artifact_ref || null, event_timestamp || null,
       title.trim(), description || null, mitre_technique || null,
       mitre_tactic || null, color || '#4d82c0', req.user.id]
    );

    await auditLog(req.user.id, 'create_bookmark', 'bookmark', result.rows[0].id,
      { title, mitre_tactic }, req.ip);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur création bookmark' });
  }
});

router.put('/:id', authenticate, async (req, res) => {
  try {
    const { id, caseId } = req.params;
    const { title, description, mitre_technique, mitre_tactic, color } = req.body;

    const result = await pool.query(
      `UPDATE timeline_bookmarks SET
         title=$1, description=$2, mitre_technique=$3, mitre_tactic=$4, color=$5, updated_at=NOW()
       WHERE id=$6 AND case_id=$7 RETURNING *`,
      [title, description || null, mitre_technique || null, mitre_tactic || null,
       color || '#4d82c0', id, caseId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Bookmark non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur mise à jour bookmark' });
  }
});

router.delete('/:id', authenticate, async (req, res) => {
  try {
    const { id, caseId } = req.params;
    await pool.query('DELETE FROM timeline_bookmarks WHERE id=$1 AND case_id=$2', [id, caseId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur suppression bookmark' });
  }
});

module.exports = router;
