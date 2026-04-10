const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

const MAX_LIMIT = 2000;
const DEFAULT_LIMIT = 200;

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const { type, source } = req.query;
    const limit  = Math.min(Math.max(1, parseInt(req.query.limit)  || DEFAULT_LIMIT), MAX_LIMIT);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);

    const params = [req.params.caseId];
    let idx = 2;
    let where = 'WHERE case_id = $1';

    if (type)   { where += ` AND event_type = $${idx++}`;          params.push(type); }
    if (source) { where += ` AND source ILIKE $${idx++}`;          params.push(`%${source}%`); }

    const [dataResult, countResult] = await Promise.all([
      pool.query(
        `SELECT * FROM timeline_events ${where} ORDER BY event_time ASC LIMIT $${idx++} OFFSET $${idx++}`,
        [...params, limit, offset]
      ),
      pool.query(`SELECT COUNT(*)::int AS total FROM timeline_events ${where}`, params),
    ]);

    res.json({
      rows:   dataResult.rows,
      total:  countResult.rows[0].total,
      limit,
      offset,
    });
  } catch (err) {
    logger.error('[timeline] GET error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId', authenticate, async (req, res) => {
  try {
    const { event_time, event_type, title, description, source, evidence_id } = req.body;
    const result = await pool.query(
      `INSERT INTO timeline_events (case_id, event_time, event_type, title, description, source, evidence_id, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.params.caseId, event_time, event_type, title, description, source, evidence_id, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('[timeline] POST error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
