
const { Router } = require('express');
const logger = require('../config/logger').default;
const { authenticate } = require('../middleware/auth');

const router = Router();

const SELECT_PIN = `
  SELECT tp.id, tp.case_id, tp.author_id, u.username AS author_name,
         tp.evidence_id, tp.event_ts, tp.artifact_type,
         tp.description, tp.source, tp.raw_data, tp.note, tp.created_at,
         tp.is_global, tp.promoted_by, tp.promoted_at,
         pu.username AS promoted_by_name
  FROM timeline_pins tp
  JOIN users u  ON u.id  = tp.author_id
  LEFT JOIN users pu ON pu.id = tp.promoted_by
`;

router.get('/:caseId', authenticate, async (req, res) => {
  const { pool } = req.app.locals;
  const { caseId } = req.params;
  try {
    const { rows } = await pool.query(
      `${SELECT_PIN} WHERE tp.case_id = $1 ORDER BY tp.is_global DESC, tp.created_at DESC`,
      [caseId]
    );
    res.json({ pins: rows });
  } catch (err) {
    logger.error('[timeline-pins] GET:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/:caseId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId } = req.params;
  const { event_ts, artifact_type, description, source, raw_data, note, evidence_id } = req.body;

  try {
    const { rows } = await pool.query(
      `INSERT INTO timeline_pins
         (case_id, author_id, evidence_id, event_ts, artifact_type, description, source, raw_data, note)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (case_id, author_id, event_ts, source) DO NOTHING
       RETURNING id`,
      [caseId, req.user.id, evidence_id || null, event_ts || null, artifact_type || null,
       description || null, source || null, raw_data ? JSON.stringify(raw_data) : null, note || null]
    );

    if (!rows.length) {
      return res.status(409).json({ error: 'Pin already exists' });
    }

    const { rows: full } = await pool.query(
      `${SELECT_PIN} WHERE tp.id = $1`,
      [rows[0].id]
    );

    const pin = full[0];
    if (io) io.to(`case:${caseId}`).emit('timeline:pin:added', pin);

    res.status(201).json({ pin });
  } catch (err) {
    logger.error('[timeline-pins] POST:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.patch('/:caseId/:pinId/promote', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId, pinId } = req.params;

  try {

    const check = await pool.query(
      `SELECT id, is_global FROM timeline_pins WHERE id = $1 AND case_id = $2`,
      [pinId, caseId]
    );
    if (!check.rows.length) return res.status(404).json({ error: 'Pin not found' });

    const nowGlobal = !check.rows[0].is_global;
    await pool.query(
      `UPDATE timeline_pins
       SET is_global = $1,
           promoted_by = CASE WHEN $1 THEN $2::uuid ELSE NULL END,
           promoted_at = CASE WHEN $1 THEN NOW() ELSE NULL END
       WHERE id = $3`,
      [nowGlobal, req.user.id, pinId]
    );

    const { rows: full } = await pool.query(
      `${SELECT_PIN} WHERE tp.id = $1`,
      [pinId]
    );

    const pin = full[0];
    if (io) io.to(`case:${caseId}`).emit('timeline:pin:promoted', pin);

    res.json({ pin });
  } catch (err) {
    logger.error('[timeline-pins] PATCH promote:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.delete('/:caseId/:pinId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId, pinId } = req.params;

  try {
    const { rowCount } = await pool.query(
      `DELETE FROM timeline_pins
       WHERE id = $1 AND case_id = $2 AND author_id = $3`,
      [pinId, caseId, req.user.id]
    );

    if (!rowCount) {
      return res.status(404).json({ error: 'Pin not found or not owned by you' });
    }

    if (io) io.to(`case:${caseId}`).emit('timeline:pin:removed', { id: pinId, case_id: caseId });

    res.json({ deleted: true });
  } catch (err) {
    logger.error('[timeline-pins] DELETE:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
