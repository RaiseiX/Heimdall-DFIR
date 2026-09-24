const express = require('express');
const { pool } = require('../config/database');
const { authenticate, requireRole } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

pool.query(`
  CREATE TABLE IF NOT EXISTS feedback (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    type        VARCHAR(20) NOT NULL DEFAULT 'bug',
    title       VARCHAR(200),
    description TEXT NOT NULL,
    page_url    VARCHAR(500),
    status      VARCHAR(20) NOT NULL DEFAULT 'open',
    admin_reply TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`).catch(e => logger.warn('[feedback] table init:', e.message));

pool.query(`
  ALTER TABLE feedback
    ADD COLUMN IF NOT EXISTS status     VARCHAR(20) NOT NULL DEFAULT 'open',
    ADD COLUMN IF NOT EXISTS admin_reply TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
`).catch(e => logger.warn('[feedback] migration:', e.message));

router.post('/', authenticate, async (req, res) => {
  try {
    const { type = 'bug', title = '', description, page_url = '' } = req.body;
    if (!description?.trim()) return res.status(400).json({ error: 'Description requise' });

    await pool.query(
      `INSERT INTO feedback (user_id, type, title, description, page_url)
       VALUES ($1,$2,$3,$4,$5)`,
      [req.user.id, type.slice(0,20), title.slice(0,200), description.slice(0,2000), page_url.slice(0,500)]
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error('[feedback] POST error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/mine', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, type, title, description, status, admin_reply, created_at, updated_at
         FROM feedback
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    logger.error('[feedback] GET /mine error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { status } = req.query;
    const params = [];
    let where = '';
    if (status) {
      params.push(status);
      where = `WHERE f.status = $${params.length}`;
    }
    const result = await pool.query(
      `SELECT f.*, u.username, u.full_name
         FROM feedback f LEFT JOIN users u ON f.user_id = u.id
         ${where}
        ORDER BY f.created_at DESC LIMIT 200`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.patch('/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { status, admin_reply } = req.body;
    const result = await pool.query(
      `UPDATE feedback
          SET status = COALESCE($1, status),
              admin_reply = COALESCE($2, admin_reply),
              updated_at = NOW()
        WHERE id = $3
        RETURNING *`,
      [status || null, admin_reply !== undefined ? admin_reply : null, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('[feedback] PATCH error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
