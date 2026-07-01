'use strict';
// Analyst notebook — one persistent markdown scratchpad per case.
// Table is created lazily on first access (no migration needed).
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const logger = require('../config/logger').default;
const router = express.Router();

let _ready = false;
async function ensureTable() {
  if (_ready) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS case_notebooks (
      case_id    INTEGER PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
      content    TEXT    NOT NULL DEFAULT '',
      updated_by UUID    REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  _ready = true;
}

// GET /api/cases/:id/notebook
router.get('/:id', authenticate, async (req, res) => {
  try {
    await ensureTable();
    const r = await pool.query(
      `SELECT n.content, n.updated_at, u.full_name AS updated_by_name
         FROM case_notebooks n
         LEFT JOIN users u ON u.id = n.updated_by
        WHERE n.case_id = $1`,
      [req.params.id],
    );
    res.json(r.rows[0] || { content: '', updated_at: null, updated_by_name: null });
  } catch (err) {
    logger.error('[notebook] get error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// PUT /api/cases/:id/notebook
router.put('/:id', authenticate, async (req, res) => {
  try {
    await ensureTable();
    const content = String(req.body.content ?? '').slice(0, 200_000);
    const r = await pool.query(
      `INSERT INTO case_notebooks (case_id, content, updated_by, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (case_id) DO UPDATE
         SET content = EXCLUDED.content,
             updated_by = EXCLUDED.updated_by,
             updated_at = NOW()
       RETURNING updated_at`,
      [req.params.id, content, req.user.id],
    );
    Promise.resolve(auditLog(req.user.id, 'save_notebook', 'case', req.params.id, { chars: content.length }, req.ip)).catch(() => {});
    res.json({ saved: true, updated_at: r.rows[0].updated_at });
  } catch (err) {
    logger.error('[notebook] put error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
