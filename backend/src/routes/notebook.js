'use strict';
// Le carnet d'enquete — un bloc Markdown persistant par dossier.
//
// La table se cree paresseusement a la premiere lecture. Sa definition vivait
// ici et declarait `case_id INTEGER` contre un `cases.id` en uuid : elle ne
// pouvait pas etre creee, la route levait a chaque appel, et le carnet n'a
// jamais rien enregistre depuis la creation du produit (zero entree
// `save_notebook` dans `audit_log`, mesure du 2026-09-17).
//
// Le SQL vit desormais dans `services/notebookStore.ts`, ou il est teste contre
// un vrai Postgres — y compris les ajouts concurrents.
const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const logger = require('../config/logger').default;
const {
  ensureNotebookTableSql,
  appendNotebookSql,
  saveNotebookSql,
  getNotebookSql,
  NOTEBOOK_MAX,
} = require('../services/notebookStore');
const router = express.Router();

let _ready = false;
async function ensureTable() {
  if (_ready) return;
  await pool.query(ensureNotebookTableSql());
  _ready = true;
}

router.get('/:id', authenticate, async (req, res) => {
  try {
    await ensureTable();
    const r = await pool.query(getNotebookSql(), [req.params.id]);
    res.json(r.rows[0] || { content: '', updated_at: null, updated_by_name: null });
  } catch (err) {
    logger.error('[notebook] get error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/:id', authenticate, async (req, res) => {
  try {
    await ensureTable();
    const content = String(req.body.content ?? '');
    const r = await pool.query(saveNotebookSql(), [req.params.id, content, req.user.id]);
    Promise.resolve(auditLog(req.user.id, 'save_notebook', 'case', req.params.id,
      { chars: Math.min(content.length, NOTEBOOK_MAX) }, req.ip)).catch(() => {});
    res.json({ saved: true, updated_at: r.rows[0].updated_at });
  } catch (err) {
    logger.error('[notebook] put error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// L'ajout depuis un onglet d'analyse. Separe du PUT parce qu'il ne relit pas le
// carnet : deux onglets qui deposent une trouvaille en meme temps conservent
// les deux, la ou un lire-modifier-ecrire en perdrait une.
router.post('/:id/append', authenticate, async (req, res) => {
  try {
    const bloc = String(req.body.content ?? '').trim();
    if (!bloc) return res.status(400).json({ error: 'contenu requis' });
    await ensureTable();
    const r = await pool.query(appendNotebookSql(), [req.params.id, bloc, req.user.id]);
    Promise.resolve(auditLog(req.user.id, 'append_notebook', 'case', req.params.id,
      { chars: bloc.length }, req.ip)).catch(() => {});
    res.json({ appended: true, updated_at: r.rows[0].updated_at });
  } catch (err) {
    logger.error('[notebook] append error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
