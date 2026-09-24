const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { canAccessCase, ELEVATED } = require('../middleware/caseAccess');

const router = express.Router({ mergeParams: true });

// Auth + case-access on every route. bookmarks/investigation omit the case guard;
// we add it explicitly here (targeted hardening — see spec Sécurité). Note: a
// child router's router.param() does NOT fire for :caseId inherited from the parent
// mount via mergeParams, so the guard is applied as ordinary middleware.
router.use(authenticate);
router.use(async (req, res, next) => {
  try {
    if (await canAccessCase(req.user, req.params.caseId)) return next();
    return res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' });
  } catch {
    return res.status(500).json({ error: "Erreur de contrôle d'accès." });
  }
});

// Only these keys survive into the persisted `query` blob. Everything else is dropped.
const QUERY_WHITELIST = new Set([
  'search', 'searchOp', 'startTime', 'endTime', 'artifactTypes',
  'hostFilter', 'hostFilterOp', 'userFilter', 'userFilterOp',
  'toolFilter', 'toolFilterOp', 'extFilter', 'extFilterOp',
  'eventIdFilter', 'tagFilter', 'hitsOnly', 'detSeverity', 'dedupe',
  'multiSort', 'groupByFields',
]);
const MAX_QUERY_BYTES = 16 * 1024;

function sanitizeQuery(raw) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const k of Object.keys(raw)) if (QUERY_WHITELIST.has(k)) out[k] = raw[k];
  return out;
}

// Returns { json } or { error } — centralises name/scope/query validation.
function validateWrite({ name, scope, query }, { nameRequired }) {
  if (name !== undefined || nameRequired) {
    if (!name?.trim() || name.trim().length > 120) return { error: 'name requis (1–120 caractères)' };
  }
  if (scope !== undefined && !['personal', 'case'].includes(scope)) {
    return { error: "scope doit être 'personal' ou 'case'" };
  }
  if (query !== undefined || nameRequired) {
    const clean = sanitizeQuery(query ?? {});
    const json = JSON.stringify(clean);
    if (Buffer.byteLength(json) > MAX_QUERY_BYTES) return { error: 'query trop volumineuse (max 16 Ko)' };
    return { json };
  }
  return {};
}

// GET / — my personal searches + all case-shared searches of this case.
router.get('/', async (req, res) => {
  try {
    const { caseId } = req.params;
    const r = await pool.query(
      `SELECT s.*, u.full_name AS author_name, u.username
         FROM timeline_saved_searches s
         LEFT JOIN users u ON u.id = s.author_id
        WHERE s.case_id = $1 AND (s.author_id = $2 OR s.scope = 'case')
        ORDER BY s.name ASC`,
      [caseId, req.user.id]
    );
    res.json(r.rows);
  } catch {
    res.status(500).json({ error: 'Erreur chargement recherches' });
  }
});

// POST / — create (author = requester, case from route).
router.post('/', async (req, res) => {
  try {
    const { caseId } = req.params;
    const { name, scope = 'personal', query = {} } = req.body;
    const v = validateWrite({ name, scope, query }, { nameRequired: true });
    if (v.error) return res.status(400).json({ error: v.error });

    const r = await pool.query(
      `INSERT INTO timeline_saved_searches (case_id, author_id, name, scope, query)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [caseId, req.user.id, name.trim(), scope, v.json]
    );
    await auditLog(req.user.id, 'create_saved_search', 'saved_search', r.rows[0].id,
      { name: name.trim(), scope }, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Une recherche avec ce nom existe déjà' });
    res.status(500).json({ error: 'Erreur création recherche' });
  }
});

// PUT /:id — edit / promote. Author only.
router.put('/:id', async (req, res) => {
  try {
    const { id, caseId } = req.params;
    const owner = await pool.query(
      'SELECT author_id FROM timeline_saved_searches WHERE id = $1 AND case_id = $2',
      [id, caseId]
    );
    if (!owner.rows.length) return res.status(404).json({ error: 'Recherche introuvable' });
    if (owner.rows[0].author_id !== req.user.id) {
      return res.status(403).json({ error: "Seul l'auteur peut modifier cette recherche" });
    }

    const { name, scope, query } = req.body;
    const v = validateWrite({ name, scope, query }, { nameRequired: false });
    if (v.error) return res.status(400).json({ error: v.error });

    const fields = [];
    const vals = [];
    let pi = 1;
    if (name  !== undefined) { fields.push(`name = $${pi++}`);  vals.push(name.trim()); }
    if (scope !== undefined) { fields.push(`scope = $${pi++}`); vals.push(scope); }
    if (query !== undefined) { fields.push(`query = $${pi++}`); vals.push(v.json); }
    if (!fields.length) return res.status(400).json({ error: 'Aucun champ à mettre à jour' });
    fields.push('updated_at = NOW()');

    vals.push(id, caseId);
    const r = await pool.query(
      `UPDATE timeline_saved_searches SET ${fields.join(', ')} WHERE id = $${pi++} AND case_id = $${pi} RETURNING *`,
      vals
    );
    res.json(r.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Une recherche avec ce nom existe déjà' });
    res.status(500).json({ error: 'Erreur mise à jour recherche' });
  }
});

// DELETE /:id — author, or elevated role (admin/team_lead) for cleanup.
router.delete('/:id', async (req, res) => {
  try {
    const { id, caseId } = req.params;
    const owner = await pool.query(
      'SELECT author_id FROM timeline_saved_searches WHERE id = $1 AND case_id = $2',
      [id, caseId]
    );
    if (!owner.rows.length) return res.status(404).json({ error: 'Recherche introuvable' });
    const isOwner = owner.rows[0].author_id === req.user.id;
    if (!isOwner && !ELEVATED.has(req.user.role)) {
      return res.status(403).json({ error: 'Suppression non autorisée' });
    }
    await pool.query('DELETE FROM timeline_saved_searches WHERE id = $1 AND case_id = $2', [id, caseId]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Erreur suppression recherche' });
  }
});

module.exports = router;
