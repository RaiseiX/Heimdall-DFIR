
const express  = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { canAccessCase, ELEVATED } = require('../middleware/caseAccess');

const logger = require('../config/logger').default;
const router = express.Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REGLE_INTROUVABLE = { error: 'Règle introuvable' };
const MAX_REORDER = 500;

const estUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

async function peutEcrireRegle(user, caseId) {
  if (caseId === null || caseId === undefined) return ELEVATED.has(user.role);
  return canAccessCase(user, caseId);
}

router.get('/', authenticate, async (req, res) => {
  try {
    const { case_id } = req.query;
    let rows;
    if (case_id && estUuid(case_id) && await canAccessCase(req.user, case_id)) {
      const r = await pool.query(
        `SELECT * FROM timeline_color_rules
          WHERE (case_id = $1 OR case_id IS NULL)
          ORDER BY priority ASC, created_at ASC`,
        [case_id]
      );
      rows = r.rows;
    } else {
      const r = await pool.query(
        `SELECT * FROM timeline_color_rules
          WHERE case_id IS NULL
          ORDER BY priority ASC, created_at ASC`
      );
      rows = r.rows;
    }
    res.json({ rules: rows });
  } catch (err) {
    logger.error('[timeline-rules] GET error:', err.message);
    res.status(500).json({ error: 'Erreur récupération des règles' });
  }
});

router.post('/', authenticate, async (req, res) => {
  try {
    const { name, case_id, color, icon, scope = 'case', conditions, priority = 10, is_active = true } = req.body;
    if (!name?.trim())  return res.status(400).json({ error: 'name requis' });
    if (!color?.match(/^#[0-9a-fA-F]{6}$/)) return res.status(400).json({ error: 'color doit être un hex valide (#rrggbb)' });
    if (!conditions?.rules?.length) return res.status(400).json({ error: 'conditions.rules ne peut pas être vide' });

    const cibleId = case_id || null;
    if (cibleId !== null) {
      if (!estUuid(cibleId) || !(await canAccessCase(req.user, cibleId))) return res.status(404).json({ error: 'Ressource introuvable' });
    } else if (!ELEVATED.has(req.user.role)) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }

    const r = await pool.query(
      `INSERT INTO timeline_color_rules (name, case_id, author_id, color, icon, scope, conditions, priority, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [name.trim(), cibleId, req.user.id, color, icon || null, scope, JSON.stringify(conditions), priority, is_active]
    );
    res.status(201).json({ rule: r.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Une règle avec ce nom existe déjà pour ce cas' });
    logger.error('[timeline-rules] POST error:', err.message);
    res.status(500).json({ error: 'Erreur création de la règle' });
  }
});

router.put('/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, color, icon, scope, conditions, priority, is_active, case_id } = req.body;

    if (!estUuid(id)) return res.status(404).json(REGLE_INTROUVABLE);
    const existante = await pool.query('SELECT id, case_id FROM timeline_color_rules WHERE id = $1', [id]);
    if (!existante.rows.length) return res.status(404).json(REGLE_INTROUVABLE);
    const caseIdActuel = existante.rows[0].case_id ?? null;
    if (!(await peutEcrireRegle(req.user, caseIdActuel))) return res.status(404).json(REGLE_INTROUVABLE);
    if (case_id !== undefined) {
      const nouveau = case_id || null;
      if (nouveau === null) {
        if (!ELEVATED.has(req.user.role)) return res.status(403).json({ error: 'Accès non autorisé' });
      } else if (!estUuid(nouveau) || !(await canAccessCase(req.user, nouveau))) {
        return res.status(404).json(REGLE_INTROUVABLE);
      }
    }

    const fields = [];
    const vals   = [];
    let   pi     = 1;
    if (name       !== undefined) { fields.push(`name = $${pi++}`);       vals.push(name.trim()); }
    if (color      !== undefined) { fields.push(`color = $${pi++}`);      vals.push(color); }
    if (icon       !== undefined) { fields.push(`icon = $${pi++}`);       vals.push(icon); }
    if (scope      !== undefined) { fields.push(`scope = $${pi++}`);      vals.push(scope); }
    if (conditions !== undefined) { fields.push(`conditions = $${pi++}`); vals.push(JSON.stringify(conditions)); }
    if (priority   !== undefined) { fields.push(`priority = $${pi++}`);   vals.push(priority); }
    if (is_active  !== undefined) { fields.push(`is_active = $${pi++}`);  vals.push(is_active); }
    if (case_id    !== undefined) { fields.push(`case_id = $${pi++}`);    vals.push(case_id || null); }
    fields.push(`updated_at = NOW()`);

    if (fields.length === 1) return res.status(400).json({ error: 'Aucun champ à mettre à jour' });

    vals.push(id, caseIdActuel);
    const r = await pool.query(
      `UPDATE timeline_color_rules SET ${fields.join(', ')} WHERE id = $${pi} AND case_id IS NOT DISTINCT FROM $${pi + 1} RETURNING *`,
      vals
    );
    if (!r.rows.length) return res.status(404).json(REGLE_INTROUVABLE);
    res.json({ rule: r.rows[0] });
  } catch (err) {
    logger.error('[timeline-rules] PUT error:', err.message);
    res.status(500).json({ error: 'Erreur mise à jour de la règle' });
  }
});

router.patch('/reorder', authenticate, async (req, res) => {
  try {
    const { updates } = req.body;
    if (!Array.isArray(updates) || !updates.length) return res.status(400).json({ error: 'updates requis' });

    if (updates.length > MAX_REORDER) return res.status(400).json({ error: 'updates trop volumineux' });
    const ids = [];
    const priorities = [];
    for (const u of updates) {
      if (!u || !estUuid(u.id) || !Number.isInteger(u.priority) || u.priority < -32768 || u.priority > 32767) {
        return res.status(400).json({ error: 'updates invalide' });
      }
      ids.push(u.id);
      priorities.push(u.priority);
    }
    if (new Set(ids.map((i) => i.toLowerCase())).size !== ids.length) return res.status(400).json({ error: 'updates invalide' });

    const trouvees = await pool.query('SELECT id, case_id FROM timeline_color_rules WHERE id = ANY($1::uuid[])', [ids]);
    if (trouvees.rows.length !== ids.length) return res.status(404).json(REGLE_INTROUVABLE);
    for (const row of trouvees.rows) {
      if (!(await peutEcrireRegle(req.user, row.case_id ?? null))) return res.status(404).json(REGLE_INTROUVABLE);
    }

    await pool.query(
      `UPDATE timeline_color_rules t SET priority = v.priority, updated_at = NOW()
         FROM (SELECT unnest($1::uuid[]) AS id, unnest($2::int[]) AS priority) v
        WHERE t.id = v.id`,
      [ids, priorities]
    );
    res.json({ updated: updates.length });
  } catch (err) {
    logger.error('[timeline-rules] PATCH reorder error:', err.message);
    res.status(500).json({ error: 'Erreur réordonnancement' });
  }
});

router.delete('/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    if (!estUuid(id)) return res.status(404).json(REGLE_INTROUVABLE);
    const existante = await pool.query('SELECT id, case_id FROM timeline_color_rules WHERE id = $1', [id]);
    if (!existante.rows.length) return res.status(404).json(REGLE_INTROUVABLE);
    const caseIdActuel = existante.rows[0].case_id ?? null;
    if (!(await peutEcrireRegle(req.user, caseIdActuel))) return res.status(404).json(REGLE_INTROUVABLE);
    const r = await pool.query(
      'DELETE FROM timeline_color_rules WHERE id = $1 AND case_id IS NOT DISTINCT FROM $2 RETURNING id',
      [id, caseIdActuel]
    );
    if (!r.rows.length) return res.status(404).json(REGLE_INTROUVABLE);
    res.json({ deleted: r.rows[0].id });
  } catch (err) {
    logger.error('[timeline-rules] DELETE error:', err.message);
    res.status(500).json({ error: 'Erreur suppression' });
  }
});

module.exports = router;
