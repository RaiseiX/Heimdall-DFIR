// Case-level access control (RBAC). Analysts only see cases they are involved in
// (investigator, creator, or explicitly assigned). Elevated roles (admin, team
// lead) see every case. Enforced as an Express param middleware so it covers every
// route carrying the case-id param without annotating each one.
const { pool } = require('../config/database');

const ELEVATED = new Set(['admin', 'team_lead']);

async function canAccessCase(user, caseId, queryable = pool) {
  if (!user || !caseId) return false;
  if (ELEVATED.has(user.role)) return true;
  const r = await queryable.query(
    `SELECT 1 FROM cases c
      WHERE c.id = $1
        AND ( c.investigator_id = $2
              OR c.created_by = $2
              OR EXISTS (SELECT 1 FROM case_assignees ca WHERE ca.case_id = c.id AND ca.user_id = $2) )
      LIMIT 1`,
    [caseId, user.id]
  );
  return r.rowCount > 0;
}

// Express param middleware — use via router.param('id'|'caseId', caseAccessParam).
function caseAccessParam(req, res, next, value) {
  canAccessCase(req.user, value)
    .then((ok) => (ok ? next() : res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' })))
    .catch(() => res.status(500).json({ error: "Erreur de contrôle d'accès." }));
}

// SQL fragment to restrict a cases listing for the given user.
// `alias` = the cases table alias; `nextIdx` = next positional parameter number.
// Returns { sql, params } — params is [] for elevated roles (no restriction).
function caseListFilter(user, alias = 'c', nextIdx = 1) {
  if (!user) return { sql: ' AND FALSE', params: [] };
  if (ELEVATED.has(user.role)) return { sql: '', params: [] };
  const p = `$${nextIdx}`;
  return {
    sql: ` AND ( ${alias}.investigator_id = ${p} OR ${alias}.created_by = ${p}
            OR EXISTS (SELECT 1 FROM case_assignees ca WHERE ca.case_id = ${alias}.id AND ca.user_id = ${p}) )`,
    params: [user.id],
  };
}

const TABLES_OBJET = Object.freeze({
  evidence: 'evidence',
  parser_result: 'parser_results',
  case_playbook: 'case_playbooks',
  chat_message: 'case_messages',
  report: 'reports',
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SOURCES_OBJET = Object.freeze(['params', 'query', 'body']);

async function resoudreDossierObjet(type, id, queryable = pool) {
  if (typeof type !== 'string' || !Object.prototype.hasOwnProperty.call(TABLES_OBJET, type)) return null;
  if (typeof id !== 'string' || !UUID_RE.test(id)) return null;
  const r = await queryable.query(`SELECT case_id FROM ${TABLES_OBJET[type]} WHERE id = $1`, [id]);
  if (!r.rows || r.rows.length === 0) return null;
  const caseId = r.rows[0].case_id;
  return caseId ? String(caseId) : null;
}

function exigerAccesObjet(type, nomParam, { source = 'params' } = {}) {
  const lieu = SOURCES_OBJET.includes(source) ? source : 'params';
  return async function exigerAccesObjetMiddleware(req, res, next) {
    try {
      const id = req[lieu] ? req[lieu][nomParam] : undefined;
      const caseId = await resoudreDossierObjet(type, id);
      if (!caseId || !(await canAccessCase(req.user, caseId))) {
        return res.status(404).json({ error: 'Ressource introuvable' });
      }
      req.objetCaseId = caseId;
      return next();
    } catch (_err) {
      return res.status(500).json({ error: "Erreur de contrôle d'accès." });
    }
  };
}

async function objetDansDossier(type, id, caseId, queryable = pool) {
  if (typeof caseId !== 'string' || !UUID_RE.test(caseId)) return false;
  const resolu = await resoudreDossierObjet(type, id, queryable);
  return resolu !== null && resolu.toLowerCase() === caseId.toLowerCase();
}

module.exports = {
  canAccessCase,
  caseAccessParam,
  caseListFilter,
  ELEVATED,
  resoudreDossierObjet,
  exigerAccesObjet,
  objetDansDossier,
};
