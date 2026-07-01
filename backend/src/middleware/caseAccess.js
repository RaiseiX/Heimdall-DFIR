// Case-level access control (RBAC). Analysts only see cases they are involved in
// (investigator, creator, or explicitly assigned). Elevated roles (admin, team
// lead) see every case. Enforced as an Express param middleware so it covers every
// route carrying the case-id param without annotating each one.
const { pool } = require('../config/database');

const ELEVATED = new Set(['admin', 'team_lead']);

async function canAccessCase(user, caseId) {
  if (!user || !caseId) return false;
  if (ELEVATED.has(user.role)) return true;
  const r = await pool.query(
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
  if (!user || ELEVATED.has(user.role)) return { sql: '', params: [] };
  const p = `$${nextIdx}`;
  return {
    sql: ` AND ( ${alias}.investigator_id = ${p} OR ${alias}.created_by = ${p}
            OR EXISTS (SELECT 1 FROM case_assignees ca WHERE ca.case_id = ${alias}.id AND ca.user_id = ${p}) )`,
    params: [user.id],
  };
}

module.exports = { canAccessCase, caseAccessParam, caseListFilter, ELEVATED };
