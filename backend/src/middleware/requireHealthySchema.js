const { isDegraded, getDegradations } = require('../services/schemaState');

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Mounted on the ingestion/parsing routes. Reads keep working on a degraded
// schema — the rows already in the database stay consultable — but anything
// that would write is refused with the real reason rather than silently
// producing an empty collection.
module.exports = function requireHealthySchema(req, res, next) {
  if (READ_METHODS.has(req.method)) return next();
  if (!isDegraded()) return next();

  return res.status(503).json({
    error: 'Schéma de base de données incomplet — écritures suspendues',
    degradations: getDegradations(),
  });
};
