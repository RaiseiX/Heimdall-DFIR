// Detection false-positive suppression ("tuning loop").
// An analyst marks a detection result as a false positive → a reusable exception
// is stored. Subsequent scans filter out matching results. Scope can be the case
// (case_id set) or global (case_id null); detection_type null = applies to all.
const { pool } = require('../config/database');
const logger = require('../config/logger').default;

pool.query(`
  CREATE TABLE IF NOT EXISTS detection_exceptions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id        UUID REFERENCES cases(id) ON DELETE CASCADE,   -- null = global
    detection_type TEXT,                                          -- null = all detections
    match_value    TEXT NOT NULL,
    reason         TEXT,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`).catch(e => logger.error('detection_exceptions DDL:', e.message));

// Active exceptions for a case = its own + global ones.
async function getExceptions(caseId) {
  try {
    const r = await pool.query(
      `SELECT id, case_id, detection_type, match_value, reason, created_at
       FROM detection_exceptions
       WHERE case_id IS NULL OR case_id = $1
       ORDER BY created_at DESC`,
      [caseId]
    );
    return r.rows;
  } catch (e) {
    logger.error('getExceptions:', e.message);
    return [];
  }
}

// Filter a flat array of result items. An item is suppressed when an applicable
// exception's match_value appears (case-insensitive) in the item's JSON.
function applyExceptions(items, exceptions, detectionType) {
  if (!Array.isArray(items) || !exceptions?.length) return items || [];
  const relevant = exceptions.filter(e => !e.detection_type || e.detection_type === detectionType);
  if (!relevant.length) return items;
  return items.filter(item => {
    const hay = JSON.stringify(item).toLowerCase();
    return !relevant.some(e => e.match_value && hay.includes(String(e.match_value).toLowerCase()));
  });
}

// Filter grouped detections ({ vectors:[{items,count}], total }), recompute counts.
function applyExceptionsGrouped(vectors, exceptions, detectionType) {
  const out = (vectors || []).map(v => {
    const items = applyExceptions(v.items || [], exceptions, detectionType);
    return { ...v, items, count: items.length };
  }).filter(v => v.count > 0);
  return { vectors: out, total: out.reduce((s, v) => s + v.count, 0) };
}

module.exports = { getExceptions, applyExceptions, applyExceptionsGrouped };
