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

// Detection result cache — detection engines are expensive SQL scans over the
// whole timeline; results are stored per (case_id, section) so a page reload
// serves the last run instead of re-scanning. ?refresh=1 forces a recompute and
// ingest invalidates the cache (see invalidateDetectionCache).
pool.query(`
  CREATE TABLE IF NOT EXISTS detection_cache (
    case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    section    TEXT NOT NULL,
    payload    JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, section)
  )
`).catch(e => logger.error('detection_cache DDL:', e.message));

// Drop cached detection results for a case — called whenever new timeline rows
// are ingested, so results reflect freshly parsed data.
async function invalidateDetectionCache(caseId) {
  try {
    await pool.query('DELETE FROM detection_cache WHERE case_id = $1', [caseId]);
  } catch (e) {
    logger.error('invalidateDetectionCache:', e.message);
  }
}

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
// Zero-hit vectors are kept so the UI can render the full rule list (coverage),
// not just the rules that fired.
function applyExceptionsGrouped(vectors, exceptions, detectionType) {
  const out = (vectors || []).map(v => {
    const items = applyExceptions(v.items || [], exceptions, detectionType);
    return { ...v, items, count: items.length };
  });
  return { vectors: out, total: out.reduce((s, v) => s + v.count, 0) };
}

module.exports = { getExceptions, applyExceptions, applyExceptionsGrouped, invalidateDetectionCache };
