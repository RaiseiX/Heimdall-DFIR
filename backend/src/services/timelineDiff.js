// Two-sided timeline diff: added/removed/unchanged between two {evidence_id?, host_name?}
// sides, matched on a per-event key (dedupe_hash, composite fallback). Pure + testable.

const DIFF_COLS = `id, timestamp, artifact_type, artifact_name, description, source,
  host_name, user_name, process_name, evidence_id`;

// content-derived identity; COALESCE keeps it non-null so NOT IN is NULL-safe.
// NOTE: the composite fallback deliberately EXCLUDES evidence_id/case_id — the whole point of the
// diff is to match identical events ACROSS two evidences (which have different evidence_ids), so
// keying on evidence_id would make every hashless row unique per side and nothing would ever be
// "unchanged". Residual v1 limitation: two genuinely-distinct hashless events sharing
// timestamp+type+host+description collapse to one key (rare; refine post-v1 with more fields, NOT evidence_id).
const MATCH_KEY = `COALESCE(dedupe_hash, md5(concat_ws('|', timestamp::text, artifact_type, host_name, description)))`;

// appends a side's filter params and returns the SQL fragment (may be '')
function sideFilter(side, params) {
  let sql = '';
  if (side && side.evidenceId) { params.push(side.evidenceId); sql += ` AND evidence_id = $${params.length}`; }
  if (side && side.hostName != null && side.hostName !== '') {
    params.push(side.hostName); sql += ` AND host_name IS NOT DISTINCT FROM $${params.length}`;
  }
  return sql;
}

async function diffTimelines(pool, caseId, sideA, sideB, { limit = 500 } = {}) {
  const cap = Math.min(2000, Math.max(1, parseInt(limit, 10) || 500));

  // counts (true totals) — one query, two key CTEs
  const cp = [caseId];
  const aF = sideFilter(sideA, cp);
  const bF = sideFilter(sideB, cp);
  const countsRes = await pool.query(
    `WITH a AS (SELECT DISTINCT ${MATCH_KEY} AS k FROM collection_timeline WHERE case_id = $1${aF}),
          b AS (SELECT DISTINCT ${MATCH_KEY} AS k FROM collection_timeline WHERE case_id = $1${bF})
     SELECT (SELECT COUNT(*) FROM b WHERE NOT EXISTS (SELECT 1 FROM a WHERE a.k = b.k))::int AS added,
            (SELECT COUNT(*) FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.k = a.k))::int AS removed,
            (SELECT COUNT(*) FROM a WHERE     EXISTS (SELECT 1 FROM b WHERE b.k = a.k))::int AS unchanged`,
    cp);
  const counts = countsRes.rows[0];

  // added rows (in B, not A)
  const ap = [caseId];
  const aF2 = sideFilter(sideA, ap);
  const bF2 = sideFilter(sideB, ap);
  const addedRes = await pool.query(
    `WITH a AS (SELECT DISTINCT ${MATCH_KEY} AS k FROM collection_timeline WHERE case_id = $1${aF2})
     SELECT ${DIFF_COLS} FROM collection_timeline
      WHERE case_id = $1${bF2} AND ${MATCH_KEY} NOT IN (SELECT k FROM a)
      ORDER BY timestamp, id LIMIT ${cap}`, ap);

  // removed rows (in A, not B)
  const rp = [caseId];
  const aF3 = sideFilter(sideA, rp);
  const bF3 = sideFilter(sideB, rp);
  const removedRes = await pool.query(
    `WITH b AS (SELECT DISTINCT ${MATCH_KEY} AS k FROM collection_timeline WHERE case_id = $1${bF3})
     SELECT ${DIFF_COLS} FROM collection_timeline
      WHERE case_id = $1${aF3} AND ${MATCH_KEY} NOT IN (SELECT k FROM b)
      ORDER BY timestamp, id LIMIT ${cap}`, rp);

  return {
    counts,
    added:   addedRes.rows.map(r => ({ ...r, diff_side: 'added' })),
    removed: removedRes.rows.map(r => ({ ...r, diff_side: 'removed' })),
  };
}

module.exports = { diffTimelines, DIFF_COLS, MATCH_KEY };
