// ±N chronological neighbors around an anchor event, ignoring active filters.
// Same host by default; all_hosts removes the host constraint. Keyset on (timestamp, id)
// for stable ordering across equal timestamps. Pure + testable against any pg pool.

const CONTEXT_COLS = `id, timestamp, artifact_type, artifact_name, description, source,
  host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic,
  tool, timestamp_kind, details, "path", ext, event_id, file_size, raw`;

class AnchorNotFound extends Error {}

async function fetchContext(pool, caseId, anchorId, { n = 25, allHosts = false } = {}) {
  const lim = Math.min(200, Math.max(1, parseInt(n, 10) || 25));

  const anchorRes = await pool.query(
    `SELECT id, timestamp, host_name FROM collection_timeline WHERE case_id = $1 AND id = $2`,
    [caseId, anchorId]);
  if (!anchorRes.rows.length) throw new AnchorNotFound();
  const a = anchorRes.rows[0];

  const hostClause = allHosts ? '' : ' AND host_name IS NOT DISTINCT FROM $4';
  const hp = allHosts ? [] : [a.host_name];

  const [before, after, anchorFull] = await Promise.all([
    pool.query(`SELECT ${CONTEXT_COLS} FROM collection_timeline
       WHERE case_id = $1 AND (timestamp, id) < ($2, $3)${hostClause}
       ORDER BY timestamp DESC, id DESC LIMIT ${lim}`, [caseId, a.timestamp, a.id, ...hp]),
    pool.query(`SELECT ${CONTEXT_COLS} FROM collection_timeline
       WHERE case_id = $1 AND (timestamp, id) > ($2, $3)${hostClause}
       ORDER BY timestamp ASC, id ASC LIMIT ${lim}`, [caseId, a.timestamp, a.id, ...hp]),
    pool.query(`SELECT ${CONTEXT_COLS} FROM collection_timeline WHERE case_id = $1 AND id = $2`, [caseId, anchorId]),
  ]);

  const rows = [
    ...before.rows.reverse().map(r => ({ ...r, is_anchor: false })),
    { ...anchorFull.rows[0], is_anchor: true },
    ...after.rows.map(r => ({ ...r, is_anchor: false })),
  ];
  return { anchor_id: anchorId, all_hosts: allHosts, host_name: a.host_name, rows };
}

module.exports = { fetchContext, AnchorNotFound, CONTEXT_COLS };
