// Elasticsearch ↔ Postgres consistency for collection_timeline.
//
// ES is indexed fire-and-forget during parsing, and the historical indexing
// path bulk-indexed EVERY batch row — including the duplicates Postgres
// dropped via ON CONFLICT DO NOTHING (the same hive collected live AND from a
// VSS shadow copy yields identical rows with the same dedupe_hash). ES can
// therefore end up holding MORE documents than PG (observed: 1 422 k vs
// 935 k), and the one-directional completeness check in /timeline (ES < PG)
// never caught the other direction — the SuperTimeline then served the
// inflated ES count while the per-evidence menu read PG.
//
// rebuildEsFromPg() compares the counts and, when they disagree, rebuilds the
// case index from PG (delete + recreate + stream re-index). Idempotent and
// best-effort: it is called after each parse finalization and at boot.
const { pool } = require('../config/database');
const esService = require('./elasticsearchService');

const REBUILD_BATCH = 2000;

async function rebuildEsFromPg(caseId) {
  const pgCount = (await pool.query(
    `SELECT COUNT(*)::int AS c FROM collection_timeline WHERE case_id = $1`, [caseId]
  )).rows[0]?.c || 0;
  const hasIndex = await esService.indexExists(caseId);
  const esCount  = hasIndex ? await esService.countDocuments(caseId) : 0;

  if (hasIndex && esCount === pgCount) {
    return { es: esCount, pg: pgCount, rebuilt: false };
  }

  logger().warn(`[ES] ${caseId}: ${esCount} docs ≠ PG ${pgCount} — rebuilding index from PG`);
  await esService.clearCaseIndex(caseId); // delete + recreate with mapping/settings

  let lastId = 0;
  let indexed = 0;
  for (;;) {
    const { rows } = await pool.query(
      `SELECT case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name,
              description, source, raw,
              host_name, user_name, process_name,
              mitre_technique_id, mitre_technique_name, mitre_tactic,
              details, dedupe_hash
         FROM collection_timeline
        WHERE case_id = $1 AND id > $2
        ORDER BY id
        LIMIT $3`, [caseId, lastId, REBUILD_BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;
    await esService.bulkIndex(caseId, rows);
    indexed += rows.length;
  }
  logger().info(`[ES] ${caseId}: rebuilt — ${indexed} documents indexed from PG`);
  return { es: indexed, pg: pgCount, rebuilt: true };
}

// Boot sweep: every case with timeline rows gets its ES index checked and, if
// needed, rebuilt. Runs in the background — a large rebuild must never delay
// startup.
async function reconcileAllCases() {
  try {
    const { rows } = await pool.query(`SELECT DISTINCT case_id FROM collection_timeline`);
    for (const r of rows) {
      try {
        await rebuildEsFromPg(r.case_id);
      } catch (e) {
        logger().warn(`[ES] reconcile ${r.case_id} failed (best-effort): ${String(e.message).substring(0, 150)}`);
      }
    }
  } catch (e) {
    logger().warn(`[ES] reconcileAllCases failed (best-effort): ${String(e.message).substring(0, 150)}`);
  }
}

function logger() {
  return require('../config/logger').default;
}

module.exports = { rebuildEsFromPg, reconcileAllCases };
