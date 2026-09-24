import type { Pool } from 'pg';

// The filesystem timeline is the one artifact family whose volume can be an
// investigative choice: 332k rows under the default noise floor, 4.4M when the
// collection is parsed exhaustively. Exhaustive mode is only usable if it can be
// undone, so this is its counterpart.
//
// Deliberately narrow. It removes rows of one artifact type, for one case, and
// refuses to run without a case id — a purge that removes one row too many
// destroys evidence, and a missing scope must fail rather than widen.
const FS_ARTIFACT_TYPE = 'catscale_fstimeline';

export async function purgeFsTimeline(
  pool: Pool,
  caseId: string | null | undefined,
  opts: { evidenceId?: string | null } = {},
): Promise<number> {
  if (!caseId) {
    throw new Error('[fsTimelinePurge] refusing to purge without a case id');
  }

  const params: unknown[] = [caseId, FS_ARTIFACT_TYPE];
  let sql = `DELETE FROM collection_timeline WHERE case_id = $1 AND artifact_type = $2`;
  if (opts.evidenceId) {
    params.push(opts.evidenceId);
    sql += ` AND evidence_id = $3`;
  }

  const res = await pool.query(sql, params);
  return res.rowCount ?? 0;
}

/**
 * Same contract for the state inventory. "Ingest everything" is only a usable
 * choice if it can be undone: on a real host lsof alone contributes 525,221 rows
 * and exec-perm-files 150,223, so an analyst must be able to drop one family
 * without re-parsing the collection.
 */
export async function purgeCatScaleState(
  pool: Pool,
  caseId: string | null | undefined,
  opts: { evidenceId?: string | null; kind?: string | null } = {},
): Promise<number> {
  if (!caseId) {
    throw new Error('[fsTimelinePurge] refusing to purge state without a case id');
  }

  const params: unknown[] = [caseId];
  let sql = `DELETE FROM catscale_state WHERE case_id = $1`;
  if (opts.kind) { params.push(opts.kind); sql += ` AND kind = $${params.length}`; }
  if (opts.evidenceId) { params.push(opts.evidenceId); sql += ` AND evidence_id = $${params.length}`; }

  const res = await pool.query(sql, params);
  return res.rowCount ?? 0;
}

export { FS_ARTIFACT_TYPE };
