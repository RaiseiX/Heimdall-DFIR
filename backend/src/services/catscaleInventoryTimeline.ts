import type { Pool } from 'pg';

// Projects catscale_state into the SuperTimeline as undated inventory rows.
//
// catscale_state holds what a collection *found existing* — 872,419 objects across
// 63 kinds on the reference host: lsof entries, memory mappings, executable hashes,
// installed packages, runlevel symlinks. None of them carries a date. Because the
// SuperTimeline reads collection_timeline, and every row there had a timestamp,
// these objects were absent from the view entirely. Absent reads as "not collected",
// which is exactly the confusion the coverage ledger exists to prevent — only here
// it was the timeline lying rather than the parser.
//
// They enter with `timestamp IS NULL` and `timestamp_kind = 'inventory'`.
//
// NULL is load-bearing, not a placeholder. catscale_state.collected_at is right
// there and would make the NOT NULL constraint go away, but stamping 872,419 objects
// with 2026-07-30 14:44 would render them in a chronological view as that many
// simultaneous events — a fabricated burst of activity at the moment of collection.
// NULL states what is known: the object existed, its age is unknown. The grid leaves
// the DateTime cell empty and names the kind in its TS Type column, so an undated
// row can never be misread as a dated one.
//
// Written as INSERT ... SELECT so the rows never make the round trip through Node,
// and so one function serves both a fresh parse and a backfill of a case parsed
// before this existed.

// Purge is scoped to this evidence's own inventory rows. A re-parse already clears
// collection_timeline for the evidence before the first parser runs, but a standalone
// backfill has no such purge in front of it — without this, running it twice would
// double the inventory, and every count drawn from the view would be wrong in a way
// that looks like a parser improvement.
const PURGE_SQL = `
  DELETE FROM collection_timeline
   WHERE case_id = $1
     AND evidence_id = $2
     AND timestamp_kind = 'inventory'`;

// `kind` is at most 23 characters and `artifact_type` holds 50, so the prefix always
// fits; left() is kept as a guard rather than a necessity. Prefixing keeps these
// consistent with the twelve catscale_* types already in the view and makes all 63
// filterable through the existing artifact-type control, with no new UI.
//
// `label` runs to 512 characters, so it goes to description (TEXT) — putting it in
// artifact_name (VARCHAR 200) would truncate a third of the runlevel-symlink rows.
const PROJECT_SQL = `
  INSERT INTO collection_timeline
    (case_id, result_id, evidence_id, timestamp, timestamp_kind,
     artifact_type, artifact_name, description, source, raw, host_name, tool)
  SELECT s.case_id,
         s.result_id,
         s.evidence_id,
         NULL::timestamptz,
         'inventory',
         left('catscale_' || s.kind, 50),
         left(initcap(replace(s.kind, '_', ' ')), 200),
         s.label,
         s.source_file,
         s.raw,
         s.host_name,
         'catscale'
    FROM catscale_state s
   WHERE s.case_id = $1
     AND s.evidence_id = $2`;

/** Returns the number of inventory rows written. Throws rather than reporting 0:
 *  a projection that failed is not a collection that held nothing. */
export async function projectInventoryRows(
  pool: Pool,
  caseId: string,
  evidenceId: string,
): Promise<number> {
  await pool.query(PURGE_SQL, [caseId, evidenceId]);
  const res = await pool.query(PROJECT_SQL, [caseId, evidenceId]);
  return res.rowCount ?? 0;
}
