// Hayabusa was written for one collection per case, and both ends of the route
// carried that assumption.
//
// The purge deleted every Hayabusa row of the *case* before writing the new run,
// so parsing one collection erased the detections of all the others. Observed in
// production: LAB-FORENSIC_Max held 4,832 detections and came back holding none,
// while LAB_Xtended-lab held 4,578 — 254 rows gone with nothing reporting it.
// The result row itself never recorded which collection produced it, although
// parser_results.evidence_id exists and is indexed.
//
// The rule applied here: a purge may only remove what it is about to rewrite.
// When the collection is known, it replaces that collection's previous run. When
// it is not, it replaces only the unattributed run — a run that cannot name its
// own evidence never touches rows that belong to an identified collection.
//
// Caveat worth knowing: rows left behind by a run whose parser_results row was
// removed out from under it (a CASCADE during an upload deletion, seen on
// 2026-08-24) keep whatever evidence_id they were inserted with. They are
// reclaimed by the next parse of that same collection, and only that one.

interface QueryResult {
  rows: Array<{ id: string }>;
  rowCount: number | null;
}

interface ScopedClient {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
}

export interface HayabusaPurge {
  timelineRows: number;
  resultIds: string[];
}

export async function purgeHayabusaScoped(
  client: ScopedClient,
  caseId: string | null | undefined,
  evidenceId: string | null | undefined = null,
): Promise<HayabusaPurge> {
  if (!caseId) {
    throw new Error('[hayabusaScope] refusing to purge without a case id');
  }

  const params: unknown[] = [caseId];
  let scope = 'AND evidence_id IS NULL';
  if (evidenceId) {
    params.push(evidenceId);
    scope = `AND evidence_id = $${params.length}`;
  }

  // Locking the in-scope result rows blocks a concurrent Hayabusa run on the
  // same collection, while leaving a run on a sibling collection free.
  const locked = await client.query(
    `SELECT id FROM parser_results
      WHERE case_id = $1 AND parser_name = 'Hayabusa' ${scope}
      FOR UPDATE`,
    params,
  );

  // The result rows to retire are not only the ones carrying the right evidence: they
  // are the ones that produced the rows we are about to erase. Observed in production
  // right after this fix shipped — 4,578 timeline rows carried evidence e0138b40 while
  // their parser_results row still carried NULL, because it predated the INSERT that
  // now fills the column. Scoping on evidence alone would have left that row behind,
  // added a fresh one beside it, and aggregateHayabusaMeta would have summed both.
  // Reading the result_ids of the rows inside our own scope stays just as narrow.
  const produced = await client.query(
    `SELECT DISTINCT result_id AS id FROM collection_timeline
      WHERE case_id = $1 AND artifact_type = 'hayabusa' AND result_id IS NOT NULL ${scope}`,
    params,
  );

  const resultIds = [...new Set([
    ...locked.rows.map(r => r.id),
    ...produced.rows.map(r => r.id),
  ])];

  const purged = await client.query(
    `DELETE FROM collection_timeline
      WHERE case_id = $1 AND artifact_type = 'hayabusa' ${scope}`,
    params,
  );

  if (resultIds.length > 0) {
    await client.query('DELETE FROM parser_results WHERE id = ANY($1::uuid[])', [resultIds]);
  }

  return { timelineRows: purged.rowCount ?? 0, resultIds };
}

// The reading end of the same defect. The route used to read one result row
// (ORDER BY created_at DESC LIMIT 1) for its metadata while counting detections
// across the whole case, so with two collections the screen would show one
// collection's evtx count beside a case-wide detection total. Two numbers each
// true on their own, one screen that is false.

export interface HayabusaMetaRow {
  created_at?: Date | string | null;
  output_data?: { evtx_files_count?: number; diagnostic?: unknown } | null;
}

export interface HayabusaMeta {
  evtxFilesCount: number;
  diagnostic: unknown | null;
  generatedAt: Date | string | null;
  runs: number;
}

export function aggregateHayabusaMeta(rows: HayabusaMetaRow[]): HayabusaMeta {
  if (!rows || rows.length === 0) {
    return { evtxFilesCount: 0, diagnostic: null, generatedAt: null, runs: 0 };
  }

  let evtxFilesCount = 0;
  let latest: HayabusaMetaRow | null = null;
  let latestAt = -Infinity;

  for (const row of rows) {
    evtxFilesCount += Number(row?.output_data?.evtx_files_count) || 0;
    // Ordering is decided here rather than trusted from the caller's ORDER BY.
    const at = row?.created_at ? new Date(row.created_at as string).getTime() : NaN;
    if (!Number.isNaN(at) && at > latestAt) {
      latestAt = at;
      latest = row;
    }
  }

  return {
    evtxFilesCount,
    diagnostic: latest?.output_data?.diagnostic ?? null,
    generatedAt: latest?.created_at ?? null,
    runs: rows.length,
  };
}
