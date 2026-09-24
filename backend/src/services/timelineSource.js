// Which engine may answer a SuperTimeline query.
//
// Elasticsearch is a fast path, not a second source of truth. Two writers bypass it:
// the CatScale parser writes through batchInsert, and the inventory projection writes
// with INSERT ... SELECT so that 872,419 rows never make the round trip through Node.
// Only the CSV ingestion and Hayabusa paths call bulkIndex.
//
// The route used to hand the request to Elasticsearch as soon as it returned a
// non-zero total. An index holding a strict subset of Postgres then answered the same
// question with fewer rows and a smaller total, and said nothing about it — a case
// carrying a CSV import beside a CatScale collection would have rendered the CSV rows
// and hidden the collection entirely.
//
// The rule below is deliberately an equality, not a threshold: an index is trusted
// only when it holds exactly what Postgres holds for the case. Anything else, in
// either direction, falls back to Postgres — the source that has everything.

/**
 * @param {number} esCaseTotal   documents indexed for the case
 * @param {number} pgCaseTotal   rows in collection_timeline for the case
 * @returns {boolean} true only when Elasticsearch can answer without losing rows
 */
function esMayServe(esCaseTotal, pgCaseTotal) {
  // An unknown count is not an invitation to guess. Both a failed ES count and a
  // failed Postgres count land here, and both mean the same thing: we cannot show
  // that the fast path is complete, so we do not use it.
  if (!Number.isInteger(esCaseTotal) || !Number.isInteger(pgCaseTotal)) return false;
  if (esCaseTotal <= 0) return false;

  // An index ahead of the database is as suspect as one behind it: it holds rows a
  // purge removed from Postgres, which is to say evidence that no longer exists.
  return esCaseTotal === pgCaseTotal;
}

module.exports = { esMayServe };
