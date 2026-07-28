// scanCollectionCsvs (backend/src/services/csv/scanCollectionCsvs.js) tallies loose
// CSVs found in a collection under `__csv`, and stores it as a sibling key inside the
// same `output_data.parse_results` object that holds one entry per native parser
// (evtx, mft, …). Left alone, Object.entries() over that object renders a bogus
// "__csv" parser row — this pulls it out via exact-key destructuring (not a prefix
// match) and hands it back separately so the caller can render it as its own summary
// instead of a fake per-parser row.
//
// Also keeps `error` (a genuine parser failure) and `reason` (why a parser was
// deliberately excluded, e.g. "Tool not installed" or "No files found") as two
// distinct fields rather than merging them into one string. Both are legitimate,
// different outcomes, and collapsing them would make a parser that never ran look
// the same as one that ran and failed — the two things this module exists to keep
// apart are exactly the two things an earlier brief for this feature got wrong: it
// assumed `__csv` arrived through a different endpoint entirely, and separately
// proposed folding `reason` into `error` as one string.
//
// Pulled out of ParserLogsPage.jsx into its own module — pure, no DOM, no React —
// so it can be unit tested directly, following the pattern of collectionPane.js.

/**
 * @param {unknown} raw the value of `output_data.parse_results` for one parser_results row
 * @returns {{ parseResults: Array<{ parser: string, status: string, record_count: number|undefined,
 *              error: string|null, reason: string|null, warning: string|null }>,
 *            csvSummary: object|null }}
 */
export function buildParseResults(raw) {
  if (Array.isArray(raw)) return { parseResults: raw, csvSummary: null };
  if (!raw || typeof raw !== 'object') return { parseResults: [], csvSummary: null };
  const { __csv, ...rest } = raw;
  const parseResults = Object.entries(rest).map(([key, val]) => ({
    parser: val.name || key,
    status: val.status === 'success' ? 'ok' : (val.status || 'ok'),
    record_count: val.normalized_records ?? val.record_count ?? val.count,
    error: val.error || val.tool_output || null,
    reason: val.reason || null,
    warning: val.warning || null,
  }));
  return { parseResults, csvSummary: __csv || null };
}
