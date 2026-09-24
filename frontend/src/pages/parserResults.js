
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
