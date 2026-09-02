
export const ALWAYS_SHOWN = ['parsed', 'empty', 'unsupported', 'archive_expanded', 'error'];

const CANONICAL_ORDER = [
  'parsed', 'empty', 'unsupported', 'archive_expanded', 'error',
  'degraded', 'quarantined', 'skipped_duplicate',
  'received', 'extracting', 'classified', 'queued', 'parsing',
];

export function summarizeCoverage(payload) {
  const counts = payload?.counts ?? {};
  const total = Number(payload?.total ?? 0);
  const parsed = Number(counts.parsed ?? 0);

  const setAside = Math.max(total - parsed, 0);

  const keys = [...new Set([...ALWAYS_SHOWN, ...Object.keys(counts)])];
  const rows = keys
    .map(key => ({ key, n: Number(counts[key] ?? 0) }))
    .sort((a, b) => {
      const ia = CANONICAL_ORDER.indexOf(a.key);
      const ib = CANONICAL_ORDER.indexOf(b.key);
      return (ia === -1 ? CANONICAL_ORDER.length : ia) - (ib === -1 ? CANONICAL_ORDER.length : ib);
    });

  const summed = Object.values(counts).reduce((a, b) => a + Number(b ?? 0), 0);
  const consistent = summed === total;

  return { total, parsed, setAside, scope: payload?.counts_scope ?? 'case', rows, consistent };
}
