// Plain-text export of a parsing run's outcome — the way to carry it off the
// machine it ran on. Tests run on one box, debugging often happens on
// another, and a screenshot can't be grepped. Deliberately a pure function
// with no imports: ParserLogsPage.jsx owns the Blob/anchor/download-URL
// mechanics, this module only builds the text so it stays trivially
// unit-testable (no DOM, no i18n, no React Testing Library in this repo).
//
// Column order mirrors the on-screen per-parser table (parser, status,
// records, then whichever of error/reason/warning applies) so the two views
// stay easy to compare side by side. `error` (a genuine failure), `reason`
// (why a parser was deliberately excluded, e.g. "Tool not installed") and
// `warning` (e.g. a "degraded" parser's "0 events parsed" explanation) are
// three distinct outcomes — the DETAIL column shows whichever one the row
// actually has, but never silently drops the one that's present. The CSV
// decision counts are appended as their own section, never folded into the
// per-parser rows — this codebase's honest-status convention is that every
// distinct outcome gets its own visible line, not a combined "ok" tally.

const NOTICE =
  'This report may contain hostnames, usernames and file paths derived from real evidence. Handle and share accordingly.';

const CSV_KEYS = ['imported', 'imported_fallback', 'skipped_redundant', 'skipped_no_mapping', 'error'];

// Fixed-width column helper. Values that fit are space-padded out to `width`;
// values that don't are truncated (with a trailing ellipsis) rather than left
// to overflow — an overlong value that's merely appended-to would push every
// later column on that line out of alignment for the rest of the report.
function pad(value, width) {
  const s = String(value ?? '');
  if (s.length > width) {
    return width > 1 ? `${s.slice(0, width - 1)}…` : s.slice(0, width);
  }
  return s + ' '.repeat(width - s.length);
}

/**
 * @param {{ caseId?: string, collectionId?: string, generatedAt?: string,
 *            rows?: Array<{ parser: string, status: string, records?: number,
 *                            error?: string|null, reason?: string|null, warning?: string|null }>,
 *            csv?: { imported?: number, imported_fallback?: number,
 *                    skipped_redundant?: number, skipped_no_mapping?: number,
 *                    error?: number } | null }} run
 * @returns {string}
 */
export function buildParserLogReport({ caseId, collectionId, generatedAt, rows, csv } = {}) {
  const lines = [];

  lines.push('Heimdall-DFIR -- parsing log export');
  lines.push(`Case:       ${caseId ?? '-'}`);
  lines.push(`Collection: ${collectionId ?? '-'}`);
  lines.push(`Generated:  ${generatedAt ?? '-'}`);
  lines.push('');
  lines.push(NOTICE);
  lines.push('');

  lines.push(`${pad('PARSER', 22)}${pad('STATUS', 12)}${pad('RECORDS', 10)}DETAIL`);
  lines.push('-'.repeat(70));

  const parserRows = Array.isArray(rows) ? rows : [];
  if (!parserRows.length) {
    lines.push('(no parser rows for this run)');
  } else {
    for (const row of parserRows) {
      const detail = row?.error || row?.reason || row?.warning || '';
      lines.push(`${pad(row?.parser, 22)}${pad(row?.status, 12)}${pad(row?.records ?? 0, 10)}${detail}`);
    }
  }

  lines.push('');
  lines.push('CSV decisions:');
  if (csv && typeof csv === 'object') {
    for (const key of CSV_KEYS) {
      lines.push(`  ${pad(key, 22)}${csv[key] ?? 0}`);
    }
  } else {
    lines.push('  (no CSVs found in this collection)');
  }

  return lines.join('\n');
}
