
const NOTICE =
  'This report may contain hostnames, usernames and file paths derived from real evidence. Handle and share accordingly.';

const CSV_KEYS = ['imported', 'imported_fallback', 'skipped_redundant', 'skipped_no_mapping', 'error'];

function pad(value, width) {
  const s = String(value ?? '');
  if (s.length > width) {
    return width > 1 ? `${s.slice(0, width - 1)}…` : s.slice(0, width);
  }
  return s + ' '.repeat(width - s.length);
}

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
