
export function downloadCSV(rows, columns, filename) {
  const BOM = '\uFEFF';
  const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;

  const header = columns.map(c => escape(c.label)).join(',');
  const body   = rows.map(r =>
    columns.map(c => escape(r[c.key])).join(',')
  ).join('\n');

  const blob = new Blob([BOM + header + '\n' + body], {
    type: 'text/csv;charset=utf-8;',
  });

  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
