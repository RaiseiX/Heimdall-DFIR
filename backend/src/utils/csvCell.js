const FORMULA_START = /^[=+\-@\t\r]/;
const PLAIN_NUMBER = /^[+-]?\d+(\.\d+)?$/;

function toText(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') return String(v);
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? '' : v.toISOString();
  if (typeof v === 'object') {
    const json = JSON.stringify(v);
    return json === undefined ? '' : json;
  }
  return String(v);
}

function csvCell(v, { sep = ',', raw = false } = {}) {
  let s = toText(v);
  if (typeof v === 'string' && FORMULA_START.test(s) && !(raw && PLAIN_NUMBER.test(s))) {
    s = "'" + s;
  }
  if (s.includes('"') || s.includes(sep) || s.includes('\r') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function csvRow(values, { sep = ',', rawIndexes = [] } = {}) {
  return values.map((v, i) => csvCell(v, { sep, raw: rawIndexes.includes(i) })).join(sep);
}

module.exports = { csvCell, csvRow };
