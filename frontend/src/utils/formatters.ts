
export function fmtLocal(ts: string | number | null | undefined): string {
  if (!ts) return '—';
  try {
    return new Date(ts as string).toLocaleString('fr-FR', { timeZone: 'UTC' }) + ' UTC';
  } catch { return String(ts); }
}

export function fmtTs(ts: string | null | undefined): string {
  if (!ts) return '-';
  try {
    const d = new Date(ts);
    const p = (n: number, l = 2) => String(n).padStart(l, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} `
         + `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`
         + `.${p(d.getUTCMilliseconds(), 3)}`;
  } catch { return String(ts); }
}
