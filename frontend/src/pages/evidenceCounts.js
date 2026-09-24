export function entier(v) {
  if (v === null || v === undefined || v === '' || typeof v === 'boolean') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

export function ecartDeclare(declare, stocke) {
  const d = entier(declare);
  const s = entier(stocke);
  if (d === null || s === null || d === 0) return null;
  if (d === s) return null;
  return { declare: d, stocke: s, manquant: d - s };
}
