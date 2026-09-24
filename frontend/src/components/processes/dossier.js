function instant(v) {
  if (typeof v !== 'string' || !v.trim()) return NaN;
  const direct = Date.parse(v);
  if (Number.isFinite(direct)) return direct;
  return Date.parse(v.trim().replace(' ', 'T') + 'Z');
}

export function binaireRemplaceApres(creeProcessus, creeFichier) {
  const p = instant(creeProcessus);
  const f = instant(creeFichier);
  if (!Number.isFinite(p) || !Number.isFinite(f)) return null;
  if (f <= p) return null;
  return { ecartMs: f - p };
}

export function taillesConcordent(a, b) {
  const x = Number(a);
  const y = Number(b);
  if (a === null || a === undefined || a === '' || !Number.isFinite(x)) return null;
  if (b === null || b === undefined || b === '' || !Number.isFinite(y)) return null;
  return x === y;
}
