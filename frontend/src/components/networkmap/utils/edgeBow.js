const LEAVE = 0.45;
const FLAT = { distances: '0 0', weights: '0.35 0.65' };

export function edgeBow(sx, sy, tx, ty) {
  const x1 = Number(sx), y1 = Number(sy), x2 = Number(tx), y2 = Number(ty);
  if (![x1, y1, x2, y2].every(Number.isFinite)) return FLAT;

  const dx = x2 - x1;
  const dy = y2 - y1;
  const l2 = dx * dx + dy * dy;
  if (l2 === 0) return FLAT;

  const d = (LEAVE * dx * dy) / Math.sqrt(l2);
  const w1 = clamp((LEAVE * dx * dx) / l2);
  const w2 = clamp(((1 - LEAVE) * dx * dx + dy * dy) / l2);

  return {
    distances: `${round(-d)} ${round(d)}`,
    weights: `${round(Math.min(w1, w2))} ${round(Math.max(w1, w2))}`,
  };
}

function clamp(v) {
  return Math.min(Math.max(v, 0.02), 0.98);
}

function round(v) {
  return Math.round(v * 1000) / 1000;
}
