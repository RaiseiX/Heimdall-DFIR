export const EDGE_WIDTH_MIN = 1;
export const EDGE_WIDTH_MAX = 6;
export const EDGE_WIDTH_FLAT = 1.5;

export function maxConnectionCount(edges) {
  let max = 0;
  for (const e of edges || []) {
    const c = Number(e?.connection_count);
    if (Number.isFinite(c) && c > max) max = c;
  }
  return max;
}

export function edgeWidth(count, max) {
  const c = Number(count);
  const m = Number(max);
  if (!Number.isFinite(c) || !Number.isFinite(m) || m <= 1) return EDGE_WIDTH_FLAT;
  const clamped = Math.min(Math.max(c, 1), m);
  return EDGE_WIDTH_MIN + ((EDGE_WIDTH_MAX - EDGE_WIDTH_MIN) * (clamped - 1)) / (m - 1);
}
