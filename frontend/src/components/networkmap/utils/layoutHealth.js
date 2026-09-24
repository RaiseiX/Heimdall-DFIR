
const NODE_SIZE = 64;

const CROWD_TOLERANCE = 0.5;

export function isDegenerateLayout(positions, { nodeSize = NODE_SIZE } = {}) {
  const entries = Object.values(positions || {});
  if (entries.length < 2) return false;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const p of entries) {
    if (!p || !Number.isFinite(p.x) || !Number.isFinite(p.y)) return true;
    if (p.x < minX) minX = p.x;
    if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.y > maxY) maxY = p.y;
  }

  const width = maxX - minX;
  const height = maxY - minY;
  if (width === 0 && height === 0) return true;

  const area = Math.max(width, nodeSize) * Math.max(height, nodeSize);
  return area < entries.length * nodeSize * nodeSize * CROWD_TOLERANCE;
}
