// Health check for persisted node positions.
//
// NetworkExplorer restores saved positions verbatim and skips the layout entirely
// when they cover the whole graph. That makes a degenerate layout PERMANENT: it is
// saved once, then faithfully restored on every load, and nothing re-runs the
// layout to escape it.
//
// This predicate is deliberately conservative. A tall narrow column is a perfectly
// valid dagre/breadthfirst result, and re-laying it out would destroy a choice the
// analyst made. We only flag arrangements that no layout engine would produce:
// non-finite coordinates, everything stacked on one point, or nodes packed into
// far less room than their own footprint needs.

/** Node footprint in px — mirrors the node width/height in cytoscapeConfig. */
const NODE_SIZE = 64;

/** How much of the nodes' own footprint the bounding box may fall below before
 *  the arrangement counts as unreadable overlap rather than a tight layout. */
const CROWD_TOLERANCE = 0.5;

/**
 * @param {Record<string, {x:number, y:number}>} positions saved positions by node id
 * @param {{nodeSize?: number}} [opts]
 * @returns {boolean} true when re-running the layout beats restoring these positions
 */
export function isDegenerateLayout(positions, { nodeSize = NODE_SIZE } = {}) {
  const entries = Object.values(positions || {});
  // One node cannot be laid out badly, and zero nodes cannot be judged at all.
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
  if (width === 0 && height === 0) return true; // every node on one point

  // A perfectly straight line is legitimate, so grant each axis at least one
  // node's own thickness before measuring the area it occupies.
  const area = Math.max(width, nodeSize) * Math.max(height, nodeSize);
  return area < entries.length * nodeSize * nodeSize * CROWD_TOLERANCE;
}
