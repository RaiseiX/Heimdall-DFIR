
const ROW   = 34;
const COL   = 420;
const HUB   = 400;
const LEFT  = 60;
const GAP   = 120;

const byVolume = (a, b) =>
  (Number(b.data?.connection_count) || 0) - (Number(a.data?.connection_count) || 0)
  || String(a.data?.id).localeCompare(String(b.data?.id));

export function zonesLayout(bands, { hub = null, omit = null } = {}) {
  const skip = omit || new Set();
  const keep = (n) => n?.data?.id != null && !skip.has(n.data.id);

  const list = (bands || [])
    .map(b => ({ zone: b?.zone, nodes: (b?.nodes || []).filter(keep) }))
    .filter(b => b.nodes.length);
  const out = { positions: {}, bands: [], top: 0, bottom: 0 };
  if (!list.length) return out;

  const columns = list.map(b => ({
    zone: b.zone,
    nodes: b.nodes.filter(n => n.data.id !== hub).sort(byVolume),
    hub: b.nodes.find(n => n.data.id === hub) || null,
  }));

  const tallest = Math.max(...columns.map(c => c.nodes.length), 1);
  const height = (tallest - 1) * ROW;

  let cursor = 0;
  columns.forEach((col) => {
    const width = COL + (col.hub ? HUB : 0);
    const x = cursor + LEFT;
    const offset = (height - (col.nodes.length - 1) * ROW) / 2;
    col.nodes.forEach((n, row) => {
      out.positions[n.data.id] = { x, y: offset + row * ROW };
    });
    const hubX = cursor + width - LEFT;
    if (col.hub) out.positions[col.hub.data.id] = { x: hubX, y: height / 2 };

    out.bands.push({
      zone: col.zone,
      x0: x,
      x1: col.hub ? hubX : x,
      count: col.nodes.length + (col.hub ? 1 : 0),
    });
    cursor += width + GAP;
  });

  out.top = 0;
  out.bottom = height;
  return out;
}
