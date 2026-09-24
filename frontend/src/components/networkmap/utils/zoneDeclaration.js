export const ZONES = Object.freeze(['internal', 'dmz', 'external']);

const INFERABLE = Object.freeze(new Set(['internal', 'external']));

export function zoneOf(node, declarations) {
  const inferred = INFERABLE.has(node?.type) ? node.type : null;
  const decl = node?.id != null ? declarations?.[node.id] : null;

  if (decl && ZONES.includes(decl.zone)) {
    return {
      zone: decl.zone,
      source: 'declared',
      inferred,
      by: decl.by ?? null,
      at: decl.at ?? null,
    };
  }
  return { zone: inferred, source: 'inferred', inferred, by: null, at: null };
}

export function declareZone(declarations, nodeId, zone, by, at) {
  const next = { ...(declarations || {}) };
  if (!nodeId || !by || !ZONES.includes(zone)) return next;
  next[nodeId] = { zone, by, at };
  return next;
}

export function withdrawZone(declarations, nodeId) {
  const next = { ...(declarations || {}) };
  delete next[nodeId];
  return next;
}

export function countZones(nodes, declarations) {
  const out = { inferred: {}, declared: {} };
  for (const node of nodes || []) {
    const { zone, source, inferred } = zoneOf(node, declarations);
    if (inferred) out.inferred[inferred] = (out.inferred[inferred] || 0) + 1;
    if (source === 'declared' && zone) out.declared[zone] = (out.declared[zone] || 0) + 1;
  }
  return out;
}

export function declaredZoneEntries(declared) {
  const d = declared || {};
  return ZONES
    .filter(zone => Number(d[zone]) > 0)
    .map(zone => ({ zone, count: Number(d[zone]), key: `networkMap.band.zone_declared_${zone}` }));
}
