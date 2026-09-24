
const NOT_A_NODE = new Set(['zone', 'zone-label', 'cluster', 'band-rule', 'band-label']);

const isExternal = (data) => data?._raw?.type === 'external';

export function triageStats(elements) {
  const nodeEls = (elements || []).filter(e =>
    e?.data && !e.data.source && e.data.id && !e.data._zone && !NOT_A_NODE.has(e.data.nodeType));
  const edgeEls = (elements || []).filter(e => e?.data?.source);

  const deg = new Map();
  for (const e of edgeEls) {
    deg.set(e.data.source, (deg.get(e.data.source) || 0) + 1);
    deg.set(e.data.target, (deg.get(e.data.target) || 0) + 1);
  }

  const score = (d) => (d._iocHit ? 40 : 0)
    + (d.is_suspicious ? 25 : 0)
    + (isExternal(d) ? 15 : 0)
    + Math.min((deg.get(d.id) || 0) * 2, 20);

  const suspects = nodeEls
    .map(e => ({
      id: e.data.id,
      label: e.data.label || e.data.id,
      ioc: !!e.data._iocHit,
      susp: !!e.data.is_suspicious,
      deg: deg.get(e.data.id) || 0,
      score: score(e.data),
    }))
    .filter(n => n.score > 0)
    .sort((a, b) => b.score - a.score || String(a.id).localeCompare(String(b.id)))
    .slice(0, 12);

  return {
    stats: {
      nodes: nodeEls.length,
      edges: edgeEls.length,
      ioc:   nodeEls.filter(e => e.data._iocHit).length,
      susp:  nodeEls.filter(e => e.data.is_suspicious).length,
      ext:   nodeEls.filter(e => isExternal(e.data)).length,
    },
    suspects,
  };
}
