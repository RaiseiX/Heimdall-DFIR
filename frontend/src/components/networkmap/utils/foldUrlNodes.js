
export const URL_SCOPES = Object.freeze({
  MACHINES: 'machines',
  DOMAINS: 'domains',
  ALL: 'all',
});

export function urlHost(url) {
  const s = String(url ?? '').trim();
  if (!s) return null;
  const m = s.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i);
  if (!m) return null;
  const host = m[1].split('@').pop().replace(/:\d+$/, '').toLowerCase();
  return host || null;
}

const isUrlNode = (n) => n?.type === 'url';

function mergeUnique(target, values) {
  for (const v of values || []) if (v && !target.includes(v)) target.push(v);
}

export function foldUrlNodes(graph, scope) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  if (scope !== URL_SCOPES.MACHINES && scope !== URL_SCOPES.DOMAINS) {
    return { nodes: [...nodes], edges: [...edges], folded: { urls: 0, hosts: 0, unfoldable: 0 } };
  }

  const urlNodes = nodes.filter(isUrlNode);
  const kept = nodes.filter(n => !isUrlNode(n));

  if (scope === URL_SCOPES.MACHINES) {
    const gone = new Set(urlNodes.map(n => n.id));
    return {
      nodes: kept,
      edges: edges.filter(e => !gone.has(e.source) && !gone.has(e.target)),
      folded: { urls: urlNodes.length, hosts: 0, unfoldable: 0 },
    };
  }

  const hostOf = new Map();
  const hostNodes = new Map();
  let unfoldable = 0;

  for (const n of urlNodes) {
    const host = urlHost(n.id);
    if (!host) {
      unfoldable++;
      kept.push(n);
      continue;
    }
    hostOf.set(n.id, host);
    if (!hostNodes.has(host)) {
      hostNodes.set(host, {
        id: host,
        label: host,
        type: 'domain',
        connection_count: 0,
        total_bytes: 0,
        is_suspicious: false,
        evidence_ids: [],
        folded_urls: 0,
      });
    }
    const h = hostNodes.get(host);
    h.connection_count += Number(n.connection_count) || 0;
    h.total_bytes += Number(n.total_bytes) || 0;
    if (n.is_suspicious) h.is_suspicious = true;
    h.folded_urls += 1;
    mergeUnique(h.evidence_ids, n.evidence_ids);
  }

  const merged = new Map();
  const out = [];
  for (const e of edges) {
    const source = hostOf.get(e.source) ?? e.source;
    const target = hostOf.get(e.target) ?? e.target;
    if (source === target) continue;
    const folded = hostOf.has(e.source) || hostOf.has(e.target);
    if (!folded) { out.push(e); continue; }
    const key = `${source}||${target}||${(e.ports || [])[0] ?? ''}||${(e.protocols || [])[0] ?? ''}`;
    if (!merged.has(key)) {
      const copy = {
        ...e, source, target,
        connection_count: 0, total_bytes: 0,
        ports: [...(e.ports || [])], protocols: [...(e.protocols || [])],
        processes: [...(e.processes || [])], evidence_ids: [],
      };
      merged.set(key, copy);
      out.push(copy);
    }
    const c = merged.get(key);
    c.connection_count += Number(e.connection_count) || 0;
    c.total_bytes += Number(e.total_bytes) || 0;
    if (e.has_suspicious) c.has_suspicious = true;
    mergeUnique(c.evidence_ids, e.evidence_ids);
  }

  return {
    nodes: [...kept, ...hostNodes.values()],
    edges: out,
    folded: { urls: urlNodes.length - unfoldable, hosts: hostNodes.size, unfoldable },
  };
}
