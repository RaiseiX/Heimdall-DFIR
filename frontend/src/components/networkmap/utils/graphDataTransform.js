// frontend/src/components/networkmap/utils/graphDataTransform.js
import { classifyNode, detectNodeType, nodeBadges, isInternal, getIPCategory, getPortBadges, getOSHint } from './nodeTypeRegistry';

function cidrContains(cidr, ip) {
  try {
    const raw = (ip || '').replace(/^::ffff:/i, '').replace(/:\d+$/, '');
    if (!raw || raw.includes(':')) return false;
    const [base, bits = '32'] = cidr.split('/');
    const shift = 32 - parseInt(bits, 10);
    const toNum = a => a.split('.').reduce((n, o) => (n << 8) | parseInt(o, 10), 0) >>> 0;
    return (toNum(raw) >>> shift) === (toNum(base) >>> shift);
  } catch { return false; }
}

function subnet24(ip) {
  const normalized = String(ip).replace(/^::ffff:/i, '');
  const parts = normalized.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function labelForNode(id) {
  if (!id) return '?';
  if (/^https?:\/\//i.test(id)) {
    try { return new URL(id).hostname; } catch {}
  }
  return id.length > 30 ? id.slice(0, 28) + '…' : id;
}

export function transformGraphData(apiData, nodeOverrides = {}, subnetRules = []) {
  const { nodes = [], edges = [] } = apiData;
  const elements = [];
  const clusterIds = new Set();

  // ── Pre-build port map from raw edges (nodeId → port numbers) ────────────
  const nodePortMap = new Map();
  edges.forEach(e => {
    const src = typeof e.source === 'string' ? e.source : e.source?.id;
    const tgt = typeof e.target === 'string' ? e.target : e.target?.id;
    const ports = e.ports || [];
    if (ports.length) {
      if (!nodePortMap.has(src)) nodePortMap.set(src, []);
      nodePortMap.get(src).push(...ports);
      if (!nodePortMap.has(tgt)) nodePortMap.set(tgt, []);
      nodePortMap.get(tgt).push(...ports);
    }
  });

  // ── 1. IP /24 subnet clustering ──────────────────────────────────────
  const subnetMap = new Map();
  nodes.forEach(n => {
    if (isInternal(n.id)) {
      const sn = subnet24(n.id);
      if (sn) {
        if (!subnetMap.has(sn)) subnetMap.set(sn, []);
        subnetMap.get(sn).push(n.id);
      }
    }
  });

  const nodeToCluster = new Map();
  subnetMap.forEach((ids, subnet) => {
    if (ids.length > 1) {
      const clusterId = `cluster:${subnet}`;
      clusterIds.add(clusterId);
      elements.push({
        data: { id: clusterId, label: subnet, nodeType: 'cluster', collapsed: false, childCount: ids.length },
        classes: 'cluster',
      });
      ids.forEach(id => nodeToCluster.set(id, clusterId));
    }
  });

  // ── 2. URL domain clustering ──────────────────────────────────────────
  // All http/https URLs with the same hostname → one domain node
  const domainAgg = new Map(); // hostname → { ids, suspicious, totalBytes, connectionCount, evidenceIds }
  const suppressedNodes = new Set();
  const urlToDomain = new Map();

  nodes.forEach(n => {
    if (/^https?:\/\//i.test(n.id)) {
      try {
        const host = new URL(n.id).hostname;
        if (!domainAgg.has(host)) domainAgg.set(host, { ids: [], suspicious: false, totalBytes: 0, connectionCount: 0, evidenceIds: [] });
        const e = domainAgg.get(host);
        e.ids.push(n.id);
        if (n.is_suspicious) e.suspicious = true;
        e.totalBytes    += n.total_bytes     || 0;
        e.connectionCount += n.connection_count || 0;
        // Propagate evidence_ids so domain clusters are filtered correctly in GlobalNetworkMapPage
        if (n.evidence_ids?.length) {
          for (const eid of n.evidence_ids) {
            if (!e.evidenceIds.includes(eid)) e.evidenceIds.push(eid);
          }
        }
      } catch {}
    }
  });

  domainAgg.forEach(({ ids, suspicious, totalBytes, connectionCount, evidenceIds }, hostname) => {
    const domainId = `domain:${hostname}`;
    clusterIds.add(domainId);
    elements.push({
      data: {
        id: domainId,
        label: ids.length > 1 ? `${hostname} (${ids.length})` : hostname,
        nodeType: 'domain',
        is_suspicious: suspicious,
        total_bytes: totalBytes,
        connection_count: connectionCount,
        urlCount: ids.length,
        _raw: { id: domainId, hostname, urls: ids, evidence_ids: evidenceIds },
      },
      classes: ['domain', suspicious ? 'suspicious' : ''].filter(Boolean).join(' '),
    });
    ids.forEach(id => { suppressedNodes.add(id); urlToDomain.set(id, domainId); });
  });

  // ── 3. Non-URL node elements ─────────────────────────────────────────
  nodes.forEach(n => {
    if (suppressedNodes.has(n.id)) return;
    const badges    = nodeBadges(n);
    const parent    = nodeToCluster.get(n.id);
    // Prefer backend-provided ports, fall back to frontend edge aggregation
    const ports        = n.ports?.length ? n.ports : (nodePortMap.get(n.id) || []);
    const behavior     = { serverScore: n.server_score ?? null };
    const classification = nodeOverrides[n.id]
      ? { typeId: nodeOverrides[n.id], confidence: 'OVERRIDE', signals: ['manual_override'] }
      : classifyNode(n, ports, behavior);
    const typeId       = classification.typeId;
    const portBadges   = getPortBadges(ports);
    const ipCategory   = getIPCategory(String(n.id || ''));
    const osHint       = n.os_hint || getOSHint(ports);
    const segmentRule  = subnetRules.find(r => r.cidr && cidrContains(r.cidr, String(n.id || '')));
    const segment      = segmentRule ? { label: segmentRule.label, color: segmentRule.color || '#6b8ccf' } : null;
    elements.push({
      data: {
        id: n.id,
        label: labelForNode(n.id),
        nodeType: typeId,
        ...(parent ? { parent } : {}),
        is_suspicious: n.is_suspicious || false,
        connection_count: n.connection_count || 0,
        total_bytes: n.total_bytes || 0,
        beacon_score: n.beacon_score || 0,
        dga_score: n.dga_score || 0,
        badges,
        portBadges,
        ipCategory: ipCategory || null,
        osHint:     osHint   || null,
        segment,
        confidence: classification.confidence,
        signals:    classification.signals,
        serverScore: n.server_score ?? null,
        geo:        n.geo || null,
        _raw: n,
        _overridden: !!nodeOverrides[n.id],
      },
      classes: [typeId, n.is_suspicious ? 'suspicious' : '', badges.includes('beacon') ? 'beacon' : '', badges.includes('dga') ? 'dga' : ''].filter(Boolean).join(' '),
    });
  });

  // ── 4. Edges — remapped to domain nodes, deduplicated ────────────────
  const visibleNodeIds = new Set([
    ...nodes.filter(n => !suppressedNodes.has(n.id)).map(n => n.id),
    ...Array.from(domainAgg.keys()).map(h => `domain:${h}`),
    ...Array.from(subnetMap.entries()).filter(([, ids]) => ids.length > 1).map(([sn]) => `cluster:${sn}`),
  ]);

  const edgeMap = new Map();
  edges.forEach(e => {
    const rawSrc = typeof e.source === 'string' ? e.source : e.source?.id;
    const rawTgt = typeof e.target === 'string' ? e.target : e.target?.id;
    const src = urlToDomain.get(rawSrc) || rawSrc;
    const tgt = urlToDomain.get(rawTgt) || rawTgt;

    if (src === tgt) return;
    if (!visibleNodeIds.has(src) || !visibleNodeIds.has(tgt)) return;

    const key = `${src}→${tgt}`;
    if (!edgeMap.has(key)) {
      edgeMap.set(key, {
        source: src, target: tgt,
        connection_count: 0, total_bytes: 0,
        ports: [], protocols: [], has_suspicious: false,
        first_seen: null, last_seen: null, label: null,
      });
    }
    const agg = edgeMap.get(key);
    agg.connection_count += e.connection_count || 1;
    agg.total_bytes      += e.total_bytes || 0;
    if (e.has_suspicious) agg.has_suspicious = true;
    if (e.ports)     agg.ports     = [...new Set([...agg.ports,     ...e.ports])];
    if (e.protocols) agg.protocols = [...new Set([...agg.protocols, ...e.protocols])];
    if (e.first_seen && (!agg.first_seen || e.first_seen < agg.first_seen)) agg.first_seen = e.first_seen;
    if (e.last_seen  && (!agg.last_seen  || e.last_seen  > agg.last_seen))  agg.last_seen  = e.last_seen;
    if (!agg.label && e.label) agg.label = e.label;
  });

  edgeMap.forEach((edge, key) => {
    // Build compact edge label: primary protocol then port count if > 1
    const mainLabel = edge.label
      || (edge.protocols[0] || (edge.ports[0] ? `TCP:${edge.ports[0]}` : null));
    const label = mainLabel && edge.ports.length > 1
      ? `${mainLabel} +${edge.ports.length - 1}`
      : mainLabel;

    elements.push({
      data: {
        id: `e_${key}`,
        source: edge.source,
        target: edge.target,
        connection_count: edge.connection_count,
        total_bytes: edge.total_bytes,
        ports: edge.ports,
        protocols: edge.protocols,
        has_suspicious: edge.has_suspicious,
        first_seen: edge.first_seen,
        last_seen:  edge.last_seen,
        label:      label || '',
        _raw: edge,
      },
      classes: edge.has_suspicious ? 'suspicious-edge' : 'normal-edge',
    });
  });

  return { elements, clusterIds };
}
