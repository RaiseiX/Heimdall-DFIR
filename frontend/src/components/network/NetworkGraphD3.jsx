import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { X, ExternalLink, AlertTriangle, Clock, Globe, Network, Tag, Link2 } from 'lucide-react';
import * as d3 from 'd3';
import { networkAPI } from '../../utils/api';

function isRFC1918(ip) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$)/.test(ip || '');
}

function fmtBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(Math.max(b, 1)) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[Math.min(i, s.length - 1)]}`;
}

function nodeColor(n) {
  if (n.is_suspicious) return '#da3633';
  if (n.type === 'domain') return '#3fb950';
  if (n.type === 'url')    return '#a371f7';
  return n.type === 'internal' ? '#4d82c0' : '#f0883e';
}

const ARTIFACT_COLORS = {
  evtx: '#4d82c0', hayabusa: '#da3633', mft: '#8b72d6', prefetch: '#22c55e',
  network: '#f0883e', dns: '#06b6d4', other: '#7d8590',
};

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'medium' });
}

export default function NetworkGraphD3({
  svgRef: externalSvgRef,
  caseId,
  nodes,
  edges,
  evidenceSources,
  activeEvidenceIds,
  onEvidenceFilter,
  theme,
}) {
  const bgColor   = theme?.bg    || '#0d1117';
  const gridColor = theme?.mode === 'light' ? '#e8eef4' : '#161b22';
  const textColor = theme?.text  || '#e6edf3';
  const dimColor  = theme?.dim   || '#484f58';
  const panelColor = theme?.panel || '#161b22';
  const borderColor = theme?.border || '#30363d';
  const localSvgRef = useRef(null);
  const svgRef = externalSvgRef || localSvgRef;
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 800, height: 600 });
  const navigate = useNavigate();

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect;
      if (width > 0 && height > 0) setDims({ width, height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const [selectedNode, setSelectedNode] = useState(null);
  const [nodeEvents, setNodeEvents] = useState([]);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [hideLocalIPs, setHideLocalIPs] = useState(false);
  const [typeFilters, setTypeFilters] = useState({ internal: true, external: true, domain: true, url: true });
  const [nodeSearch, setNodeSearch] = useState('');

  const toggleType = (key) => setTypeFilters(f => ({ ...f, [key]: !f[key] }));

  const applyPreset = (preset) => {
    if (preset === 'all')     setTypeFilters({ internal: true,  external: true,  domain: true,  url: true  });
    if (preset === 'ips')     setTypeFilters({ internal: true,  external: true,  domain: false, url: false });
    if (preset === 'domains') setTypeFilters({ internal: false, external: false, domain: true,  url: false });
    if (preset === 'urls')    setTypeFilters({ internal: false, external: false, domain: false, url: true  });
    setSelectedNode(null);
  };

  const filteredNodes = nodes.filter(n => {
    if (suspiciousOnly && !n.is_suspicious) return false;
    if (hideLocalIPs && isRFC1918(n.id)) return false;
    if (n.type === 'internal' && !typeFilters.internal) return false;
    if (n.type === 'external' && !typeFilters.external) return false;
    if (n.type === 'domain'   && !typeFilters.domain)   return false;
    if (n.type === 'url'      && !typeFilters.url)      return false;
    if (nodeSearch && !String(n.id).toLowerCase().includes(nodeSearch.toLowerCase())) return false;
    return true;
  });
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = edges.filter(e => {
    if (suspiciousOnly && !e.has_suspicious) return false;
    const src = typeof e.source === 'object' ? e.source.id : e.source;
    const dst = typeof e.target === 'object' ? e.target.id : e.target;
    if (hideLocalIPs && (isRFC1918(src) || isRFC1918(dst))) return false;
    return filteredNodeIds.has(src) && filteredNodeIds.has(dst);
  });

  const susCount = edges.filter(e => e.has_suspicious).length;

  useEffect(() => {
    if (!selectedNode) { setNodeEvents([]); return; }
    setLoadingEvents(true);
    networkAPI.nodeEvents(caseId, selectedNode.id, { limit: 30 })
      .then(res => setNodeEvents(Array.isArray(res.data) ? res.data : []))
      .catch(() => setNodeEvents([]))
      .finally(() => setLoadingEvents(false));
  }, [selectedNode, caseId]);

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = dims.width;
    const height = dims.height;

    const nodesCopy = filteredNodes.map(n => ({ ...n }));
    const nodeById = new Map(nodesCopy.map(n => [n.id, n]));

    const linksCopy = filteredEdges
      .map(e => ({
        ...e,
        source: typeof e.source === 'object' ? e.source.id : e.source,
        target: typeof e.target === 'object' ? e.target.id : e.target,
      }))
      .filter(e => nodeById.has(e.source) && nodeById.has(e.target));

    svg.append('rect').attr('width', width).attr('height', height).attr('fill', bgColor);
    const grid = svg.append('g');
    for (let x = 0; x < width; x += 40)
      grid.append('line').attr('x1', x).attr('y1', 0).attr('x2', x).attr('y2', height).attr('stroke', gridColor).attr('stroke-width', 0.5);
    for (let y = 0; y < height; y += 40)
      grid.append('line').attr('x1', 0).attr('y1', y).attr('x2', width).attr('y2', y).attr('stroke', gridColor).attr('stroke-width', 0.5);

    const defs = svg.append('defs');
    defs.append('radialGradient').attr('id', 'ngBlueN').html('<stop offset="0%" stop-color="#4d82c0" stop-opacity="0.3"/><stop offset="100%" stop-color="#4d82c0" stop-opacity="0"/>');
    defs.append('radialGradient').attr('id', 'ngOrangeN').html('<stop offset="0%" stop-color="#f0883e" stop-opacity="0.3"/><stop offset="100%" stop-color="#f0883e" stop-opacity="0"/>');
    defs.append('radialGradient').attr('id', 'ngRedN').html('<stop offset="0%" stop-color="#da3633" stop-opacity="0.3"/><stop offset="100%" stop-color="#da3633" stop-opacity="0"/>');
    defs.append('radialGradient').attr('id', 'ngGreenN').html('<stop offset="0%" stop-color="#3fb950" stop-opacity="0.3"/><stop offset="100%" stop-color="#3fb950" stop-opacity="0"/>');
    defs.append('radialGradient').attr('id', 'ngPurpleN').html('<stop offset="0%" stop-color="#a371f7" stop-opacity="0.3"/><stop offset="100%" stop-color="#a371f7" stop-opacity="0"/>');

    const linkDistance = Math.max(120, width * 0.15);
    const chargeStrength = Math.max(-400, -width * 0.5);

    const simulation = d3.forceSimulation(nodesCopy)
      .force('link', d3.forceLink(linksCopy).id(d => d.id).distance(linkDistance))
      .force('charge', d3.forceManyBody().strength(chargeStrength))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(55));

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', event => g.attr('transform', event.transform));
    svg.call(zoom);

    const link = g.append('g').selectAll('line').data(linksCopy).join('line')
      .attr('stroke', d => d.has_suspicious ? '#da363360' : '#4d82c050')
      .attr('stroke-width', d => Math.max(1, Math.min(10, Math.log2((d.connection_count || 1) + 1) * 2)))
      .attr('stroke-dasharray', d => d.has_suspicious ? '8,4' : 'none')
      .style('cursor', 'pointer')
      .on('mouseenter', function(event, d) {
        d3.select(this).attr('stroke', d.has_suspicious ? '#da3633cc' : '#4d82c0cc')
          .attr('stroke-width', Math.max(2, Math.min(12, Math.log2((d.connection_count || 1) + 1) * 2 + 2)));
      })
      .on('mouseleave', function(event, d) {
        d3.select(this)
          .attr('stroke', d.has_suspicious ? '#da363360' : '#4d82c050')
          .attr('stroke-width', Math.max(1, Math.min(10, Math.log2((d.connection_count || 1) + 1) * 2)));
      });

    const linkLabel = g.append('g').selectAll('text').data(linksCopy).join('text')
      .text(d => {
        const port = d.ports?.[0]; const proto = d.protocols?.[0];
        if (port && proto) return `${proto}:${port}`;
        if (port) return `port ${port}`;
        return proto || '';
      })
      .attr('fill', dimColor).attr('font-size', 8).attr('font-family', 'monospace')
      .attr('text-anchor', 'middle').style('pointer-events', 'none');

    g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', 26)
      .attr('fill', d => {
        if (d.is_suspicious) return 'url(#ngRedN)';
        if (d.type === 'domain') return 'url(#ngGreenN)';
        if (d.type === 'url') return 'url(#ngPurpleN)';
        return d.type === 'internal' ? 'url(#ngBlueN)' : 'url(#ngOrangeN)';
      });

    const linkedNodeIds = new Set(linksCopy.flatMap(e => [
      typeof e.source === 'object' ? e.source.id : e.source,
      typeof e.target === 'object' ? e.target.id : e.target,
    ]));
    const node = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', d => 8 + Math.sqrt(d.connection_count || 1) * 2.5)
      .attr('fill', d => nodeColor(d))
      .attr('stroke', bgColor).attr('stroke-width', 2)
      .attr('stroke-dasharray', d => linkedNodeIds.has(d.id) ? 'none' : '4,2')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode({ id: d.id, type: d.type, is_suspicious: d.is_suspicious, connection_count: d.connection_count, total_bytes: d.total_bytes });
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    node.append('title').text(d =>
      `${d.id}\n${d.type}${d.is_suspicious ? ' ⚠ Suspect' : ''}\n${d.connection_count} connexions\n${fmtBytes(d.total_bytes)}`
    );

    g.append('g').selectAll('text').data(nodesCopy).join('text')
      .text(d => {
        const id = String(d.id);
        if (d.type === 'url') {
          try {
            const u = new URL(id);
            const path = u.pathname.length > 1 ? u.pathname.substring(0, 18) + (u.pathname.length > 18 ? '…' : '') : '';
            return u.hostname + path;
          } catch  }
        }
        return id.length > 30 ? id.substring(0, 28) + '…' : id;
      })
      .attr('fill', textColor).attr('font-size', 10).attr('font-family', 'monospace')
      .attr('text-anchor', 'middle').attr('dy', -18).style('pointer-events', 'none');

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel.attr('x', d => (d.source.x + d.target.x) / 2).attr('y', d => (d.source.y + d.target.y) / 2 - 5);
      g.selectAll('circle').attr('cx', d => d.x).attr('cy', d => d.y);
      g.selectAll('text').attr('x', d => d.x).attr('y', d => d.y);
    });

    return () => simulation.stop();
  }, [filteredNodes, filteredEdges, dims]);

  return (
    <div ref={containerRef} style={{ display: 'flex', flex: 1, width: '100%', height: '100%', position: 'relative' }}>
      
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 20,
        display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
        padding: '6px 10px',
        background: panelColor + 'ee',
        borderBottom: `1px solid ${borderColor}`,
        backdropFilter: 'blur(4px)',
      }}>

        <span style={{ fontSize: 9, fontFamily: 'monospace', color: dimColor, textTransform: 'uppercase', letterSpacing: '0.05em', flexShrink: 0 }}>Vue</span>
        {[
          { id: 'all',     label: 'Tout',     Icon: Network },
          { id: 'ips',     label: 'IPs',      Icon: Globe   },
          { id: 'domains', label: 'Domaines', Icon: Tag     },
          { id: 'urls',    label: 'URLs',     Icon: Link2   },
        ].map(({ id, label, Icon }) => {
          const isActive =
            id === 'all'     ? (typeFilters.internal && typeFilters.external && typeFilters.domain && typeFilters.url) :
            id === 'ips'     ? (typeFilters.internal && typeFilters.external && !typeFilters.domain && !typeFilters.url) :
            id === 'domains' ? (!typeFilters.internal && !typeFilters.external && typeFilters.domain && !typeFilters.url) :
            (!typeFilters.internal && !typeFilters.external && !typeFilters.domain && typeFilters.url);
          return (
            <button key={id} onClick={() => applyPreset(id)} style={{
              display: 'flex', alignItems: 'center', gap: 3,
              padding: '2px 8px', fontSize: 10, fontFamily: 'monospace', borderRadius: 4, cursor: 'pointer',
              background: isActive ? '#1c2d3f' : 'transparent',
              border: `1px solid ${isActive ? '#4d82c060' : borderColor}`,
              color: isActive ? '#4d82c0' : dimColor,
            }}>
              <Icon size={9} /> {label}
            </button>
          );
        })}

        <div style={{ width: 1, height: 14, background: borderColor, flexShrink: 0 }} />

        {[
          { key: 'internal', label: 'Interne',  color: '#4d82c0' },
          { key: 'external', label: 'Externe',  color: '#f0883e' },
          { key: 'domain',   label: 'Domaine',  color: '#3fb950' },
          { key: 'url',      label: 'URL',      color: '#a371f7' },
        ].map(({ key, label, color }) => (
          <button key={key} onClick={() => toggleType(key)} style={{
            display: 'flex', alignItems: 'center', gap: 4,
            padding: '2px 7px', fontSize: 10, fontFamily: 'monospace', borderRadius: 4, cursor: 'pointer',
            background: typeFilters[key] ? `${color}15` : 'transparent',
            border: `1px solid ${typeFilters[key] ? `${color}40` : borderColor}`,
            color: typeFilters[key] ? color : dimColor,
            opacity: typeFilters[key] ? 1 : 0.45,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
            {label}
          </button>
        ))}

        <div style={{ width: 1, height: 14, background: borderColor, flexShrink: 0 }} />

        <button onClick={() => setSuspiciousOnly(v => !v)} style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '2px 8px', fontSize: 10, fontFamily: 'monospace', borderRadius: 4, cursor: 'pointer',
          background: suspiciousOnly ? '#da363315' : 'transparent',
          color: suspiciousOnly ? '#da3633' : dimColor,
          border: `1px solid ${suspiciousOnly ? '#da363340' : borderColor}`,
        }}>
          <AlertTriangle size={9} /> Suspects
        </button>
        <button onClick={() => setHideLocalIPs(v => !v)} style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '2px 8px', fontSize: 10, fontFamily: 'monospace', borderRadius: 4, cursor: 'pointer',
          background: hideLocalIPs ? '#4d82c015' : 'transparent',
          color: hideLocalIPs ? '#4d82c0' : dimColor,
          border: `1px solid ${hideLocalIPs ? '#4d82c040' : borderColor}`,
        }}>
          Masquer RFC1918
        </button>

        <div style={{ width: 1, height: 14, background: borderColor, flexShrink: 0 }} />

        <div style={{ position: 'relative', flexShrink: 0 }}>
          <input
            value={nodeSearch}
            onChange={e => setNodeSearch(e.target.value)}
            placeholder="Rechercher un nœud…"
            style={{
              background: bgColor, border: `1px solid ${borderColor}`, borderRadius: 4,
              padding: '2px 22px 2px 8px', fontSize: 10, fontFamily: 'monospace',
              color: textColor, width: 180, outline: 'none',
            }}
          />
          {nodeSearch && (
            <button onClick={() => setNodeSearch('')} style={{
              position: 'absolute', right: 5, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer', color: dimColor, fontSize: 10, lineHeight: 1,
            }}>✕</button>
          )}
        </div>

        {evidenceSources.length > 0 && (
          <>
            <div style={{ width: 1, height: 14, background: borderColor, flexShrink: 0 }} />
            {evidenceSources.map(ev => {
              const active = activeEvidenceIds.includes(ev.id);
              const label = (ev.name || ev.id).split('_')[0] || ev.id.slice(0, 8);
              return (
                <button key={ev.id} title={ev.name}
                  onClick={() => {
                    const next = active ? activeEvidenceIds.filter(x => x !== ev.id) : [...activeEvidenceIds, ev.id];
                    onEvidenceFilter(next);
                  }}
                  style={{
                    padding: '2px 8px', fontSize: 10, fontFamily: 'monospace', borderRadius: 10, cursor: 'pointer',
                    background: active ? '#4d82c018' : panelColor,
                    color: active ? '#4d82c0' : dimColor,
                    border: `1px solid ${active ? '#4d82c040' : borderColor}`,
                  }}
                >
                  Collecte: {label} {active ? '×' : '+'}
                </button>
              );
            })}
          </>
        )}

        <span style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: dimColor, flexShrink: 0 }}>
          {filteredNodes.length}/{nodes.length} nœuds · {filteredEdges.length} arêtes
          {susCount > 0 && <span style={{ color: '#da3633' }}> · {susCount} suspectes</span>}
        </span>
      </div>

      <svg
        ref={svgRef}
        width={dims.width}
        height={Math.max(0, dims.height - 36)}
        style={{ display: 'block', marginTop: 36 }}
        onClick={() => setSelectedNode(null)}
      />

      {nodes.length === 0 && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <div style={{ textAlign: 'center', color: dimColor }}>
            <div style={{ fontSize: 13, marginBottom: 4 }}>Aucune donnee reseau</div>
            <div style={{ fontSize: 11 }}>Parsez des logs reseau via la page Collection</div>
          </div>
        </div>
      )}

      {selectedNode && (
        <div
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0, width: 300,
            background: panelColor, borderLeft: `1px solid ${borderColor}`,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div style={{
            padding: '10px 14px', borderBottom: `1px solid ${borderColor}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
          }}>
            <div>
              {selectedNode.is_suspicious && <AlertTriangle size={13} style={{ color: '#da3633', marginRight: 5, display: 'inline' }} />}
              <span style={{ fontSize: 12, fontWeight: 700, color: textColor, fontFamily: 'monospace' }}>
                {selectedNode.id}
              </span>
              <div style={{ fontSize: 10, color: dimColor, marginTop: 2 }}>
                {selectedNode.type} · {selectedNode.connection_count} connexions · {fmtBytes(selectedNode.total_bytes)}
              </div>
            </div>
            <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: dimColor }}>
              <X size={14} />
            </button>
          </div>

          <div style={{ padding: '10px 14px', borderBottom: `1px solid ${borderColor}`, flexShrink: 0 }}>
            <button
              onClick={() => navigate(`/cases/${caseId}/collections/timeline?search=${encodeURIComponent(selectedNode.id)}`)}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                width: '100%', padding: '6px 10px', fontSize: 11, borderRadius: 4, cursor: 'pointer',
                background: bgColor, color: '#4d82c0', border: `1px solid ${borderColor}`,
              }}
            >
              <ExternalLink size={11} /> Voir dans Super Timeline
            </button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 14px' }}>
            <div style={{ fontSize: 11, color: dimColor, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Evenements timeline ({loadingEvents ? '...' : nodeEvents.length})
            </div>
            {loadingEvents ? (
              <div style={{ color: dimColor, fontSize: 11, textAlign: 'center', padding: 20 }}>Chargement...</div>
            ) : nodeEvents.length === 0 ? (
              <div style={{ color: dimColor, fontSize: 11, textAlign: 'center', padding: 20 }}>Aucun evenement trouve</div>
            ) : (
              nodeEvents.map((ev, i) => (
                <div key={i} style={{
                  marginBottom: 8, padding: '8px 10px', borderRadius: 4,
                  background: bgColor, border: `1px solid ${borderColor}`, fontSize: 11,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
                    <span style={{
                      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                      background: `${ARTIFACT_COLORS[ev.artifact_type] || '#7d8590'}20`,
                      color: ARTIFACT_COLORS[ev.artifact_type] || '#7d8590',
                      border: `1px solid ${ARTIFACT_COLORS[ev.artifact_type] || '#7d8590'}30`,
                    }}>{ev.artifact_type || 'other'}</span>
                    {ev.evidence_name && (
                      <span style={{ fontSize: 9, color: dimColor, fontFamily: 'monospace' }}>
                        {(ev.evidence_name).split('_')[0] || ev.evidence_name}
                      </span>
                    )}
                  </div>
                  <div style={{ color: textColor, marginBottom: 3, lineHeight: 1.4 }}>
                    {ev.description ? ev.description.slice(0, 120) + (ev.description.length > 120 ? '...' : '') : '—'}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: dimColor, fontSize: 9, fontFamily: 'monospace' }}>
                    <Clock size={9} /> {fmtTs(ev.timestamp)}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
