import { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { Loader2, RefreshCw, ZoomIn, ZoomOut, Maximize2, Filter } from 'lucide-react';
import { casesAPI } from '../../utils/api';
import { fmtLocal } from '../../utils/formatters';

const EVENT_META = {
  '4624': { label: 'Logon réseau (4624)',        color: '#4d82c0', desc: 'Connexion réseau réussie' },
  '4648': { label: 'Explicit creds (4648)',       color: '#d97c20', desc: 'Logon avec credentials explicites (PTH/PTT)' },
  '4768': { label: 'Kerberos TGT (4768)',         color: '#8b72d6', desc: 'Demande de ticket Kerberos TGT' },
  '4769': { label: 'Kerberos TGS (4769)',         color: '#c96898', desc: 'Demande de ticket Kerberos TGS (Kerberoasting)' },
  '4776': { label: 'NTLM auth (4776)',            color: '#c89d1d', desc: 'Authentification NTLM (Pass-the-Hash)' },
  '3':    { label: 'Sysmon Netconn (EID 3)',      color: '#3fb950', desc: 'Connexion réseau (Sysmon)' },
  '?':    { label: 'Inconnu',                     color: '#7d8590', desc: 'Type inconnu' },
};

function edgeColor(event_ids) {
  if (!event_ids?.length) return '#7d8590';
  return EVENT_META[event_ids[0]]?.color || '#7d8590';
}

function renderGraph(svgEl, data, triageScores, filterEids) {
  const { nodes: rawNodes, edges: rawEdges } = data;

  const edges = filterEids.length
    ? rawEdges.filter(e => e.event_ids.some(eid => filterEids.includes(eid)))
    : rawEdges;

  const activeIds = new Set(edges.flatMap(e => [e.source, e.target]));
  const nodes = rawNodes.filter(n => activeIds.has(n.id));

  if (!nodes.length) return;

  const scoreMap = Object.fromEntries((triageScores || []).map(s => [s.hostname?.toLowerCase(), s]));
  const RISK_COLOR = { CRITIQUE: '#da3633', ÉLEVÉ: '#d97c20', MOYEN: '#c89d1d', FAIBLE: '#3fb950' };

  const svg = d3.select(svgEl);
  svg.selectAll('*').remove();

  const W = svgEl.clientWidth  || 900;
  const H = svgEl.clientHeight || 500;

  const defs = svg.append('defs');
  const markerIds = [...new Set(edges.map(e => edgeColor(e.event_ids)))];
  markerIds.forEach(color => {
    const safeId = 'arrow-' + color.replace('#', '');
    defs.append('marker')
      .attr('id', safeId)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', color)
      .attr('opacity', 0.8);
  });

  const zoom = d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', (event) => g.attr('transform', event.transform));

  svg.call(zoom);
  const g = svg.append('g');

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d => d.id).distance(d => 80 + Math.log1p(d.count) * 15))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collide', d3.forceCollide(35));

  const link = g.append('g').selectAll('line').data(edges).join('line')
    .attr('stroke', d => edgeColor(d.event_ids))
    .attr('stroke-width', d => Math.max(1, Math.min(6, Math.log1p(d.count))))
    .attr('stroke-opacity', 0.7)
    .attr('marker-end', d => `url(#arrow-${edgeColor(d.event_ids).replace('#', '')})`);

  const edgeLabel = g.append('g').selectAll('text').data(edges).join('text')
    .attr('font-size', 9)
    .attr('fill', '#7d8590')
    .attr('text-anchor', 'middle')
    .attr('font-family', 'JetBrains Mono, monospace')
    .text(d => d.count > 1 ? `×${d.count}` : '');

  const nodeG = g.append('g').selectAll('g').data(nodes).join('g')
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag',  (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end',   (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    );

  nodeG.append('rect')
    .attr('width', 120).attr('height', 28)
    .attr('x', -60).attr('y', -14)
    .attr('rx', 6)
    .attr('fill', d => {
      const score = scoreMap[d.id?.toLowerCase()];
      return score ? RISK_COLOR[score.risk_level] + '25' : '#161b2260';
    })
    .attr('stroke', d => {
      const score = scoreMap[d.id?.toLowerCase()];
      return score ? RISK_COLOR[score.risk_level] : '#30363d';
    })
    .attr('stroke-width', 1.5);

  nodeG.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '0.35em')
    .attr('font-size', 11)
    .attr('font-family', 'JetBrains Mono, monospace')
    .attr('font-weight', '600')
    .attr('fill', '#e6edf3')
    .text(d => d.id.length > 14 ? d.id.slice(0, 13) + '…' : d.id);

  const tooltip = d3.select('body').append('div')
    .attr('class', 'lateral-tooltip')
    .style('position', 'fixed')
    .style('display', 'none')
    .style('background', '#1c2333')
    .style('border', '1px solid #30363d')
    .style('border-radius', '8px')
    .style('padding', '10px 14px')
    .style('font-size', '12px')
    .style('color', '#e6edf3')
    .style('z-index', '9999')
    .style('pointer-events', 'none')
    .style('max-width', '300px')
    .style('font-family', 'JetBrains Mono, monospace');

  nodeG
    .on('mouseover', (event, d) => {
      const score = scoreMap[d.id?.toLowerCase()];
      tooltip.style('display', 'block').html(`
        <div style="font-weight:700;margin-bottom:6px;color:#4d82c0">${d.id}</div>
        <div>Événements : <strong>${d.total_events}</strong></div>
        <div>Source : ${d.as_source} — Destination : ${d.as_target}</div>
        ${score ? `<div style="margin-top:4px;color:${RISK_COLOR[score.risk_level]}">Score triage : ${score.score}/100 (${score.risk_level})</div>` : ''}
      `);
    })
    .on('mousemove', event => {
      tooltip.style('left', (event.clientX + 12) + 'px').style('top', (event.clientY - 10) + 'px');
    })
    .on('mouseout', () => tooltip.style('display', 'none'));

  link
    .on('mouseover', (event, d) => {
      const eids = d.event_ids.map(eid => EVENT_META[eid]?.label || eid).join(', ');
      const users = d.usernames.slice(0, 5).join(', ') || '—';
      tooltip.style('display', 'block').html(`
        <div style="font-weight:700;margin-bottom:6px">${d.source.id || d.source} → ${d.target.id || d.target}</div>
        <div>Événements : <strong>${d.count}</strong></div>
        <div>Types : ${eids}</div>
        <div>Comptes : ${users}</div>
        <div style="margin-top:4px;color:#7d8590">
          ${d.first_seen ? fmtLocal(d.first_seen) : ''}<br/>
          ${d.last_seen  ? fmtLocal(d.last_seen)  : ''}
        </div>
      `);
    })
    .on('mousemove', event => {
      tooltip.style('left', (event.clientX + 12) + 'px').style('top', (event.clientY - 10) + 'px');
    })
    .on('mouseout', () => tooltip.style('display', 'none'));

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    edgeLabel
      .attr('x', d => ((d.source.x || 0) + (d.target.x || 0)) / 2)
      .attr('y', d => ((d.source.y || 0) + (d.target.y || 0)) / 2 - 4);
    nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  return () => {
    tooltip.remove();
    sim.stop();
  };
}

export default function LateralMovementGraph({ caseId, triageScores }) {
  const svgRef = useRef(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filterEids, setFilterEids] = useState([]);
  const cleanupRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const res = await casesAPI.lateralMovement(caseId);
      setData(res.data);
    } catch {
      setError('Erreur chargement du graphe');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!data || !svgRef.current) return;
    if (cleanupRef.current) cleanupRef.current();
    cleanupRef.current = renderGraph(svgRef.current, data, triageScores, filterEids);
    return () => { if (cleanupRef.current) cleanupRef.current(); };
  }, [data, triageScores, filterEids]);

  function zoomIn()  { d3.select(svgRef.current).transition().call(d3.zoom().scaleBy, 1.4); }
  function zoomOut() { d3.select(svgRef.current).transition().call(d3.zoom().scaleBy, 0.7); }
  function resetZoom() {
    d3.select(svgRef.current).transition().call(
      d3.zoom().transform, d3.zoomIdentity
    );
  }

  const toggleEid = (eid) =>
    setFilterEids(prev => prev.includes(eid) ? prev.filter(e => e !== eid) : [...prev, eid]);

  const allEids = data ? [...new Set(data.edges.flatMap(e => e.event_ids))] : [];

  return (
    <div className="fl-card" style={{ overflow: 'hidden' }}>
      
      <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #21262d' }}>
        <div className="flex items-center gap-2">
          <Filter size={13} style={{ color: '#7d8590' }} />
          <span className="text-xs font-semibold" style={{ color: '#7d8590' }}>Filtrer par type :</span>
          {allEids.map(eid => {
            const m = EVENT_META[eid] || EVENT_META['?'];
            const active = filterEids.length === 0 || filterEids.includes(eid);
            return (
              <button
                key={eid}
                onClick={() => toggleEid(eid)}
                className="text-xs px-2 py-0.5 rounded font-mono transition-opacity"
                style={{
                  background: active ? m.color + '20' : '#21262d',
                  color: active ? m.color : '#484f58',
                  border: `1px solid ${active ? m.color + '40' : '#30363d'}`,
                }}
                title={m.desc}
              >
                {eid === '3' ? 'Sysmon 3' : `EID ${eid}`}
              </button>
            );
          })}
          {filterEids.length > 0 && (
            <button onClick={() => setFilterEids([])} className="text-xs" style={{ color: '#7d8590' }}>
              Tout afficher
            </button>
          )}
        </div>
        <div className="flex items-center gap-1">
          {data && (
            <span className="text-xs font-mono mr-2" style={{ color: '#7d8590' }}>
              {data.nodes.length} machines · {data.edges.length} liens · {data.total_events.toLocaleString()} events
            </span>
          )}
          <button onClick={zoomIn}    className="fl-btn fl-btn-ghost fl-btn-sm" title="Zoom +"><ZoomIn  size={13} /></button>
          <button onClick={zoomOut}   className="fl-btn fl-btn-ghost fl-btn-sm" title="Zoom -"><ZoomOut size={13} /></button>
          <button onClick={resetZoom} className="fl-btn fl-btn-ghost fl-btn-sm" title="Reset"><Maximize2 size={13} /></button>
          <button onClick={load}      className="fl-btn fl-btn-ghost fl-btn-sm" title="Recharger"><RefreshCw size={13} /></button>
        </div>
      </div>

      <div style={{ position: 'relative', height: 480, background: '#0d1117' }}>
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center" style={{ background: 'rgba(13,17,23,0.8)', zIndex: 10 }}>
            <Loader2 size={28} className="animate-spin" style={{ color: '#4d82c0' }} />
          </div>
        )}
        {error && (
          <div className="absolute inset-0 flex items-center justify-center" style={{ zIndex: 10 }}>
            <div className="text-sm" style={{ color: '#da3633' }}>{error}</div>
          </div>
        )}
        {!loading && !error && data?.nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
            <div className="text-sm font-semibold" style={{ color: '#7d8590' }}>Aucun mouvement latéral détecté</div>
            <div className="text-xs" style={{ color: '#484f58' }}>
              Assurez-vous que des événements 4624/4648/4768/4769/4776 ou Sysmon EID 3 sont indexés dans la timeline.
            </div>
          </div>
        )}
        <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block' }} />
      </div>

      {data?.edges.length > 0 && (
        <div className="flex flex-wrap gap-3 px-4 py-2" style={{ borderTop: '1px solid #21262d', background: '#0d1117' }}>
          {[...new Set(data.edges.flatMap(e => e.event_ids))].map(eid => {
            const m = EVENT_META[eid] || EVENT_META['?'];
            return (
              <div key={eid} className="flex items-center gap-1.5 text-xs" style={{ color: '#7d8590' }}>
                <div style={{ width: 24, height: 2, background: m.color, borderRadius: 1 }} />
                {m.label}
              </div>
            );
          })}
          <div className="flex items-center gap-1.5 text-xs ml-auto" style={{ color: '#7d8590' }}>
            Couleur nœud = score de triage · Glisser pour repositionner · Scroll pour zoomer
          </div>
        </div>
      )}
    </div>
  );
}
