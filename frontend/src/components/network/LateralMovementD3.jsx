import { useState, useEffect, useRef, useCallback } from 'react';
import { X, AlertTriangle, Clock, User, ArrowRight } from 'lucide-react';
import * as d3 from 'd3';

function riskScore(node) {
  if (!node.total_events) return 0;
  const sourceRatio = node.as_source / node.total_events;
  const targetRatio = node.as_target / node.total_events;

  if (sourceRatio >= 0.65 && node.total_events >= 5) return 70 + Math.min(30, node.total_events);

  if (targetRatio >= 0.70 && node.total_events >= 3) return 50 + Math.min(20, node.total_events);

  if (node.total_events >= 10) return 40;
  return Math.min(35, node.total_events * 5);
}

function nodeColor(node) {
  const score = riskScore(node);
  if (score >= 80) return '#da3633';
  if (score >= 60) return '#d97c20';
  if (score >= 40) return '#c89d1d';
  return '#4d82c0';
}

function nodeRiskLabel(node) {
  const score = riskScore(node);
  if (score >= 80) return { label: 'Pivot critique', color: '#da3633' };
  if (score >= 60) return { label: 'Pivot source', color: '#d97c20' };
  if (score >= 40) return { label: 'Actif', color: '#c89d1d' };
  return { label: 'Normal', color: '#4d82c0' };
}

function edgeColor(eventIds) {
  if (!eventIds || !eventIds.length) return '#4d82c050';
  if (eventIds.includes('4648')) return '#d97c2070';
  if (eventIds.includes('4768') || eventIds.includes('4769')) return '#06b6d470';
  return '#4d82c050';
}

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

const EVENT_LABELS = {
  '4624': '4624 Logon réseau',
  '4648': '4648 Credentials explicites',
  '4768': '4768 Kerberos TGT',
  '4769': '4769 Kerberos TGS',
  '4776': '4776 NTLM',
  '3':    'Sysmon 3 Connexion réseau',
};

export default function LateralMovementD3({ svgRef: externalSvgRef, nodes, edges, totalEvents, theme }) {
  const bgColor    = theme?.bg    || '#0d1117';
  const panelColor = theme?.panel || '#161b22';
  const borderColor = theme?.border || '#30363d';
  const textColor  = theme?.text  || '#e6edf3';
  const dimColor   = theme?.dim   || '#484f58';
  const gridColor  = theme?.mode === 'light' ? '#e8eef4' : '#161b22';
  const localSvgRef = useRef(null);
  const svgRef = externalSvgRef || localSvgRef;
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 800, height: 600 });
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedNodeEdges, setSelectedNodeEdges] = useState([]);

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

  const sortedNodes = [...nodes].sort((a, b) => riskScore(b) - riskScore(a));

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = dims.width;
    const height = dims.height;

    const nodesCopy = nodes.map(n => ({ ...n, _score: riskScore(n) }));
    const nodeById = new Map(nodesCopy.map(n => [n.id, n]));

    const linksCopy = edges
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
    ['normal', 'explicit', 'kerberos'].forEach(type => {
      const colors = { normal: '#4d82c0', explicit: '#d97c20', kerberos: '#06b6d4' };
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 18).attr('refY', 0)
        .attr('markerWidth', 5).attr('markerHeight', 5)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', `${colors[type]}80`);
    });

    const simulation = d3.forceSimulation(nodesCopy)
      .force('link', d3.forceLink(linksCopy).id(d => d.id).distance(d => 120 + Math.sqrt(d.count || 1) * 10))
      .force('charge', d3.forceManyBody().strength(d => -400 - d._score * 3))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => 14 + Math.sqrt(d.total_events || 1) * 3 + 10));

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', event => g.attr('transform', event.transform));
    svg.call(zoom);

    const getMarker = (e) => {
      if (e.event_ids?.includes('4648')) return 'url(#arrow-explicit)';
      if (e.event_ids?.includes('4768') || e.event_ids?.includes('4769')) return 'url(#arrow-kerberos)';
      return 'url(#arrow-normal)';
    };

    const link = g.append('g').selectAll('line').data(linksCopy).join('line')
      .attr('stroke', d => edgeColor(d.event_ids))
      .attr('stroke-width', d => Math.max(1.5, Math.min(8, Math.log2((d.count || 1) + 1) * 1.5)))
      .attr('marker-end', d => getMarker(d))
      .style('cursor', 'default');

    const linkLabel = g.append('g').selectAll('text').data(linksCopy).join('text')
      .text(d => d.count > 1 ? d.count : '')
      .attr('fill', dimColor).attr('font-size', 9).attr('font-family', 'monospace')
      .attr('text-anchor', 'middle').style('pointer-events', 'none');

    g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', d => 22 + Math.sqrt(d.total_events || 1) * 2)
      .attr('fill', d => `${nodeColor(d)}15`);

    const node = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', d => 10 + Math.sqrt(d.total_events || 1) * 2)
      .attr('fill', d => `${nodeColor(d)}30`)
      .attr('stroke', d => nodeColor(d))
      .attr('stroke-width', d => d._score >= 60 ? 2.5 : 1.5)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        const nodeEdges = edges.filter(e => {
          const src = typeof e.source === 'object' ? e.source.id : e.source;
          const dst = typeof e.target === 'object' ? e.target.id : e.target;
          return src === d.id || dst === d.id;
        });
        setSelectedNode({ ...d });
        setSelectedNodeEdges(nodeEdges);
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    g.append('g').selectAll('circle.ring').data(nodesCopy.filter(n => n._score >= 60)).join('circle')
      .attr('class', 'ring')
      .attr('r', d => 12 + Math.sqrt(d.total_events || 1) * 2 + 4)
      .attr('fill', 'none')
      .attr('stroke', d => nodeColor(d))
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '3,3')
      .style('pointer-events', 'none');

    g.append('g').selectAll('text').data(nodesCopy).join('text')
      .text(d => d.id.length > 20 ? d.id.slice(0, 18) + '…' : d.id)
      .attr('fill', textColor).attr('font-size', 10).attr('font-family', 'monospace')
      .attr('text-anchor', 'middle').attr('dy', d => -(12 + Math.sqrt(d.total_events || 1) * 2 + 6))
      .style('pointer-events', 'none');

    g.append('g').selectAll('text.stat').data(nodesCopy).join('text')
      .attr('class', 'stat')
      .text(d => `→${d.as_source} ←${d.as_target}`)
      .attr('fill', dimColor).attr('font-size', 8).attr('font-family', 'monospace')
      .attr('text-anchor', 'middle').attr('dy', d => 14 + Math.sqrt(d.total_events || 1) * 2 + 8)
      .style('pointer-events', 'none');

    node.append('title').text(d =>
      `${d.id}\nTotal: ${d.total_events} évts | Sortant: ${d.as_source} | Entrant: ${d.as_target}\nRisque: ${nodeRiskLabel(d).label}`
    );

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 5);
      g.selectAll('circle').attr('cx', d => d.x).attr('cy', d => d.y);
      g.selectAll('text').attr('x', d => d.x).attr('y', d => d.y);
    });

    return () => simulation.stop();
  }, [nodes, edges, dims]);

  return (
    <div ref={containerRef} style={{ display: 'flex', flex: 1, width: '100%', height: '100%', position: 'relative' }}>
      
      <div style={{
        position: 'absolute', top: 10, left: 10, zIndex: 20,
        display: 'flex', flexDirection: 'column', gap: 6,
      }}>
        
        <div style={{
          background: panelColor + 'cc', border: `1px solid ${borderColor}`, borderRadius: 5,
          padding: '6px 10px', fontSize: 10, display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>Risque nœud</div>
          {[
            ['#da3633', 'Pivot critique (≥80)'],
            ['#d97c20', 'Pivot source (≥60)'],
            ['#c89d1d', 'Actif (≥40)'],
            ['#4d82c0', 'Normal'],
          ].map(([color, label]) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, color: dimColor }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0 }} />
              {label}
            </span>
          ))}
          <div style={{ height: 1, background: borderColor, margin: '3px 0' }} />
          <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>Arêtes</div>
          {[
            ['#4d82c0', '4624 Logon réseau'],
            ['#d97c20', '4648 Credentials explicites'],
            ['#06b6d4', '4768/4769 Kerberos'],
          ].map(([color, label]) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, color: dimColor }}>
              <span style={{ width: 16, height: 2, background: color, flexShrink: 0 }} />
              {label}
            </span>
          ))}
        </div>

        {nodes.length > 0 && (
          <div style={{
            background: panelColor + 'cc', border: `1px solid ${borderColor}`, borderRadius: 5,
            padding: '5px 10px', fontSize: 10, color: dimColor, fontFamily: 'monospace',
          }}>
            {nodes.length} machines · {edges.length} chemins · {totalEvents} évts
          </div>
        )}

        {sortedNodes.slice(0, 3).filter(n => riskScore(n) >= 40).length > 0 && (
          <div style={{
            background: panelColor + 'cc', border: `1px solid ${borderColor}`, borderRadius: 5,
            padding: '6px 10px', fontSize: 10, maxWidth: 200,
          }}>
            <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', marginBottom: 4 }}>Machines à risque</div>
            {sortedNodes.slice(0, 3).filter(n => riskScore(n) >= 40).map(n => {
              const { label, color } = nodeRiskLabel(n);
              return (
                <div key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                  <span style={{ color: textColor, fontFamily: 'monospace', fontSize: 9, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {n.id}
                  </span>
                  <span style={{ color, fontSize: 9 }}>{label}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <svg
        ref={svgRef}
        width={dims.width}
        height={dims.height}
        style={{ display: 'block' }}
        onClick={() => setSelectedNode(null)}
      />

      {nodes.length === 0 && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <div style={{ textAlign: 'center', color: dimColor }}>
            <div style={{ fontSize: 13, marginBottom: 4 }}>Aucune donnée de mouvement latéral</div>
            <div style={{ fontSize: 11 }}>Parsez des journaux EVTX (Security) contenant les évènements 4624, 4648, 4768, 4769</div>
          </div>
        </div>
      )}

      {selectedNode && (
        <div
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0, width: 320,
            background: panelColor, borderLeft: `1px solid ${borderColor}`,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
          onClick={e => e.stopPropagation()}
        >
          
          <div style={{ padding: '10px 14px', borderBottom: `1px solid ${borderColor}`, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: textColor, fontFamily: 'monospace', marginBottom: 2 }}>
                  {selectedNode.id}
                </div>
                {(() => {
                  const { label, color } = nodeRiskLabel(selectedNode);
                  return (
                    <span style={{
                      padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                      background: `${color}20`, color, border: `1px solid ${color}30`,
                    }}>{label}</span>
                  );
                })()}
              </div>
              <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: dimColor }}>
                <X size={14} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, marginTop: 10 }}>
              {[
                ['Total', selectedNode.total_events, '#7d8590'],
                ['Sortant →', selectedNode.as_source, '#d97c20'],
                ['Entrant ←', selectedNode.as_target, '#4d82c0'],
              ].map(([label, val, color]) => (
                <div key={label} style={{ background: bgColor, borderRadius: 4, padding: '6px 8px', border: `1px solid ${borderColor}`, textAlign: 'center' }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color, fontFamily: 'monospace' }}>{val}</div>
                  <div style={{ fontSize: 9, color: dimColor }}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 14px' }}>
            <div style={{ fontSize: 11, color: dimColor, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Connexions ({selectedNodeEdges.length})
            </div>
            {selectedNodeEdges.map((edge, i) => {
              const src = typeof edge.source === 'object' ? edge.source.id : edge.source;
              const dst = typeof edge.target === 'object' ? edge.target.id : edge.target;
              const isOutgoing = src === selectedNode.id;
              return (
                <div key={i} style={{
                  marginBottom: 8, padding: '8px 10px', borderRadius: 4,
                  background: bgColor, border: `1px solid ${borderColor}`, fontSize: 11,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontFamily: 'monospace' }}>
                    <span style={{ color: isOutgoing ? '#d97c20' : '#4d82c0', fontSize: 10 }}>
                      {isOutgoing ? '→' : '←'}
                    </span>
                    <span style={{ color: textColor, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {isOutgoing ? dst : src}
                    </span>
                    <span style={{
                      padding: '1px 5px', borderRadius: 3, fontSize: 9,
                      background: '#4d82c020', color: '#4d82c0',
                    }}>×{edge.count}</span>
                  </div>

                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                    {(edge.event_ids || []).map(eid => (
                      <span key={eid} style={{
                        padding: '1px 5px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
                        background: eid === '4648' ? '#d97c2020' : eid === '4768' || eid === '4769' ? '#06b6d420' : '#4d82c020',
                        color: eid === '4648' ? '#d97c20' : eid === '4768' || eid === '4769' ? '#06b6d4' : '#4d82c0',
                      }}>{EVENT_LABELS[eid] || `Event ${eid}`}</span>
                    ))}
                  </div>

                  {edge.usernames?.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: dimColor, fontSize: 10 }}>
                      <User size={10} />
                      {edge.usernames.slice(0, 3).join(', ')}{edge.usernames.length > 3 ? ` +${edge.usernames.length - 3}` : ''}
                    </div>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 3, color: dimColor, fontSize: 9, fontFamily: 'monospace' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Clock size={9} /> {fmtTs(edge.first_seen)}
                    </span>
                    {edge.last_seen !== edge.first_seen && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                        <ArrowRight size={9} /> {fmtTs(edge.last_seen)}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
