import { useState, useEffect, useRef, useCallback } from 'react';
import { X, Clock, Shield, BookmarkIcon, Cpu, GitBranch } from 'lucide-react';
import * as d3 from 'd3';

const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const TACTIC_COLORS = {
  'Reconnaissance':          'var(--fl-accent)',
  'Resource Development':    'var(--fl-purple)',
  'Initial Access':          'var(--fl-gold)',
  'Execution':               'var(--fl-warn)',
  'Persistence':             'var(--fl-pink)',
  'Privilege Escalation':    'var(--fl-accent)',
  'Defense Evasion':         '#64748b',
  'Credential Access':       'var(--fl-purple)',
  'Discovery':               'var(--fl-ok)',
  'Lateral Movement':        'var(--fl-warn)',
  'Collection':              'var(--fl-ok)',
  'Command and Control':     'var(--fl-purple)',
  'Exfiltration':            'var(--fl-danger)',
  'Impact':                  'var(--fl-danger)',
};

const CONF_COLORS = {
  confirmed: 'var(--fl-danger)',
  high:      'var(--fl-warn)',
  medium:    'var(--fl-gold)',
  low:       'var(--fl-ok)',
};

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

export default function AttackPathD3({ svgRef: externalSvgRef, caseId, nodes, edges, phasesCovered, theme }) {
  const bgColor    = theme?.bg    || 'var(--fl-bg)';
  const panelColor = theme?.panel || 'var(--fl-panel)';
  const dimColor   = theme?.dim   || 'var(--fl-muted)';
  const inactiveColBg = theme?.mode === 'light' ? '#e8eef4' : 'var(--fl-bg)';
  const inactiveColHdr = theme?.mode === 'light' ? '#dce4ec' : '#1a2030';
  const inactiveColTxt = theme?.mode === 'light' ? '#8090a8' : '#3d4f6a';
  const emptyPrimary   = theme?.mode === 'light' ? '#90a0b8' : '#3d4f6a';
  const emptySecondary = theme?.mode === 'light' ? '#b0c0d0' : '#2a3a4a';
  const localSvgRef = useRef(null);
  const svgRef = externalSvgRef || localSvgRef;
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 1200, height: 700 });
  const [selectedNode, setSelectedNode] = useState(null);

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

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const containerWidth = dims.width;
    const containerHeight = dims.height;

    const COL_W = 160;
    const COL_H_HEADER = 48;
    const NODE_H = 52;
    const NODE_MARGIN = 8;
    const COL_GAP = 12;
    const PADDING_LEFT = 20;

    const tacticNodes = {};
    TACTIC_ORDER.forEach(t => { tacticNodes[t] = []; });
    const unknownNodes = [];
    for (const n of nodes) {
      if (n.tactic && tacticNodes[n.tactic] !== undefined) {
        tacticNodes[n.tactic].push(n);
      } else {
        unknownNodes.push(n);
      }
    }

    const maxNodesInCol = Math.max(1, ...Object.values(tacticNodes).map(arr => arr.length), unknownNodes.length);
    const svgHeight = Math.max(containerHeight, COL_H_HEADER + maxNodesInCol * (NODE_H + NODE_MARGIN) + 60);
    const svgWidth = Math.max(containerWidth, (COL_W + COL_GAP) * (TACTIC_ORDER.length + (unknownNodes.length > 0 ? 1 : 0)) + PADDING_LEFT * 2);

    svg.attr('viewBox', `0 0 ${svgWidth} ${svgHeight}`)
       .style('width', '100%').style('height', '100%');

    svg.append('rect').attr('width', svgWidth).attr('height', svgHeight).attr('fill', bgColor);

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.2, 3]).on('zoom', event => g.attr('transform', event.transform));
    svg.call(zoom);

    const nodePos = new Map();

    const allCols = [...TACTIC_ORDER, ...(unknownNodes.length > 0 ? ['Autres'] : [])];
    // Only draw the kill-chain scaffold when there's data — an empty grid of 14 hollow
    // columns reads as unfinished. The empty state is a clean HTML overlay instead.
    if (nodes.length > 0) allCols.forEach((tactic, colIdx) => {
      const colNodes = tactic === 'Autres' ? unknownNodes : (tacticNodes[tactic] || []);
      const color = TACTIC_COLORS[tactic] || 'var(--fl-muted)';
      const colX = PADDING_LEFT + colIdx * (COL_W + COL_GAP);
      const isActive = colNodes.length > 0;

      const colTotalH = COL_H_HEADER + colNodes.length * (NODE_H + NODE_MARGIN) + 20;
      g.append('rect')
        .attr('x', colX)
        .attr('y', 10)
        .attr('width', COL_W)
        .attr('height', Math.max(colTotalH, 80))
        .attr('rx', 6)
        .attr('fill', isActive ? `color-mix(in srgb, ${color} 3%, transparent)` : inactiveColBg)
        .attr('stroke', isActive ? `color-mix(in srgb, ${color} 19%, transparent)` : inactiveColHdr)
        .attr('stroke-width', 1);

      g.append('rect')
        .attr('x', colX)
        .attr('y', 10)
        .attr('width', COL_W)
        .attr('height', COL_H_HEADER)
        .attr('rx', 6)
        .attr('fill', isActive ? `color-mix(in srgb, ${color} 13%, transparent)` : inactiveColHdr);

      g.append('text')
        .attr('x', colX + COL_W / 2)
        .attr('y', 10 + COL_H_HEADER / 2)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('font-size', 9)
        .attr('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
        .attr('font-weight', isActive ? 700 : 400)
        .attr('fill', isActive ? color : inactiveColTxt)
        .text(tactic)
        .call(wrap, COL_W - 10);

      if (colNodes.length > 0) {
        g.append('circle')
          .attr('cx', colX + COL_W - 12)
          .attr('cy', 10 + 12)
          .attr('r', 9)
          .attr('fill', `color-mix(in srgb, ${color} 25%, transparent)`);
        g.append('text')
          .attr('x', colX + COL_W - 12)
          .attr('y', 10 + 12)
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'middle')
          .attr('font-size', 9)
          .attr('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
          .attr('fill', color)
          .text(colNodes.length);
      }

      colNodes.forEach((node, nodeIdx) => {
        const nx = colX + COL_W / 2;
        const ny = 10 + COL_H_HEADER + nodeIdx * (NODE_H + NODE_MARGIN) + NODE_H / 2 + NODE_MARGIN;
        nodePos.set(node.id, { x: nx, y: ny });

        const confColor = CONF_COLORS[node.confidence] || 'var(--fl-dim)';
        const nodeG = g.append('g')
          .style('cursor', 'pointer')
          .on('click', (event) => {
            event.stopPropagation();
            setSelectedNode(node);
          });

        if (node.type === 'bookmark') {

          const hex = d3.path();
          const r = 18;
          for (let k = 0; k < 6; k++) {
            const angle = (Math.PI / 3) * k - Math.PI / 6;
            if (k === 0) hex.moveTo(nx + r * Math.cos(angle), ny + r * Math.sin(angle));
            else hex.lineTo(nx + r * Math.cos(angle), ny + r * Math.sin(angle));
          }
          hex.closePath();
          nodeG.append('path').attr('d', hex).attr('fill', `color-mix(in srgb, ${color} 15%, transparent)`).attr('stroke', color).attr('stroke-width', 1.5);
        } else if (node.type === 'technique') {

          nodeG.append('polygon')
            .attr('points', `${nx},${ny - 18} ${nx + 14},${ny} ${nx},${ny + 18} ${nx - 14},${ny}`)
            .attr('fill', `color-mix(in srgb, ${color} 15%, transparent)`).attr('stroke', color).attr('stroke-width', 1.5);
        } else {

          nodeG.append('circle').attr('cx', nx).attr('cy', ny).attr('r', 16)
            .attr('fill', `color-mix(in srgb, ${color} 15%, transparent)`).attr('stroke', color).attr('stroke-width', 1.5);

          if (node.confidence === 'high' || node.confidence === 'confirmed') {
            nodeG.append('circle').attr('cx', nx).attr('cy', ny).attr('r', 22)
              .attr('fill', 'none').attr('stroke', `color-mix(in srgb, ${color} 25%, transparent)`).attr('stroke-width', 1);
          }
        }

        nodeG.append('circle')
          .attr('cx', nx + 12)
          .attr('cy', ny - 12)
          .attr('r', 4)
          .attr('fill', confColor);

        nodeG.append('text')
          .attr('x', nx)
          .attr('y', ny + 26)
          .attr('text-anchor', 'middle')
          .attr('font-size', 8)
          .attr('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
          .attr('fill', dimColor)
          .text((node.technique_id || '').toUpperCase());

        nodeG.append('title').text(`${node.technique_id || ''} — ${node.title}\nSource: ${node.source}\nConfiance: ${node.confidence}\n${node.timestamp ? fmtTs(node.timestamp) : ''}`);
      });
    });

    const edgeG = g.insert('g', ':first-child').attr('class', 'edges');
    for (const edge of edges) {
      const src = nodePos.get(edge.source);
      const dst = nodePos.get(edge.target);
      if (!src || !dst) continue;

      const midX = (src.x + dst.x) / 2;
      edgeG.append('path')
        .attr('d', `M${src.x},${src.y} C${midX},${src.y} ${midX},${dst.y} ${dst.x},${dst.y}`)
        .attr('fill', 'none')
        .attr('stroke', 'color-mix(in srgb, var(--fl-accent) 19%, transparent)')
        .attr('stroke-width', 1.5)
        .attr('marker-end', 'url(#arrow-dn)');
    }

    const markerDefs = svg.select('defs').empty() ? svg.append('defs') : svg.select('defs');
    markerDefs.append('marker')
      .attr('id', 'arrow-dn')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 10).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', 'color-mix(in srgb, var(--fl-accent) 38%, transparent)');

  }, [nodes, edges, dims]);

  return (
    <div ref={containerRef} style={{ display: 'flex', flex: 1, width: '100%', height: '100%', position: 'relative' }}>
      
      <div style={{
        position: 'absolute', bottom: 12, left: 12, zIndex: 20,
        display: 'flex', gap: 10, fontSize: 10, color: dimColor,
        background: panelColor + 'cc', padding: '5px 10px', borderRadius: 5,
        backdropFilter: 'blur(4px)',
      }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width="16" height="16" viewBox="0 0 16 16">
            <polygon points="8,2 14,8 8,14 2,8" fill="none" stroke="var(--fl-dim)" strokeWidth="1.5" />
          </svg> Technique manuelle
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width="16" height="16" viewBox="0 0 16 16">
            <path d="M8,2 L13.5,5 L13.5,11 L8,14 L2.5,11 L2.5,5 Z" fill="none" stroke="var(--fl-dim)" strokeWidth="1.5" />
          </svg> Bookmark
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width="16" height="16" viewBox="0 0 16 16">
            <circle cx="8" cy="8" r="6" fill="none" stroke="var(--fl-dim)" strokeWidth="1.5" />
          </svg> Detection Sigma
        </span>
        {phasesCovered.length > 0 && (
          <span style={{ color: 'var(--fl-ok)' }}>{phasesCovered.length} tactiques couvertes</span>
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
          <div style={{ textAlign: 'center', maxWidth: 360, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            <div style={{
              width: 44, height: 44, margin: '0 auto 14px', borderRadius: 12,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'var(--fl-raised)', border: '1px solid var(--fl-border)',
            }}>
              <GitBranch size={20} style={{ color: 'var(--fl-muted)' }} strokeWidth={1.5} />
            </div>
            <div style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 14, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 6, letterSpacing: '-0.01em' }}>
              Aucune donnée MITRE ATT&amp;CK
            </div>
            <div style={{ fontSize: 12, color: 'var(--fl-dim)', lineHeight: 1.5 }}>
              Ajoutez des techniques MITRE, des bookmarks ou lancez une chasse Sigma pour construire la kill chain
            </div>
          </div>
        </div>
      )}

      {selectedNode && (
        <div
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0, width: 280,
            background: panelColor, borderLeft: `1px solid ${theme?.border || 'var(--fl-border)'}`,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div style={{
            padding: '10px 14px', borderBottom: `1px solid ${theme?.border || 'var(--fl-border)'}`,
            display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: theme?.text || 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                {selectedNode.technique_id || '—'}
              </div>
              <div style={{ fontSize: 11, color: dimColor, marginTop: 2 }}>
                {selectedNode.title}
              </div>
            </div>
            <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: dimColor }}>
              <X size={14} />
            </button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
              {selectedNode.tactic && (
                <div>
                  <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Tactique</div>
                  <span style={{
                    padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                    background: `color-mix(in srgb, ${TACTIC_COLORS[selectedNode.tactic] || 'var(--fl-muted)'} 13%, transparent)`,
                    color: TACTIC_COLORS[selectedNode.tactic] || 'var(--fl-dim)',
                  }}>
                    {selectedNode.tactic}
                  </span>
                </div>
              )}

              <div>
                <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Source</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: theme?.text || 'var(--fl-text)' }}>
                  {selectedNode.source === 'bookmark' && <BookmarkIcon size={12} style={{ color: 'var(--fl-gold)' }} />}
                  {selectedNode.source === 'technique' && <Shield size={12} style={{ color: 'var(--fl-accent)' }} />}
                  {selectedNode.source === 'detection' && <Cpu size={12} style={{ color: 'var(--fl-purple)' }} />}
                  {selectedNode.source === 'bookmark' ? 'Bookmark Timeline' : selectedNode.source === 'technique' ? 'Technique manuelle' : 'Detection Sigma/Hayabusa'}
                </div>
                {selectedNode.rule_name && (
                  <div style={{ color: dimColor, fontSize: 10, marginTop: 2, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    Regle: {selectedNode.rule_name}
                  </div>
                )}
              </div>

              <div>
                <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Confiance</div>
                <span style={{
                  padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  background: `color-mix(in srgb, ${CONF_COLORS[selectedNode.confidence] || 'var(--fl-muted)'} 13%, transparent)`,
                  color: CONF_COLORS[selectedNode.confidence] || 'var(--fl-dim)',
                }}>
                  {selectedNode.confidence}
                </span>
              </div>

              {selectedNode.timestamp && (
                <div>
                  <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Horodatage</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: theme?.text || 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
                    <Clock size={11} style={{ color: dimColor }} /> {fmtTs(selectedNode.timestamp)}
                  </div>
                </div>
              )}

              {selectedNode.notes && (
                <div>
                  <div style={{ color: dimColor, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Notes</div>
                  <div style={{ color: dimColor, fontSize: 11, lineHeight: 1.4 }}>{selectedNode.notes}</div>
                </div>
              )}

              {selectedNode.artifact_ref && (
                <div>
                  <div style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>Artefact source</div>
                  <div style={{ color: 'var(--fl-accent)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{selectedNode.artifact_ref}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function wrap(text, width) {
  text.each(function() {
    const textEl = d3.select(this);
    const words = textEl.text().split(/\s+/).reverse();
    let word, line = [], lineNumber = 0;
    const lineHeight = 1.1;
    const y = textEl.attr('y');
    const x = textEl.attr('x');
    const dy = parseFloat(textEl.attr('dy') || 0);
    let tspan = textEl.text(null).append('tspan').attr('x', x).attr('y', y).attr('dy', `${dy}em`);

    while ((word = words.pop())) {
      line.push(word);
      tspan.text(line.join(' '));
      if (tspan.node().getComputedTextLength() > width) {
        line.pop();
        tspan.text(line.join(' '));
        line = [word];
        tspan = textEl.append('tspan').attr('x', x).attr('y', y).attr('dy', `${++lineNumber * lineHeight + dy}em`).text(word);
      }
    }
  });
}
