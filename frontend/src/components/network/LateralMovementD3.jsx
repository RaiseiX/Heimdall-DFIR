import { useState, useEffect, useRef, useCallback } from 'react';
import { X, AlertTriangle, Clock, User, ArrowRight, GitBranch } from 'lucide-react';
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

function effectiveScore(node) {
  return typeof node.score === 'number' ? node.score : riskScore(node);
}

function nodeColor(node) {
  const score = effectiveScore(node);
  if (score >= 80) return 'var(--fl-danger)';
  if (score >= 60) return 'var(--fl-warn)';
  if (score >= 40) return 'var(--fl-gold)';
  return 'var(--fl-accent)';
}

function nodeRiskLabel(node) {
  const score = effectiveScore(node);
  if (score >= 80) return { label: 'Critical pivot', color: 'var(--fl-danger)' };
  if (score >= 60) return { label: 'Source pivot', color: 'var(--fl-warn)' };
  if (score >= 40) return { label: 'Active', color: 'var(--fl-gold)' };
  return { label: 'Normal', color: 'var(--fl-accent)' };
}

function edgeColor(eventIds) {
  if (!eventIds || !eventIds.length) return 'color-mix(in srgb, var(--fl-accent) 31%, transparent)';
  if (eventIds.includes('4648')) return 'color-mix(in srgb, var(--fl-warn) 44%, transparent)';
  if (eventIds.includes('4768') || eventIds.includes('4769')) return 'color-mix(in srgb, var(--fl-purple) 44%, transparent)';
  if (eventIds.includes('NET:RDP') || eventIds.includes('NET:VNC')) return 'color-mix(in srgb, var(--fl-purple) 40%, transparent)';
  if (eventIds.includes('NET:SSH')) return 'color-mix(in srgb, var(--fl-warn) 40%, transparent)';
  if (eventIds.some((e) => typeof e === 'string' && e.startsWith('NET:'))) return 'color-mix(in srgb, var(--fl-accent) 38%, transparent)';
  return 'color-mix(in srgb, var(--fl-accent) 31%, transparent)';
}

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

function fmtDuration(from, to) {
  if (!from || !to) return null;
  const ms = new Date(to) - new Date(from);
  if (ms <= 0) return null;
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  if (h > 0) return `${h}h${m > 0 ? m + 'm' : ''}`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(ms / 1000)}s`;
}

const EVENT_LABELS = {
  '4624': '4624 Network logon',
  '4648': '4648 Explicit credentials',
  '4768': '4768 Kerberos TGT',
  '4769': '4769 Kerberos TGS',
  '4776': '4776 NTLM',
  '3':    'Sysmon 3 Network connection',
};

const BASE_LINK_OP = 0.5;

export default function LateralMovementD3({ svgRef: externalSvgRef, nodes, edges, totalEvents, chains = [], theme }) {
  const bgColor    = theme?.bg    || '#0d1117';
  const textColor  = '#ffffff';
  const dimColor   = theme?.dim   || '#484f58';
  const panelColor = 'var(--fl-panel)';
  const borderColor = 'var(--fl-border)';
  const gridColor  = theme?.mode === 'light' ? '#e8eef4' : '#161b22';
  const localSvgRef = useRef(null);
  const svgRef = externalSvgRef || localSvgRef;
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 800, height: 600 });
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedNodeEdges, setSelectedNodeEdges] = useState([]);

  // Chain panel state
  const [showChainsPanel, setShowChainsPanel] = useState(false);
  const [selectedChainIdx, setSelectedChainIdx] = useState(null);

  // Refs for imperative D3 highlighting from chain selection effect
  const nodeSelRef = useRef(null);
  const linkSelRef = useRef(null);
  const haloSelRef = useRef(null);
  const ringSelRef = useRef(null);
  const nameTextSelRef = useRef(null);
  const isLabeledRef = useRef(() => false);

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

  const sortedNodes = [...nodes].sort((a, b) => effectiveScore(b) - effectiveScore(a));

  // ── Chain highlight effect: runs when selected chain changes, mutates D3 DOM directly ──
  useEffect(() => {
    const node = nodeSelRef.current;
    const link = linkSelRef.current;
    const halo = haloSelRef.current;
    const ring = ringSelRef.current;
    const nameText = nameTextSelRef.current;
    if (!node) return;

    if (selectedChainIdx === null || !chains?.[selectedChainIdx]) {
      node.interrupt().transition().duration(140).attr('opacity', 1);
      if (halo) halo.interrupt().transition().duration(140).attr('opacity', 1);
      if (ring) ring.interrupt().transition().duration(140).attr('opacity', 0.7);
      if (nameText) nameText.interrupt().transition().duration(140).attr('opacity', d => isLabeledRef.current(d) ? 1 : 0);
      link.interrupt().transition().duration(140).attr('opacity', BASE_LINK_OP);
    } else {
      const chainNodes = new Set(chains[selectedChainIdx].path);
      node.interrupt().transition().duration(140).attr('opacity', d => chainNodes.has(d.id) ? 1 : 0.06);
      if (halo) halo.interrupt().transition().duration(140).attr('opacity', d => chainNodes.has(d.id) ? 1 : 0.06);
      if (ring) ring.interrupt().transition().duration(140).attr('opacity', d => chainNodes.has(d.id) ? 0.7 : 0.03);
      if (nameText) nameText.interrupt().transition().duration(140).attr('opacity', d => chainNodes.has(d.id) ? 1 : 0);
      link.interrupt().transition().duration(140).attr('opacity', l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return chainNodes.has(s) && chainNodes.has(t) ? 0.95 : 0.03;
      });
    }
  }, [selectedChainIdx, chains]);

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = dims.width;
    const height = dims.height;

    const nodesCopy = nodes.map(n => ({ ...n, _score: effectiveScore(n) }));
    const nodeById = new Map(nodesCopy.map(n => [n.id, n]));

    const linksCopy = edges
      .map(e => ({
        ...e,
        source: typeof e.source === 'object' ? e.source.id : e.source,
        target: typeof e.target === 'object' ? e.target.id : e.target,
      }))
      .filter(e => nodeById.has(e.source) && nodeById.has(e.target));

    const bg = svg.append('rect').attr('width', width).attr('height', height).attr('fill', bgColor).style('cursor', 'default');

    const defs = svg.append('defs');
    const vig = defs.append('radialGradient').attr('id', 'lm-vignette').attr('cx', '50%').attr('cy', '45%').attr('r', '72%');
    vig.append('stop').attr('offset', '55%').attr('stop-color', '#000').attr('stop-opacity', 0);
    vig.append('stop').attr('offset', '100%').attr('stop-color', '#000').attr('stop-opacity', theme?.mode === 'light' ? 0.05 : 0.5);
    svg.append('rect').attr('width', width).attr('height', height).attr('fill', 'url(#lm-vignette)').style('pointer-events', 'none');

    const glow = defs.append('filter').attr('id', 'lm-glow').attr('x', '-80%').attr('y', '-80%').attr('width', '260%').attr('height', '260%');
    glow.append('feGaussianBlur').attr('stdDeviation', 5).attr('result', 'b');
    const gmerge = glow.append('feMerge'); gmerge.append('feMergeNode').attr('in', 'b'); gmerge.append('feMergeNode').attr('in', 'SourceGraphic');

    ['normal', 'explicit', 'kerberos'].forEach(type => {
      const colors = { normal: 'var(--fl-accent)', explicit: 'var(--fl-warn)', kerberos: 'var(--fl-purple)' };
      defs.append('marker')
        .attr('id', `arrow-${type}`).attr('viewBox', '0 -5 10 10')
        .attr('refX', 15).attr('refY', 0).attr('markerWidth', 4.5).attr('markerHeight', 4.5).attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', `color-mix(in srgb, ${colors[type]} 55%, transparent)`);
    });

    const degree = new Map();
    const neighbors = new Map();
    nodesCopy.forEach(n => neighbors.set(n.id, new Set()));
    linksCopy.forEach(l => {
      degree.set(l.source, (degree.get(l.source) || 0) + 1);
      degree.set(l.target, (degree.get(l.target) || 0) + 1);
      neighbors.get(l.source)?.add(l.target);
      neighbors.get(l.target)?.add(l.source);
    });
    const sortedDeg = [...degree.values()].sort((a, b) => b - a);
    const hubCut = sortedDeg.length ? sortedDeg[Math.floor(sortedDeg.length * 0.12)] : 0;
    const deg = id => degree.get(id) || 0;
    const rOf = d => 8 + Math.min(16, Math.sqrt(d.total_events || 1) * 1.7);
    const isLabeled = d => d._score >= 40 || deg(d.id) >= Math.max(5, hubCut);
    isLabeledRef.current = isLabeled;

    const simulation = d3.forceSimulation(nodesCopy)
      .force('link', d3.forceLink(linksCopy).id(d => d.id).distance(d => 100 + Math.sqrt(d.count || 1) * 9))
      .force('charge', d3.forceManyBody().strength(d => -520 - d._score * 4))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => rOf(d) + 16));

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', event => g.attr('transform', event.transform));
    svg.call(zoom).on('dblclick.zoom', null);

    const getMarker = (e) => {
      const ids = e.event_ids || [];
      if (ids.includes('4648')) return 'url(#arrow-explicit)';
      if (ids.includes('4768') || ids.includes('4769')) return 'url(#arrow-kerberos)';
      if (ids.includes('NET:RDP') || ids.includes('NET:VNC')) return 'url(#arrow-kerberos)';
      return 'url(#arrow-normal)';
    };

    const link = g.append('g').selectAll('line').data(linksCopy).join('line')
      .attr('stroke', d => edgeColor(d.event_ids))
      .attr('stroke-width', d => Math.max(1, Math.min(5, Math.log2((d.count || 1) + 1) * 1.1)))
      .attr('stroke-linecap', 'round')
      .attr('stroke-dasharray', d => d.origin === 'network' ? '2,5' : null)
      .attr('marker-end', d => getMarker(d))
      .attr('opacity', BASE_LINK_OP)
      .style('cursor', 'default');

    const linkLabel = g.append('g').selectAll('text').data(linksCopy).join('text')
      .text(d => d.count > 1 ? d.count : '')
      .attr('fill', dimColor).attr('font-size', 9)
      .style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('text-anchor', 'middle').attr('opacity', 0).style('pointer-events', 'none');

    const halo = g.append('g').selectAll('circle').data(nodesCopy.filter(n => n._score >= 80)).join('circle')
      .attr('r', d => rOf(d) + 7)
      .attr('fill', d => `color-mix(in srgb, ${nodeColor(d)} 26%, transparent)`)
      .attr('filter', 'url(#lm-glow)')
      .style('pointer-events', 'none');

    const node = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', rOf)
      .attr('fill', d => `color-mix(in srgb, ${nodeColor(d)} ${d._score >= 40 ? 24 : 13}%, transparent)`)
      .attr('stroke', d => nodeColor(d))
      .attr('stroke-width', d => d._score >= 80 ? 2.5 : d._score >= 60 ? 2 : 1.25)
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
        // Clear chain highlight when a node is selected
        setSelectedChainIdx(null);
        focusLock = d.id; applyFocus(d.id);
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    const ring = g.append('g').selectAll('circle').data(nodesCopy.filter(n => n._score >= 60)).join('circle')
      .attr('r', d => rOf(d) + 4)
      .attr('fill', 'none')
      .attr('stroke', d => nodeColor(d))
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '2,3')
      .attr('opacity', 0.7)
      .style('pointer-events', 'none');

    const nameText = g.append('g').selectAll('text').data(nodesCopy).join('text')
      .text(d => d.id.length > 20 ? d.id.slice(0, 18) + '…' : d.id)
      .attr('fill', textColor).attr('font-size', 9.5).attr('font-weight', d => d._score >= 60 ? 600 : 400)
      .style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('text-anchor', 'middle').attr('dy', d => -(rOf(d) + 7))
      .attr('opacity', d => isLabeled(d) ? 1 : 0)
      .style('pointer-events', 'none');

    node.append('title').text(d =>
      `${d.id}\nTotal: ${d.total_events} events | Outbound: ${d.as_source} | Inbound: ${d.as_target}\nRisk: ${nodeRiskLabel(d).label}`
    );

    // Save selections for chain highlight effect (imperative bridge)
    nodeSelRef.current = node;
    linkSelRef.current = link;
    haloSelRef.current = halo;
    ringSelRef.current = ring;
    nameTextSelRef.current = nameText;

    let focusLock = null;
    function applyFocus(id) {
      const nb = neighbors.get(id) || new Set();
      const lit = n => n.id === id || nb.has(n.id);
      node.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 1 : 0.07);
      halo.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 1 : 0.07);
      ring.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 0.7 : 0.05);
      nameText.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 1 : 0);
      link.interrupt().transition().duration(140)
        .attr('opacity', l => (l.source.id === id || l.target.id === id) ? 0.95 : 0.03);
      linkLabel.interrupt().transition().duration(140)
        .attr('opacity', l => (l.source.id === id || l.target.id === id) ? 1 : 0);
    }
    function clearFocus() {
      node.interrupt().transition().duration(140).attr('opacity', 1);
      halo.interrupt().transition().duration(140).attr('opacity', 1);
      ring.interrupt().transition().duration(140).attr('opacity', 0.7);
      nameText.interrupt().transition().duration(140).attr('opacity', d => isLabeled(d) ? 1 : 0);
      link.interrupt().transition().duration(140).attr('opacity', BASE_LINK_OP);
      linkLabel.interrupt().transition().duration(140).attr('opacity', 0);
    }
    node.on('mouseover', (e, d) => { if (!focusLock) applyFocus(d.id); })
        .on('mouseout', () => { if (!focusLock) clearFocus(); });
    bg.on('click', () => { focusLock = null; clearFocus(); setSelectedNode(null); setSelectedChainIdx(null); });

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 5);
      halo.attr('cx', d => d.x).attr('cy', d => d.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      ring.attr('cx', d => d.x).attr('cy', d => d.y);
      nameText.attr('x', d => d.x).attr('y', d => d.y);
    });

    const fitView = () => {
      if (!nodesCopy.length) return;
      const xs = nodesCopy.map(n => n.x), ys = nodesCopy.map(n => n.y);
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys);
      const gw = (maxX - minX) || 1, gh = (maxY - minY) || 1;
      const padX = 280, padY = 140;
      const scale = Math.max(0.3, Math.min(1.8,
        Math.min((width - padX) / gw, (height - padY) / gh)));
      const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
      const t = d3.zoomIdentity
        .translate(width / 2 - scale * cx, height / 2 - scale * cy)
        .scale(scale);
      svg.transition().duration(450).call(zoom.transform, t);
    };
    simulation.on('end', fitView);
    const fitTimer = setTimeout(fitView, 1200);

    return () => { clearTimeout(fitTimer); simulation.stop(); };
  }, [nodes, edges, dims]);

  // Sort chains: longest first, then by total hop count (more events = more significant)
  const sortedChains = [...chains].sort((a, b) => {
    if (b.path.length !== a.path.length) return b.path.length - a.path.length;
    return b.timestamps.length - a.timestamps.length;
  });

  const showRightPanel = selectedNode !== null || (showChainsPanel && chains.length > 0);

  return (
    <div ref={containerRef} style={{ display: 'flex', flex: 1, width: '100%', height: '100%', position: 'relative' }}>

      {/* ── Left overlay: legend + stats + risky machines ── */}
      <div style={{
        position: 'absolute', top: 12, left: 12, zIndex: 20,
        display: 'flex', flexDirection: 'column', gap: 8,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      }}>

        <div style={{
          background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
          boxShadow: 'var(--fl-shadow-lg)',
          padding: '11px 13px', fontSize: 10.5, display: 'flex', flexDirection: 'column', gap: 6,
        }}>
          <div style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 1 }}>Node risk</div>
          {[
            ['var(--fl-danger)', 'Critical pivot (≥80)'],
            ['var(--fl-warn)', 'Source pivot (≥60)'],
            ['var(--fl-gold)', 'Active (≥40)'],
            ['var(--fl-accent)', 'Normal'],
          ].map(([color, label]) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--fl-dim)' }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
              {label}
            </span>
          ))}
          <div style={{ height: 1, background: 'var(--fl-border)', margin: '4px 0' }} />
          <div style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 1 }}>Edges</div>
          {[
            ['var(--fl-accent)', '4624 Network logon', false],
            ['var(--fl-warn)', '4648 Explicit credentials', false],
            ['var(--fl-purple)', '4768/4769 Kerberos', false],
            ['var(--fl-accent)', 'Flux réseau (SMB/RDP/SSH…)', true],
          ].map(([color, label, dashed]) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--fl-dim)' }}>
              <span style={{
                width: 16, height: 0, borderTop: `2px ${dashed ? 'dashed' : 'solid'} ${color}`,
                flexShrink: 0,
              }} />
              {label}
            </span>
          ))}
        </div>

        {nodes.length > 0 && (
          <div style={{
            background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
            boxShadow: 'var(--fl-shadow-lg)',
            padding: '7px 12px', fontSize: 10.5, color: 'var(--fl-dim)',
            display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          }}>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{nodes.length}</strong> machines
            <span style={{ color: 'var(--fl-subtle)' }}>·</span>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{edges.length}</strong> chemins
            <span style={{ color: 'var(--fl-subtle)' }}>·</span>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{totalEvents}</strong> events
          </div>
        )}

        {sortedNodes.slice(0, 3).filter(n => effectiveScore(n) >= 40).length > 0 && (
          <div style={{
            background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
            boxShadow: 'var(--fl-shadow-lg)',
            padding: '11px 13px', fontSize: 10.5, maxWidth: 220,
          }}>
            <div style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 7 }}>Risky machines</div>
            {sortedNodes.slice(0, 3).filter(n => effectiveScore(n) >= 40).map(n => {
              const { label, color } = nodeRiskLabel(n);
              return (
                <div key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2, background: color, flexShrink: 0 }} />
                  <span style={{ color: 'var(--fl-text)', fontSize: 10, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {n.id}
                  </span>
                  <span style={{ color, fontSize: 9, fontWeight: 600 }}>{label}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Chains toggle button (top-right, only when chains exist) ── */}
      {chains.length > 0 && (
        <button
          onClick={() => {
            setShowChainsPanel(v => !v);
            setSelectedChainIdx(null);
            setSelectedNode(null);
          }}
          style={{
            position: 'absolute', top: 12, right: 12, zIndex: 21,
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
            fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
            border: showChainsPanel
              ? '1px solid color-mix(in srgb, var(--fl-warn) 50%, transparent)'
              : '1px solid var(--fl-border)',
            background: showChainsPanel
              ? 'color-mix(in srgb, var(--fl-warn) 10%, var(--fl-panel))'
              : 'var(--fl-panel)',
            color: showChainsPanel ? 'var(--fl-warn)' : 'var(--fl-dim)',
            boxShadow: 'var(--fl-shadow-lg)',
            transition: 'all 0.15s',
          }}
        >
          <GitBranch size={12} />
          Propagation chains
          <span style={{
            padding: '1px 6px', borderRadius: 10, fontSize: 9, fontWeight: 700,
            background: showChainsPanel
              ? 'color-mix(in srgb, var(--fl-warn) 18%, transparent)'
              : 'color-mix(in srgb, var(--fl-accent) 14%, transparent)',
            color: showChainsPanel ? 'var(--fl-warn)' : 'var(--fl-accent)',
          }}>{chains.length}</span>
        </button>
      )}

      <svg
        ref={svgRef}
        width={dims.width}
        height={dims.height}
        style={{ display: 'block' }}
        onClick={() => { setSelectedNode(null); setSelectedChainIdx(null); }}
      />

      {nodes.length === 0 && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <div style={{ textAlign: 'center', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            <div style={{ fontSize: 13, marginBottom: 5, color: 'var(--fl-text)', fontWeight: 600 }}>No lateral movement data</div>
            <div style={{ fontSize: 11, color: 'var(--fl-muted)' }}>Parse EVTX (Security) logs containing events 4624, 4648, 4768, 4769</div>
          </div>
        </div>
      )}

      {/* ── Right panel: node detail takes priority over chains panel ── */}
      {showRightPanel && (
        <div
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0, width: 'clamp(300px, 24vw, 400px)',
            background: panelColor, borderLeft: `1px solid ${borderColor}`,
            boxShadow: 'var(--fl-shadow-lg)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
          onClick={e => e.stopPropagation()}
        >
          {selectedNode ? (
            /* ── Node detail panel ── */
            <>
              <div style={{ padding: '10px 14px', borderBottom: `1px solid ${borderColor}`, flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: textColor, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginBottom: 2 }}>
                      {selectedNode.id}
                    </div>
                    {(() => {
                      const { label, color } = nodeRiskLabel(selectedNode);
                      return (
                        <span style={{
                          padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                          background: `color-mix(in srgb, ${color} 13%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)`,
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
                    ['Outbound →', selectedNode.as_source, 'var(--fl-warn)'],
                    ['Inbound ←', selectedNode.as_target, 'var(--fl-accent)'],
                  ].map(([label, val, color]) => (
                    <div key={label} style={{ background: bgColor, borderRadius: 4, padding: '6px 8px', border: `1px solid ${borderColor}`, textAlign: 'center' }}>
                      <div style={{ fontSize: 16, fontWeight: 700, color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{val}</div>
                      <div style={{ fontSize: 9, color: dimColor }}>{label}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto', padding: '10px 14px' }}>
                {selectedNode?.factors?.length > 0 && (
                  <div style={{ marginBottom: 12, padding: '8px 10px', borderRadius: 4, background: bgColor, border: `1px solid ${borderColor}` }}>
                    <div style={{ fontSize: 11, color: dimColor, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Pourquoi ce score
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 16 }}>
                      {selectedNode.factors.map((f, i) => (
                        <li key={i} style={{ fontSize: 12, color: 'var(--fl-text)' }}>{f}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div style={{ fontSize: 11, color: dimColor, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Connections ({selectedNodeEdges.length})
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
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                        <span style={{ color: isOutgoing ? 'var(--fl-warn)' : 'var(--fl-accent)', fontSize: 10 }}>
                          {isOutgoing ? '→' : '←'}
                        </span>
                        <span style={{ color: textColor, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {isOutgoing ? dst : src}
                        </span>
                        <span style={{
                          padding: '1px 5px', borderRadius: 3, fontSize: 9,
                          background: 'color-mix(in srgb, var(--fl-accent) 13%, transparent)', color: 'var(--fl-accent)',
                        }}>x{edge.count}</span>
                      </div>

                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                        {(edge.event_ids || []).map(eid => (
                          <span key={eid} style={{
                            padding: '1px 5px', borderRadius: 3, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                            background: eid === '4648' ? 'color-mix(in srgb, var(--fl-warn) 13%, transparent)' : eid === '4768' || eid === '4769' ? 'color-mix(in srgb, var(--fl-purple) 13%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 13%, transparent)',
                            color: eid === '4648' ? 'var(--fl-warn)' : eid === '4768' || eid === '4769' ? 'var(--fl-purple)' : 'var(--fl-accent)',
                          }}>{EVENT_LABELS[eid] || `Event ${eid}`}</span>
                        ))}
                      </div>

                      {edge.usernames?.length > 0 && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: dimColor, fontSize: 10 }}>
                          <User size={10} />
                          {edge.usernames.slice(0, 3).join(', ')}{edge.usernames.length > 3 ? ` +${edge.usernames.length - 3}` : ''}
                        </div>
                      )}

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 3, color: dimColor, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
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
            </>
          ) : (
            /* ── Chains panel ── */
            <>
              <div style={{
                padding: '10px 14px', borderBottom: `1px solid ${borderColor}`, flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              }}>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginBottom: 2 }}>
                    Propagation chains
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--fl-muted)' }}>
                    {chains.length} chaîne{chains.length > 1 ? 's' : ''} · cliquer pour highlight
                  </div>
                </div>
                <button
                  onClick={() => { setShowChainsPanel(false); setSelectedChainIdx(null); }}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: dimColor }}
                >
                  <X size={14} />
                </button>
              </div>

              <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px' }}>
                {sortedChains.map((chain, idx) => {
                  const originalIdx = chains.indexOf(chain);
                  const isSelected = selectedChainIdx === originalIdx;
                  const depth = chain.path.length - 1;
                  const first = chain.timestamps[0];
                  const last = chain.timestamps[chain.timestamps.length - 1];
                  const dur = fmtDuration(first, last);

                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedChainIdx(isSelected ? null : originalIdx)}
                      style={{
                        marginBottom: 7, padding: '9px 11px', borderRadius: 6,
                        border: isSelected
                          ? '1px solid color-mix(in srgb, var(--fl-warn) 55%, transparent)'
                          : `1px solid ${borderColor}`,
                        background: isSelected
                          ? 'color-mix(in srgb, var(--fl-warn) 6%, var(--fl-bg))'
                          : bgColor,
                        cursor: 'pointer', transition: 'all 0.12s',
                      }}
                    >
                      {/* Hop path */}
                      <div style={{
                        display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 3,
                        marginBottom: 6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      }}>
                        {chain.path.map((node, ni) => (
                          <span key={ni} style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                            <span style={{
                              padding: '1px 6px', borderRadius: 3, fontSize: 9.5, fontWeight: ni === 0 ? 700 : 400,
                              background: ni === 0
                                ? 'color-mix(in srgb, var(--fl-danger) 14%, transparent)'
                                : 'color-mix(in srgb, var(--fl-accent) 10%, transparent)',
                              color: ni === 0 ? 'var(--fl-danger)' : 'var(--fl-accent)',
                              border: `1px solid ${ni === 0 ? 'color-mix(in srgb, var(--fl-danger) 22%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 16%, transparent)'}`,
                              maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }} title={node}>{node}</span>
                            {ni < chain.path.length - 1 && (
                              <span style={{ color: 'var(--fl-muted)', fontSize: 9 }}>→</span>
                            )}
                          </span>
                        ))}
                      </div>

                      {/* Meta row */}
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9,
                        color: 'var(--fl-muted)',
                      }}>
                        <span style={{
                          padding: '0 5px', borderRadius: 3, fontSize: 9, fontWeight: 600,
                          background: 'color-mix(in srgb, var(--fl-purple) 12%, transparent)',
                          color: 'var(--fl-purple)',
                        }}>{depth} hop{depth > 1 ? 's' : ''}</span>

                        {first && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Clock size={8} /> {fmtTs(first)}
                          </span>
                        )}

                        {dur && (
                          <span style={{
                            padding: '0 5px', borderRadius: 3, fontSize: 9,
                            background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)',
                            color: 'var(--fl-dim)',
                          }}>{dur}</span>
                        )}
                      </div>

                      {/* Entry point label */}
                      {chain.entryPoint && (
                        <div style={{ marginTop: 4, fontSize: 9, color: 'var(--fl-muted)' }}>
                          Entry: <span style={{ color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{chain.entryPoint}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
