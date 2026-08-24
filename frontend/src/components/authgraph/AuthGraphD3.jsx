// frontend/src/components/authgraph/AuthGraphD3.jsx
// LogonTracer-style bipartite graph: users (left column) ↔ machines (right
// column), edges colored by dominant logon type, failed logons in red.
import { useState, useEffect, useRef } from 'react';
import { X, Clock, User, Monitor, ArrowRight, AlertTriangle } from 'lucide-react';
import * as d3 from 'd3';

// LogonType code → color/label (Windows + Linux categories)
const LOGON_STYLES = {
  '2':      { color: 'var(--fl-ok)',     label: '2 · Interactif' },
  '3':      { color: 'var(--fl-accent)', label: '3 · Réseau' },
  '4':      { color: 'var(--fl-purple)', label: '4 · Batch' },
  '5':      { color: 'var(--fl-gold)',   label: '5 · Service' },
  '7':      { color: 'var(--fl-accent)', label: '7 · Déverrouillage' },
  '8':      { color: 'var(--fl-purple)', label: '8 · Réseau clair' },
  '9':      { color: 'var(--fl-purple)', label: '9 · Nouvelles identifiants' },
  '10':     { color: 'var(--fl-warn)',   label: '10 · RDP / Remote' },
  '11':     { color: 'var(--fl-muted)',  label: '11 · Cache' },
  'ssh_login':   { color: 'var(--fl-ok)',     label: 'SSH login' },
  'ssh_failed':  { color: 'var(--fl-danger)', label: 'SSH échec' },
  'ssh_invalid': { color: 'var(--fl-danger)', label: 'SSH user invalide' },
  'su':          { color: 'var(--fl-gold)',   label: 'su' },
  'sudo':        { color: 'var(--fl-warn)',   label: 'sudo' },
  'logon':       { color: 'var(--fl-ok)',     label: 'Logon (last)' },
  'system_event':{ color: 'var(--fl-muted)',  label: 'System event' },
  'unknown':     { color: 'var(--fl-muted)',  label: 'Inconnu' },
};

function logonStyle(lt) {
  return LOGON_STYLES[lt] || LOGON_STYLES.unknown;
}

// Dominant logon type of an edge (by count)
function dominantLogonType(edge) {
  const types = edge.logon_types || {};
  let best = null, bestCount = -1;
  for (const [t, c] of Object.entries(types)) {
    if (c > bestCount) { best = t; bestCount = c; }
  }
  return best || 'unknown';
}

function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

const BASE_LINK_OP = 0.45;

export default function AuthGraphD3({ nodes, edges, stats, theme, onSelectNode, onSelectEdge }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 900, height: 600 });
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

    const width = dims.width;
    const height = dims.height;
    const bgColor = theme?.bg || 'var(--fl-bg)';
    const textColor = 'var(--fl-text)';
    const dimColor = theme?.dim || 'var(--fl-dim)';

    const nodesCopy = nodes.map(n => ({ ...n }));
    const nodeById = new Map(nodesCopy.map(n => [n.id, n]));

    const linksCopy = edges
      .map(e => ({ ...e, source: e.source, target: e.target }))
      .filter(e => nodeById.has(e.source) && nodeById.has(e.target));

    const bg = svg.append('rect').attr('width', width).attr('height', height).attr('fill', bgColor).style('cursor', 'default');

    // Bipartite layout: users fixed to left column, machines to right column.
    const colX = (d) => (d.kind === 'user' ? width * 0.22 : width * 0.78);

    const rOf = d => 9 + Math.min(20, Math.sqrt(d.total_events || 1) * 1.6);

    const simulation = d3.forceSimulation(nodesCopy)
      .force('x', d3.forceX(d => colX(d)).strength(0.55))
      .force('y', d3.forceY(height / 2).strength(0.08))
      .force('link', d3.forceLink(linksCopy).id(d => d.id).distance(d => 150 + Math.sqrt(d.count || 1) * 6).strength(0.18))
      .force('charge', d3.forceManyBody().strength(d => (d.kind === 'user' ? -260 : -320)))
      .force('collision', d3.forceCollide().radius(d => rOf(d) + 18))
      .force('center', d3.forceCenter(width / 2, height / 2));

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.15, 5]).on('zoom', event => g.attr('transform', event.transform));
    svg.call(zoom).on('dblclick.zoom', null);

    const getEdgeColor = (e) => {
      const st = logonStyle(dominantLogonType(e));
      // Failed-heavy edges are red regardless of the dominant type
      if (e.failed > 0 && e.failed >= (e.success || 0)) return 'var(--fl-danger)';
      return st.color;
    };

    const link = g.append('g').selectAll('line').data(linksCopy).join('line')
      .attr('stroke', getEdgeColor)
      .attr('stroke-width', d => Math.max(1, Math.min(5, Math.log2((d.count || 1) + 1) * 1.05)))
      .attr('stroke-linecap', 'round')
      .attr('stroke-dasharray', d => (d.failed > 0 && d.failed >= (d.success || 0)) ? '4,4' : null)
      .attr('opacity', BASE_LINK_OP)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(null);
        onSelectEdge?.(d);
      });

    const linkLabel = g.append('g').selectAll('text').data(linksCopy).join('text')
      .text(d => d.count > 1 ? d.count : '')
      .attr('fill', dimColor).attr('font-size', 9)
      .style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('text-anchor', 'middle').attr('opacity', 0).style('pointer-events', 'none');

    // Column separators + labels
    g.append('line').attr('x1', width * 0.22).attr('y1', 0).attr('x2', width * 0.22).attr('y2', height)
      .attr('stroke', 'var(--fl-border)').attr('stroke-dasharray', '2,4').attr('opacity', 0.35).style('pointer-events', 'none');
    g.append('line').attr('x1', width * 0.78).attr('y1', 0).attr('x2', width * 0.78).attr('y2', height)
      .attr('stroke', 'var(--fl-border)').attr('stroke-dasharray', '2,4').attr('opacity', 0.35).style('pointer-events', 'none');
    g.append('text').text('UTILISATEURS').attr('x', width * 0.22).attr('y', 18).attr('text-anchor', 'middle')
      .attr('fill', 'var(--fl-muted)').attr('font-size', 9).style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('letter-spacing', '0.12em').style('pointer-events', 'none');
    g.append('text').text('MACHINES').attr('x', width * 0.78).attr('y', 18).attr('text-anchor', 'middle')
      .attr('fill', 'var(--fl-muted)').attr('font-size', 9).style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('letter-spacing', '0.12em').style('pointer-events', 'none');

    const nodeColor = d => (d.kind === 'user' ? 'var(--fl-purple)' : 'var(--fl-accent)');
    const node = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', rOf)
      .attr('fill', d => (d.failed >= d.success && d.failed > 0)
        ? 'color-mix(in srgb, var(--fl-danger) 30%, transparent)'
        : `color-mix(in srgb, ${nodeColor(d)} ${d.total_events > 100 ? 28 : 15}%, transparent)`)
      .attr('stroke', d => (d.failed >= d.success && d.failed > 0) ? 'var(--fl-danger)' : nodeColor(d))
      .attr('stroke-width', d => d.total_events > 1000 ? 2.5 : 1.25)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(d);
        onSelectNode?.(d);
        onSelectEdge?.(null);
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    const nameText = g.append('g').selectAll('text').data(nodesCopy).join('text')
      .text(d => d.name.length > 26 ? d.name.slice(0, 24) + '…' : d.name)
      .attr('fill', textColor).attr('font-size', 9.5).attr('font-weight', 500)
      .style('font-family', 'var(--f-mono, "JetBrains Mono", monospace)')
      .attr('text-anchor', 'middle').attr('dy', d => -(rOf(d) + 7))
      .attr('opacity', 1)
      .style('pointer-events', 'none');

    node.append('title').text(d =>
      `${d.name}\nTotal: ${d.total_events} | OK: ${d.success} | Échecs: ${d.failed}\n${d.degree} ${d.kind === 'user' ? 'machines' : 'utilisateurs'}`
    );

    let focusLock = null;
    const neighbors = new Map();
    nodesCopy.forEach(n => neighbors.set(n.id, new Set()));
    linksCopy.forEach(l => {
      neighbors.get(l.source)?.add(l.target);
      neighbors.get(l.target)?.add(l.source);
    });
    function applyFocus(id) {
      const nb = neighbors.get(id) || new Set();
      const lit = n => n.id === id || nb.has(n.id);
      node.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 1 : 0.07);
      nameText.interrupt().transition().duration(140).attr('opacity', n => lit(n) ? 1 : 0.06);
      link.interrupt().transition().duration(140)
        .attr('opacity', l => (l.source.id === id || l.target.id === id) ? 0.95 : 0.03);
      linkLabel.interrupt().transition().duration(140)
        .attr('opacity', l => (l.source.id === id || l.target.id === id) ? 1 : 0);
    }
    function clearFocus() {
      node.interrupt().transition().duration(140).attr('opacity', 1);
      nameText.interrupt().transition().duration(140).attr('opacity', 1);
      link.interrupt().transition().duration(140).attr('opacity', BASE_LINK_OP);
      linkLabel.interrupt().transition().duration(140).attr('opacity', 0);
    }
    node.on('mouseover', (e, d) => { if (!focusLock) applyFocus(d.id); })
        .on('mouseout', () => { if (!focusLock) clearFocus(); });
    bg.on('click', () => { focusLock = null; clearFocus(); setSelectedNode(null); onSelectNode?.(null); onSelectEdge?.(null); });

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 5);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      nameText.attr('x', d => d.x).attr('y', d => d.y);
    });

    const fitView = () => {
      if (!nodesCopy.length) return;
      const xs = nodesCopy.map(n => n.x), ys = nodesCopy.map(n => n.y);
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys);
      const gw = (maxX - minX) || 1, gh = (maxY - minY) || 1;
      const padX = 260, padY = 120;
      const scale = Math.max(0.3, Math.min(1.8, Math.min((width - padX) / gw, (height - padY) / gh)));
      const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
      const t = d3.zoomIdentity.translate(width / 2 - scale * cx, height / 2 - scale * cy).scale(scale);
      svg.transition().duration(450).call(zoom.transform, t);
    };
    simulation.on('end', fitView);
    const fitTimer = setTimeout(fitView, 1200);

    return () => { clearTimeout(fitTimer); simulation.stop(); };
  }, [nodes, edges, dims]);

  // ── Selected node detail ────────────────────────────────────────────────
  const selEdges = selectedNode
    ? edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
    : [];

  return (
    <div ref={containerRef} style={{ display: 'flex', flex: 1, width: '100%', height: '100%', position: 'relative' }}>

      {/* ── Legend overlay (top-left) ── */}
      <div style={{
        position: 'absolute', top: 12, left: 12, zIndex: 20,
        display: 'flex', flexDirection: 'column', gap: 8,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      }}>
        <div style={{
          background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
          boxShadow: 'var(--fl-shadow-lg)', padding: '11px 13px', fontSize: 10.5,
          display: 'flex', flexDirection: 'column', gap: 6, maxWidth: 230,
        }}>
          <div style={{ color: 'var(--fl-muted)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 1 }}>
            Types de logon
          </div>
          {Object.entries(LOGON_STYLES).filter(([k]) => !['unknown', 'logon', 'system_event', 'su', 'sudo', 'ssh_login', 'ssh_failed', 'ssh_invalid'].includes(k)).map(([k, st]) => (
            <span key={k} style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--fl-dim)' }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: st.color, flexShrink: 0 }} />
              {st.label}
            </span>
          ))}
          <div style={{ height: 1, background: 'var(--fl-border)', margin: '3px 0' }} />
          <span style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--fl-danger)' }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--fl-danger)', flexShrink: 0 }} />
            Échec de logon (4625 / SSH)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--fl-dim)' }}>
            <span style={{ width: 14, height: 0, borderTop: '2px dashed var(--fl-danger)', flexShrink: 0 }} />
            Lien dominé par les échecs
          </span>
        </div>

        {stats && (
          <div style={{
            background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
            boxShadow: 'var(--fl-shadow-lg)', padding: '7px 12px', fontSize: 10.5, color: 'var(--fl-dim)',
            display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          }}>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{stats.users}</strong> users
            <span style={{ color: 'var(--fl-subtle)' }}>·</span>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{stats.machines}</strong> machines
            <span style={{ color: 'var(--fl-subtle)' }}>·</span>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{stats.edges}</strong> liens
            <span style={{ color: 'var(--fl-subtle)' }}>·</span>
            <strong style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{stats.total_events}</strong> events
          </div>
        )}

        {stats?.failed_events > 0 && (
          <div style={{
            background: 'color-mix(in srgb, var(--fl-danger) 9%, var(--fl-panel))',
            border: '1px solid color-mix(in srgb, var(--fl-danger) 26%, transparent)', borderRadius: 10,
            boxShadow: 'var(--fl-shadow-lg)', padding: '8px 12px', fontSize: 10.5, color: 'var(--fl-danger)',
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <AlertTriangle size={12} />
            <strong style={{ fontWeight: 700 }}>{stats.failed_events}</strong> échecs de connexion
            {stats.rdp_events > 0 && (
              <span style={{ color: 'var(--fl-dim)' }}>· <strong style={{ color: 'var(--fl-warn)' }}>{stats.rdp_events}</strong> RDP</span>
            )}
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
          <div style={{ textAlign: 'center', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            <div style={{ fontSize: 13, marginBottom: 5, color: 'var(--fl-text)', fontWeight: 600 }}>Aucune donnée d'authentification</div>
            <div style={{ fontSize: 11, color: 'var(--fl-muted)' }}>Analysez des logs Security.evtx (4624/4625) ou des logs d'auth Linux</div>
          </div>
        </div>
      )}

      {/* ── Right detail panel ── */}
      {selectedNode && (
        <div
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0, width: 'clamp(320px, 26vw, 430px)',
            background: 'var(--fl-panel)', borderLeft: '1px solid var(--fl-border)',
            boxShadow: 'var(--fl-shadow-lg)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                {selectedNode.kind === 'user'
                  ? <User size={14} style={{ color: 'var(--fl-purple)' }} />
                  : <Monitor size={14} style={{ color: 'var(--fl-accent)' }} />}
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    {selectedNode.name}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 1 }}>
                    {selectedNode.kind === 'user' ? 'Utilisateur' : 'Machine'}
                  </div>
                </div>
              </div>
              <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)' }}>
                <X size={14} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, marginTop: 10 }}>
              {[
                ['Total', selectedNode.total_events, 'var(--fl-muted)'],
                ['OK', selectedNode.success, 'var(--fl-ok)'],
                ['Échecs', selectedNode.failed, 'var(--fl-danger)'],
              ].map(([label, val, color]) => (
                <div key={label} style={{ background: 'var(--fl-bg)', borderRadius: 4, padding: '6px 8px', border: '1px solid var(--fl-border)', textAlign: 'center' }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{val}</div>
                  <div style={{ fontSize: 9, color: 'var(--fl-dim)' }}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 14px' }}>
            <div style={{ fontSize: 11, color: 'var(--fl-dim)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {selectedNode.kind === 'user' ? `Machines accédées (${selEdges.length})` : `Utilisateurs (${selEdges.length})`}
            </div>
            {selEdges.map((edge, i) => {
              const peerId = edge.source === selectedNode.id ? edge.target : edge.source;
              const peer = nodes.find(n => n.id === peerId);
              const lt = dominantLogonType(edge);
              const st = logonStyle(lt);
              const failedDominant = edge.failed >= edge.success && edge.failed > 0;
              return (
                <div key={i} style={{
                  marginBottom: 8, padding: '8px 10px', borderRadius: 4,
                  background: 'var(--fl-bg)', border: `1px solid ${failedDominant ? 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' : 'var(--fl-border)'}`, fontSize: 11,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    <ArrowRight size={10} style={{ color: selectedNode.kind === 'user' ? 'var(--fl-warn)' : 'var(--fl-accent)', flexShrink: 0 }} />
                    <span style={{ color: 'var(--fl-text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={peer?.name || peerId}>
                      {peer?.name || peerId}
                    </span>
                    <span style={{
                      padding: '1px 5px', borderRadius: 3, fontSize: 9, color: st.color,
                      background: `color-mix(in srgb, ${st.color} 12%, transparent)`,
                    }}>{st.label}</span>
                    <span style={{ padding: '1px 5px', borderRadius: 3, fontSize: 9, background: 'color-mix(in srgb, var(--fl-accent) 13%, transparent)', color: 'var(--fl-accent)' }}>
                      x{edge.count}
                    </span>
                  </div>

                  {(edge.sources?.length > 0) && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--fl-dim)', fontSize: 10, marginBottom: 3 }}>
                      <span style={{ opacity: 0.7 }}>depuis</span>
                      {edge.sources.slice(0, 4).map(s => (
                        <span key={s} style={{
                          padding: '0 5px', borderRadius: 3, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9,
                          background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-muted)',
                        }}>{s}</span>
                      ))}
                      {edge.sources.length > 4 && <span style={{ fontSize: 9, color: 'var(--fl-muted)' }}>+{edge.sources.length - 4}</span>}
                    </div>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 3, color: 'var(--fl-dim)', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Clock size={9} /> {fmtTs(edge.first_seen)}
                    </span>
                    {edge.last_seen !== edge.first_seen && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                        <ArrowRight size={9} /> {fmtTs(edge.last_seen)}
                      </span>
                    )}
                    {edge.failed > 0 && (
                      <span style={{ color: 'var(--fl-danger)', fontWeight: 600 }}>{edge.failed} échec{s(edge.failed)}</span>
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

function s(n) { return n > 1 ? 's' : ''; }
