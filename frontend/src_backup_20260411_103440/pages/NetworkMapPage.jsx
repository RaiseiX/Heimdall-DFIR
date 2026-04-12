import { useState, useEffect, useLayoutEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Globe, Filter, Plus, X, ExternalLink, Upload, Search, Tag, Network, Link2 } from 'lucide-react';
import * as d3 from 'd3';

function fmtBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function nodeColor(n) {
  if (n.is_suspicious) return '#da3633';
  if (n.type === 'domain') return '#3fb950';
  if (n.type === 'url')    return '#a371f7';
  return n.type === 'internal' ? '#4d82c0' : '#f0883e';
}

function nodeLabel(n) {
  if (n.type === 'internal') return 'IP interne';
  if (n.type === 'external') return 'IP externe';
  if (n.type === 'domain')   return 'Domaine';
  if (n.type === 'url')      return 'URL';
  return n.type;
}

function displayLabel(n) {
  if (n.type === 'url') {
    try {
      const h = new URL(n.id).hostname;
      return h.length > 28 ? h.substring(0, 26) + '…' : h;
    } catch { return n.id.substring(0, 20) + '…'; }
  }
  const s = String(n.id);
  return s.length > 30 ? s.substring(0, 28) + '…' : s;
}

function ForceGraph({ nodes, edges, onSelectEdge, onSelectNode, showUrlLabels = false }) {
  const svgRef      = useRef(null);
  const simRef      = useRef(null);
  const zoomRef     = useRef(null);

  useLayoutEffect(() => {
    const el = svgRef.current;
    if (!el) return;

    const width  = el.clientWidth  || el.parentElement?.clientWidth  || 900;
    const height = el.clientHeight || el.parentElement?.clientHeight || 600;
    const cx = width / 2;
    const cy = height / 2;

    const svg = d3.select(el);
    svg.selectAll('*').remove();

    if (!nodes.length) return;

    const nodesCopy = nodes.map(n => ({ ...n, x: cx + (Math.random() - 0.5) * 80, y: cy + (Math.random() - 0.5) * 80 }));
    const nodeById  = new Map(nodesCopy.map(n => [n.id, n]));
    const linksCopy = edges
      .filter(e => nodeById.has(e.source) && nodeById.has(e.target))
      .map(e => ({ ...e }));

    svg.append('rect').attr('width', width).attr('height', height).attr('fill', '#0d1117');
    const grid = svg.append('g');
    for (let x = 0; x < width; x += 40)
      grid.append('line').attr('x1', x).attr('y1', 0).attr('x2', x).attr('y2', height)
        .attr('stroke', '#161b22').attr('stroke-width', 0.5);
    for (let y = 0; y < height; y += 40)
      grid.append('line').attr('x1', 0).attr('y1', y).attr('x2', width).attr('y2', y)
        .attr('stroke', '#161b22').attr('stroke-width', 0.5);

    const defs = svg.append('defs');
    defs.append('marker').attr('id', 'arrow').attr('viewBox', '0 -5 10 10').attr('refX', 16)
      .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#4d82c040');
    [['ngBlue','#4d82c0'],['ngOrange','#f0883e'],['ngRed','#da3633'],['ngGreen','#3fb950'],['ngPurple','#a371f7']]
      .forEach(([id, col]) =>
        defs.append('radialGradient').attr('id', id)
          .html(`<stop offset="0%" stop-color="${col}" stop-opacity="0.35"/><stop offset="100%" stop-color="${col}" stop-opacity="0"/>`)
      );

    const g    = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.1, 6]).on('zoom', ev => g.attr('transform', ev.transform));
    svg.call(zoom);
    zoomRef.current = zoom;

    const n = nodesCopy.length;
    const distScale = Math.max(0.6, Math.min(1.4, Math.sqrt(300 / Math.max(n, 10))));

    const simulation = d3.forceSimulation(nodesCopy)
      .force('link', d3.forceLink(linksCopy).id(d => d.id)
        .distance(d => {
          const t = (typeof d.target === 'object' ? d.target.type : null)
                  || (typeof d.source === 'object' ? d.source.type : null);
          return (t === 'url' ? 80 : t === 'domain' ? 130 : 180) * distScale;
        })
        .strength(0.6))
      .force('charge', d3.forceManyBody()
        .strength(d => d.type === 'url' ? -120 : -500)
        .distanceMax(500))
      .force('center', d3.forceCenter(cx, cy).strength(0.08))
      .force('x', d3.forceX(cx).strength(0.04))
      .force('y', d3.forceY(cy).strength(0.04))
      .force('collision', d3.forceCollide()
        .radius(d => d.type === 'url' ? 22 : 40)
        .strength(0.8));

    simRef.current = simulation;

    const link = g.append('g').selectAll('line').data(linksCopy).join('line')
      .attr('stroke', d => d.has_suspicious ? '#da363360' : '#4d82c040')
      .attr('stroke-width', d => Math.max(1, Math.min(8, Math.log2((d.connection_count || 1) + 1) * 1.8)))
      .attr('stroke-dasharray', d => d.has_suspicious ? '6,3' : 'none')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        onSelectEdge({
          ...d,
          source: typeof d.source === 'object' ? d.source.id : d.source,
          target: typeof d.target === 'object' ? d.target.id : d.target,
        });
      })
      .on('mouseenter', function(_, d) {
        d3.select(this)
          .attr('stroke', d.has_suspicious ? '#da3633bb' : '#4d82c0bb')
          .attr('stroke-width', Math.max(2, Math.min(10, Math.log2((d.connection_count || 1) + 1) * 2.4)));
      })
      .on('mouseleave', function(_, d) {
        d3.select(this)
          .attr('stroke', d.has_suspicious ? '#da363360' : '#4d82c040')
          .attr('stroke-width', Math.max(1, Math.min(8, Math.log2((d.connection_count || 1) + 1) * 1.8)));
      });

    const linkLabel = g.append('g').selectAll('text').data(linksCopy).join('text')
      .text(d => {
        const port  = d.ports?.[0];
        const proto = d.protocols?.[0];
        if (port && proto) return `${proto}:${port}`;
        if (port)  return `port ${port}`;
        if (proto) return proto;
        return '';
      })
      .attr('fill', '#3d5070')
      .attr('font-size', 7)
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('text-anchor', 'middle')
      .style('pointer-events', 'none');

    const glow = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', 24)
      .attr('fill', d => {
        if (d.is_suspicious)     return 'url(#ngRed)';
        if (d.type === 'domain') return 'url(#ngGreen)';
        if (d.type === 'url')    return 'url(#ngPurple)';
        return d.type === 'internal' ? 'url(#ngBlue)' : 'url(#ngOrange)';
      });

    const node = g.append('g').selectAll('circle').data(nodesCopy).join('circle')
      .attr('r', d => d.type === 'url' ? 5 : 7 + Math.sqrt(d.connection_count || 1) * 2)
      .attr('fill', d => nodeColor(d))
      .attr('stroke', '#0d1117')
      .attr('stroke-width', d => d.type === 'url' ? 1 : 2)
      .attr('opacity', d => d.type === 'url' ? 0.8 : 1)
      .style('cursor', 'grab')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    node.append('title').text(d =>
      `${d.id}\n${nodeLabel(d)}${d.is_suspicious ? ' ⚠ Suspect' : ''}\n${d.connection_count} connexions\n${fmtBytes(d.total_bytes)}`
    );

    node.on('click', (event, d) => {
      event.stopPropagation();
      if (onSelectNode) onSelectNode(d);
    });

    const label = g.append('g').selectAll('text').data(nodesCopy).join('text')
      .text(d => displayLabel(d))
      .attr('fill', d => d.type === 'url' ? '#7070a0' : '#e6edf3')
      .attr('font-size', d => d.type === 'url' ? 7 : 10)
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.type === 'url' ? -10 : -16)
      .attr('opacity', d => d.type === 'url' ? (showUrlLabels ? 0.7 : 0) : 1)
      .style('pointer-events', 'none');

    const pad = 20;
    simulation.on('tick', () => {
      nodesCopy.forEach(d => {
        d.x = Math.max(pad, Math.min(width - pad, d.x));
        d.y = Math.max(pad, Math.min(height - pad, d.y));
      });
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 4);
      glow .attr('cx', d => d.x).attr('cy', d => d.y);
      node .attr('cx', d => d.x).attr('cy', d => d.y);
      label.attr('x',  d => d.x).attr('y',  d => d.y);
    });

    simulation.on('end', () => {
      const xs = nodesCopy.map(d => d.x);
      const ys = nodesCopy.map(d => d.y);
      const x0 = Math.min(...xs) - 40, x1 = Math.max(...xs) + 40;
      const y0 = Math.min(...ys) - 40, y1 = Math.max(...ys) + 40;
      const scale = Math.min(0.95, Math.min(width / (x1 - x0), height / (y1 - y0)));
      const tx = (width  - scale * (x0 + x1)) / 2;
      const ty = (height - scale * (y0 + y1)) / 2;
      svg.transition().duration(600)
        .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    });

    return () => { simulation.stop(); simRef.current = null; };
  }, [nodes, edges, onSelectEdge, onSelectNode, showUrlLabels]);

  return <svg ref={svgRef} style={{ width: '100%', height: '100%', display: 'block', borderRadius: 8 }} />;
}

export default function NetworkMapPage() {
  const { caseId } = useParams();
  const [searchParams] = useSearchParams();
  const evidenceId = searchParams.get('evidence_id') || null;
  const navigate = useNavigate();
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [nodeTypeFilters, setNodeTypeFilters] = useState({ internal: true, external: true, domain: true, url: true, suspicious_only: false });
  const [nodeSearch, setNodeSearch] = useState('');
  const [showUrlLabels, setShowUrlLabels] = useState(false);

  const toggleFilter = (key) => setNodeTypeFilters(f => ({ ...f, [key]: !f[key] }));

  const applyPreset = (preset) => {
    if (preset === 'all')     setNodeTypeFilters({ internal: true, external: true, domain: true, url: true, suspicious_only: false });
    if (preset === 'ips')     setNodeTypeFilters({ internal: true, external: true, domain: false, url: false, suspicious_only: false });
    if (preset === 'domains') setNodeTypeFilters({ internal: false, external: false, domain: true, url: false, suspicious_only: false });
    if (preset === 'urls')    setNodeTypeFilters({ internal: false, external: false, domain: false, url: true, suspicious_only: false });
    if (preset === 'suspects')setNodeTypeFilters({ internal: true, external: true, domain: true, url: true, suspicious_only: true });
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  const [caseInfo, setCaseInfo] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [newConn, setNewConn] = useState({ src: '', dst: '', srcPort: '', dstPort: '', proto: 'TCP', label: '', suspicious: false, srcCity: '', srcCountry: '', dstCity: '', dstCountry: '' });
  const [csvImporting, setCsvImporting] = useState(false);
  const [csvResult, setCsvResult] = useState(null);
  const csvInputRef = useRef(null);

  useEffect(() => {
    if (!caseId) { setGraphData({ nodes: [], edges: [] }); return; }
    setLoading(true);
    const load = async () => {
      try {
        const { networkAPI, casesAPI } = await import('../utils/api');
        const [graphRes, caseRes] = await Promise.allSettled([
          networkAPI.graph(caseId, evidenceId),
          casesAPI.get(caseId),
        ]);
        if (caseRes.status === 'fulfilled' && caseRes.value?.data) setCaseInfo(caseRes.value.data);
        if (graphRes.status === 'fulfilled' && graphRes.value?.data) {
          setGraphData({
            nodes: graphRes.value.data.nodes || [],
            edges: graphRes.value.data.edges || [],
          });
        } else {
          setGraphData({ nodes: [], edges: [] });
        }
      } catch { setGraphData({ nodes: [], edges: [] }); }
      setLoading(false);
    };
    load();
  }, [caseId]);

  const handleSelectEdge = useCallback((edge) => { setSelectedEdge(edge); setSelectedNode(null); }, []);
  const handleSelectNode = useCallback((node) => { setSelectedNode(node); setSelectedEdge(null); }, []);
  const susCount = graphData.edges.filter(e => e.has_suspicious).length;

  const filteredNodes = graphData.nodes.filter(n => {
    if (nodeTypeFilters.suspicious_only && !n.is_suspicious) return false;
    if (n.type === 'internal' && !nodeTypeFilters.internal) return false;
    if (n.type === 'external' && !nodeTypeFilters.external) return false;
    if (n.type === 'domain'   && !nodeTypeFilters.domain)   return false;
    if (n.type === 'url'      && !nodeTypeFilters.url)      return false;
    if (nodeSearch && !String(n.id).toLowerCase().includes(nodeSearch.toLowerCase())) return false;
    return true;
  });
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = graphData.edges.filter(e =>
    filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target) &&
    (!nodeTypeFilters.suspicious_only || e.has_suspicious)
  );

  const addConnection = async () => {
    if (!newConn.src || !newConn.dst) return;
    if (caseId) {
      try {
        const { networkAPI } = await import('../utils/api');
        await networkAPI.create(caseId, {
          src_ip: newConn.src, src_port: parseInt(newConn.srcPort) || 0,
          dst_ip: newConn.dst, dst_port: parseInt(newConn.dstPort) || 0,
          protocol: newConn.proto, is_suspicious: newConn.suspicious,
          notes: newConn.label,
          geo_src: { country: newConn.srcCountry, city: newConn.srcCity },
          geo_dst: { country: newConn.dstCountry, city: newConn.dstCity },
        });
      } catch (err) { console.error('Network save error:', err); }
    }
    setNewConn({ src: '', dst: '', srcPort: '', dstPort: '', proto: 'TCP', label: '', suspicious: false, srcCity: '', srcCountry: '', dstCity: '', dstCountry: '' });
    setShowAdd(false);
  };

  const handleCsvImport = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    setCsvImporting(true);
    setCsvResult(null);
    try {
      const { networkAPI } = await import('../utils/api');
      const res = await networkAPI.importCsv(caseId, file);
      setCsvResult({ ok: true, msg: `${res.data.imported} connexions importées sur ${res.data.total_rows} lignes` });

      const graphRes = await networkAPI.graph(caseId, evidenceId);
      if (graphRes?.data) setGraphData({ nodes: graphRes.data.nodes || [], edges: graphRes.data.edges || [] });
    } catch (err) {
      setCsvResult({ ok: false, msg: err.response?.data?.error || 'Erreur import CSV' });
    } finally {
      setCsvImporting(false);
    }
  };

  const isEmpty = graphData.nodes.length === 0 && !loading;
  const isFilteredEmpty = filteredNodes.length === 0 && !isEmpty && !loading;

  return (
    <div className="h-full flex flex-col">
      
      <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: '#30363d', background: '#161b22', flexShrink: 0 }}>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="fl-btn fl-btn-ghost fl-btn-sm" style={{ padding: '6px 8px' }}>
            <ArrowLeft size={15} />
          </button>
          <div>
            <div className="text-sm font-bold flex items-center gap-2">
              <Globe size={16} style={{ color: '#4d82c0' }} />
              Carte Réseau Interactive
            </div>
            <div className="text-xs" style={{ color: '#7d8590' }}>
              {caseInfo ? `${caseInfo.case_number} — ` : ''}
              {filteredNodes.length}/{graphData.nodes.length} nœuds · {filteredEdges.length} arêtes
              {susCount > 0 && <span style={{ color: '#da3633' }}> · {susCount} suspectes</span>}
              {evidenceId && <span style={{ color: '#4d82c0' }}> · collecte filtrée</span>}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          
          <div className="flex items-center gap-1 mr-1">
            {[
              { key: 'internal',      label: 'IP int.',   color: '#4d82c0' },
              { key: 'external',      label: 'IP ext.',   color: '#f0883e' },
              { key: 'domain',        label: 'Domaine',   color: '#3fb950' },
              { key: 'url',           label: 'URL',       color: '#a371f7' },
              { key: 'suspicious_only', label: '⚠ Suspects', color: '#da3633' },
            ].map(({ key, label, color }) => {
              const active = nodeTypeFilters[key];
              return (
                <button key={key} onClick={() => toggleFilter(key)} style={{
                  display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px',
                  background: active ? `${color}15` : 'transparent',
                  border: `1px solid ${active ? `${color}40` : '#30363d'}`,
                  borderRadius: 5, cursor: 'pointer',
                  opacity: active ? 1 : 0.45, transition: 'all 0.15s',
                  fontSize: 10, fontFamily: 'monospace',
                  color: active ? color : '#7d8590',
                }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
                  {label}
                </button>
              );
            })}
          </div>
          <div style={{ width: 1, height: 16, background: '#30363d', margin: '0 4px' }} />
          <input ref={csvInputRef} type="file" accept=".csv,.tsv,.log,.txt" style={{ display: 'none' }} onChange={handleCsvImport} />
          <button
            onClick={() => csvInputRef.current?.click()}
            disabled={csvImporting}
            title="Importer un CSV réseau (Zeek, pare-feu…)"
            className="fl-btn fl-btn-sm"
            style={{ color: '#4d82c0', border: '1px solid #4d82c030' }}
          >
            <Upload size={12} /> {csvImporting ? 'Import…' : 'Import CSV'}
          </button>
          <button onClick={() => setShowAdd(true)} className="fl-btn fl-btn-primary fl-btn-sm">
            <Plus size={12} /> Ajouter
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 px-4 py-2 border-b" style={{ borderColor: '#30363d', background: '#0d1117', flexShrink: 0, flexWrap: 'wrap' }}>
        <span style={{ color: '#484f58', fontSize: 10, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em', flexShrink: 0 }}>Vue</span>
        {[
          { id: 'all',     label: 'Tout',     icon: <Network size={10} /> },
          { id: 'ips',     label: 'IPs',      icon: <Globe size={10} /> },
          { id: 'domains', label: 'Domaines', icon: <Tag size={10} /> },
          { id: 'urls',    label: 'URLs',     icon: <Link2 size={10} /> },
          { id: 'suspects',label: '⚠ Suspects', icon: null },
        ].map(p => {
          const isActive =
            p.id === 'all'     ? (nodeTypeFilters.internal && nodeTypeFilters.external && nodeTypeFilters.domain && nodeTypeFilters.url && !nodeTypeFilters.suspicious_only) :
            p.id === 'ips'     ? (nodeTypeFilters.internal && nodeTypeFilters.external && !nodeTypeFilters.domain && !nodeTypeFilters.url && !nodeTypeFilters.suspicious_only) :
            p.id === 'domains' ? (!nodeTypeFilters.internal && !nodeTypeFilters.external && nodeTypeFilters.domain && !nodeTypeFilters.url && !nodeTypeFilters.suspicious_only) :
            p.id === 'urls'    ? (!nodeTypeFilters.internal && !nodeTypeFilters.external && !nodeTypeFilters.domain && nodeTypeFilters.url && !nodeTypeFilters.suspicious_only) :
            nodeTypeFilters.suspicious_only;
          return (
            <button key={p.id} onClick={() => applyPreset(p.id)} style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 4, cursor: 'pointer',
              fontSize: 10, fontFamily: 'monospace',
              background: isActive ? '#1c2d3f' : 'transparent',
              border: `1px solid ${isActive ? '#4d82c060' : '#30363d'}`,
              color: isActive ? '#4d82c0' : '#7d8590',
              transition: 'all 0.15s',
            }}>
              {p.icon}{p.label}
            </button>
          );
        })}
        <div style={{ width: 1, height: 14, background: '#30363d', flexShrink: 0 }} />
        
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <Search size={11} style={{ position: 'absolute', left: 7, top: '50%', transform: 'translateY(-50%)', color: '#484f58', pointerEvents: 'none' }} />
          <input
            value={nodeSearch}
            onChange={e => setNodeSearch(e.target.value)}
            placeholder="Rechercher un nœud…"
            style={{
              background: '#161b22', border: '1px solid #30363d', borderRadius: 4,
              padding: '3px 8px 3px 24px', fontSize: 11, fontFamily: 'monospace',
              color: '#e6edf3', width: 200, outline: 'none',
            }}
          />
          {nodeSearch && (
            <button onClick={() => setNodeSearch('')} style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', lineHeight: 1 }}>✕</button>
          )}
        </div>
        <div style={{ width: 1, height: 14, background: '#30363d', flexShrink: 0 }} />
        
        <button onClick={() => setShowUrlLabels(v => !v)} style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '2px 8px', borderRadius: 4, cursor: 'pointer',
          fontSize: 10, fontFamily: 'monospace',
          background: showUrlLabels ? '#1c1a2e' : 'transparent',
          border: `1px solid ${showUrlLabels ? '#a371f760' : '#30363d'}`,
          color: showUrlLabels ? '#a371f7' : '#7d8590',
          transition: 'all 0.15s',
        }}>
          <Link2 size={10} /> Labels URL
        </button>
      </div>

      {csvResult && (
        <div style={{
          padding: '6px 16px', fontSize: 12, fontFamily: 'monospace', flexShrink: 0,
          background: csvResult.ok ? '#1a3a1a' : '#3a1a1a',
          color: csvResult.ok ? '#3fb950' : '#da3633',
          borderBottom: `1px solid ${csvResult.ok ? '#3fb95030' : '#da363330'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>{csvResult.ok ? '✓' : '✗'} {csvResult.msg}</span>
          <button onClick={() => setCsvResult(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', opacity: 0.6 }}>✕</button>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 relative" onClick={() => setSelectedEdge(null)}>
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center" style={{ color: '#7d8590' }}>
                <Globe size={32} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
                <div className="text-sm">Chargement du graphe…</div>
              </div>
            </div>
          ) : isFilteredEmpty ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Filter size={36} style={{ color: '#30363d', margin: '0 auto 12px' }} />
                <div className="text-sm font-semibold mb-1" style={{ color: '#e6edf3' }}>Aucun nœud visible</div>
                <p className="text-xs" style={{ color: '#7d8590' }}>Activez des types via les filtres ci-dessus</p>
              </div>
            </div>
          ) : isEmpty ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Globe size={48} style={{ color: '#30363d', margin: '0 auto 16px' }} />
                <div className="text-base font-semibold mb-2" style={{ color: '#e6edf3' }}>Aucune donnée réseau</div>
                <p className="text-sm mb-1" style={{ color: '#7d8590' }}>
                  Parsez des logs réseau (Zeek, pare-feu, EVTX) via la page Collection
                </p>
                <p className="text-xs" style={{ color: '#484f58' }}>
                  ou ajoutez manuellement des connexions avec le bouton ci-dessus.
                </p>
              </div>
            </div>
          ) : (
            <ForceGraph
              nodes={filteredNodes}
              edges={filteredEdges}
              onSelectEdge={handleSelectEdge}
              onSelectNode={handleSelectNode}
              showUrlLabels={showUrlLabels}
            />
          )}
        </div>

        {selectedNode && !selectedEdge && (() => {
          const nodeEdges = graphData.edges.filter(e =>
            e.source === selectedNode.id || e.target === selectedNode.id
          );
          const peers = [...new Set(nodeEdges.map(e => e.source === selectedNode.id ? e.target : e.source))];
          return (
            <div className="w-72 border-l overflow-auto flex-shrink-0" style={{ background: '#161b22', borderColor: '#30363d' }}
              onClick={e => e.stopPropagation()}>
              <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: '#30363d' }}>
                <h3 className="font-bold text-sm flex items-center gap-2">
                  <span style={{ width: 9, height: 9, borderRadius: '50%', background: nodeColor(selectedNode), display: 'inline-block', flexShrink: 0 }} />
                  {nodeLabel(selectedNode)}
                  {selectedNode.is_suspicious && <AlertTriangle size={13} style={{ color: '#da3633' }} />}
                </h3>
                <button onClick={() => setSelectedNode(null)} style={{ color: '#7d8590' }}><X size={14} /></button>
              </div>
              <div className="p-4 space-y-3 text-xs">
                <div className="p-3 rounded-lg font-mono break-all" style={{ background: '#0d1117', border: '1px solid #30363d', color: nodeColor(selectedNode), lineHeight: 1.5 }}>
                  {selectedNode.id}
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                    <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Connexions</div>
                    <div className="font-mono font-bold" style={{ color: '#e6edf3' }}>{selectedNode.connection_count || nodeEdges.length}</div>
                  </div>
                  <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                    <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Volume</div>
                    <div className="font-mono font-bold" style={{ color: '#e6edf3' }}>{fmtBytes(selectedNode.total_bytes)}</div>
                  </div>
                </div>
                {selectedNode.is_suspicious && (
                  <div className="p-2 rounded flex items-center gap-2" style={{ background: '#2d1a1a', border: '1px solid #da363330' }}>
                    <AlertTriangle size={12} style={{ color: '#da3633', flexShrink: 0 }} />
                    <span style={{ color: '#da3633' }}>Nœud suspect</span>
                  </div>
                )}
                {peers.length > 0 && (
                  <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                    <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-2">Pairs connectés ({peers.length})</div>
                    <div className="space-y-1" style={{ maxHeight: 160, overflowY: 'auto' }}>
                      {peers.map(p => {
                        const pNode = graphData.nodes.find(n => n.id === p);
                        return (
                          <button key={p} onClick={() => { if (pNode) handleSelectNode(pNode); }} style={{
                            display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                            background: 'none', border: 'none', cursor: pNode ? 'pointer' : 'default',
                            padding: '2px 0', textAlign: 'left',
                          }}>
                            <span style={{ width: 7, height: 7, borderRadius: '50%', background: pNode ? nodeColor(pNode) : '#484f58', flexShrink: 0, display: 'inline-block' }} />
                            <span className="font-mono truncate" style={{ color: '#c9d1d9', fontSize: 10 }}>{p}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
                <button
                  onClick={() => navigate(`/super-timeline?caseId=${caseId}&search=${encodeURIComponent(selectedNode.id)}`)}
                  className="w-full fl-btn fl-btn-primary fl-btn-sm"
                  style={{ justifyContent: 'center' }}
                >
                  <ExternalLink size={12} /> Voir dans la Super Timeline
                </button>
              </div>
            </div>
          );
        })()}

        {selectedEdge && (
          <div className="w-72 border-l overflow-auto flex-shrink-0" style={{ background: '#161b22', borderColor: '#30363d' }}
            onClick={e => e.stopPropagation()}>
            <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: '#30363d' }}>
              <h3 className="font-bold text-sm flex items-center gap-2">
                {selectedEdge.has_suspicious && <AlertTriangle size={14} style={{ color: '#da3633' }} />}
                Connexion
              </h3>
              <button onClick={() => setSelectedEdge(null)} style={{ color: '#7d8590' }}><X size={14} /></button>
            </div>
            <div className="p-4 space-y-3 text-xs">
              <div className="p-3 rounded-lg font-mono" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                <div style={{ color: '#4d82c0', wordBreak: 'break-all' }}>{selectedEdge.source}</div>
                <div style={{ color: '#484f58', margin: '2px 0' }}>↓</div>
                <div style={{
                  wordBreak: 'break-all',
                  color: /^https?:\/\
                    : (!isInternalIP(selectedEdge.target) ? '#f0883e' : '#4d82c0'),
                }}>
                  {selectedEdge.target}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                  <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Connexions</div>
                  <div className="font-mono font-bold" style={{ color: '#e6edf3' }}>{selectedEdge.connection_count}</div>
                </div>
                <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                  <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Volume</div>
                  <div className="font-mono font-bold" style={{ color: '#e6edf3' }}>{fmtBytes(selectedEdge.total_bytes)}</div>
                </div>
              </div>

              {selectedEdge.ports?.length > 0 && (
                <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                  <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Ports</div>
                  <div className="font-mono" style={{ color: '#e6edf3' }}>{selectedEdge.ports.join(', ')}</div>
                </div>
              )}

              {selectedEdge.protocols?.length > 0 && (
                <div className="p-2 rounded" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
                  <div style={{ color: '#484f58', fontSize: 9 }} className="uppercase tracking-wider mb-1">Protocoles</div>
                  <div className="font-mono" style={{ color: '#e6edf3' }}>{selectedEdge.protocols.join(', ')}</div>
                </div>
              )}

              <button
                onClick={() => navigate(`/super-timeline?caseId=${caseId}&search=${encodeURIComponent(selectedEdge.source)}`)}
                className="w-full fl-btn fl-btn-primary fl-btn-sm"
                style={{ justifyContent: 'center' }}
              >
                <ExternalLink size={12} /> Voir dans la Super Timeline
              </button>
            </div>
          </div>
        )}
      </div>

      {showAdd && (
        <div className="fl-modal-overlay" onClick={e => e.target === e.currentTarget && setShowAdd(false)}>
          <div className="fl-modal" style={{ maxWidth: 520 }}>
            <div className="fl-modal-header">
              <Plus size={16} style={{ color: '#4d82c0' }} /> Ajouter une connexion
            </div>
            <div className="fl-modal-body">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { key: 'src', label: 'IP Source', ph: '10.0.1.15' },
                  { key: 'dst', label: 'IP Destination', ph: '192.168.1.100' },
                  { key: 'srcPort', label: 'Port Source', ph: '49152' },
                  { key: 'dstPort', label: 'Port Destination', ph: '443' },
                  { key: 'srcCity', label: 'Ville Source', ph: 'Paris' },
                  { key: 'dstCity', label: 'Ville Destination', ph: 'Moscow' },
                  { key: 'srcCountry', label: 'Pays Source', ph: 'FR' },
                  { key: 'dstCountry', label: 'Pays Destination', ph: 'RU' },
                ].map(f => (
                  <div key={f.key}>
                    <label className="fl-label">{f.label}</label>
                    <input
                      value={newConn[f.key]}
                      onChange={e => setNewConn(p => ({ ...p, [f.key]: e.target.value }))}
                      placeholder={f.ph}
                      className="fl-input w-full"
                      style={{ fontFamily: ['src', 'dst', 'srcPort', 'dstPort'].includes(f.key) ? 'JetBrains Mono, monospace' : undefined }}
                    />
                  </div>
                ))}
                <div>
                  <label className="fl-label">Protocole</label>
                  <select value={newConn.proto} onChange={e => setNewConn(p => ({ ...p, proto: e.target.value }))} className="fl-select w-full">
                    {['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'].map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="fl-label">Label</label>
                  <input value={newConn.label} onChange={e => setNewConn(p => ({ ...p, label: e.target.value }))} placeholder="Description" className="fl-input w-full" />
                </div>
              </div>
              <div className="mt-3">
                <label className="flex items-center gap-2 cursor-pointer text-sm" style={{ color: newConn.suspicious ? '#da3633' : '#7d8590' }}>
                  <input type="checkbox" checked={newConn.suspicious} onChange={e => setNewConn(p => ({ ...p, suspicious: e.target.checked }))} />
                  Marquer comme suspect
                </label>
              </div>
            </div>
            <div className="fl-modal-footer">
              <button onClick={() => setShowAdd(false)} className="fl-btn fl-btn-secondary">Annuler</button>
              <button onClick={addConnection} className="fl-btn fl-btn-primary" disabled={!newConn.src || !newConn.dst}>
                Ajouter
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function isInternalIP(ip) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$)/.test(ip || '');
}
