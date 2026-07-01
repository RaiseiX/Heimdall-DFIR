// frontend/src/pages/NetworkMapPage.jsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { networkAPI } from '../utils/api';
import { transformGraphData } from '../components/networkmap/utils/graphDataTransform';
import NetworkExplorer      from '../components/networkmap/NetworkExplorer';
import InvestigationDrawer  from '../components/networkmap/InvestigationDrawer';
import Toolbar              from '../components/networkmap/Toolbar';
import StatusBar            from '../components/networkmap/StatusBar';
import ZonePanel            from '../components/networkmap/ZonePanel';
import { useTranslation } from 'react-i18next';

export default function NetworkMapPage() {
  const { t } = useTranslation();
  const { id: caseId } = useParams();
  const [searchParams]  = useSearchParams();
  const evidenceId      = searchParams.get('evidence_id');

  const [graphData,      setGraphData]      = useState(null);  // raw API response
  const [elements,       setElements]       = useState([]);    // Cytoscape elements
  const [allEdges,       setAllEdges]       = useState([]);    // for drawer tabs
  const [loading,        setLoading]        = useState(false);
  const [error,          setError]          = useState(null);
  const [selectedNode,   setSelectedNode]   = useState(null);  // Cytoscape nodeData
  const [view,           setView]           = useState('network');
  const [filters,        setFilters]        = useState({ hiddenTypes: new Set(), suspiciousOnly: false, search: '' });
  const [zoom,           setZoom]           = useState(1);
  const [annotations,    setAnnotations]    = useState({ zones: [], node_overrides: {} });
  const [drawingZoneType, setDrawingZoneType] = useState(null);
  const [colorblindMode,      setColorblindMode]      = useState(() => localStorage.getItem('nm_colorblind') === '1');
  const [nodeColorOverrides,  setNodeColorOverrides]  = useState(() => {
    try { return JSON.parse(localStorage.getItem('nm_node_colors') || '{}'); } catch { return {}; }
  });
  const saveTimer = useRef(null);

  function toggleColorblind() {
    setColorblindMode(v => {
      const next = !v;
      localStorage.setItem('nm_colorblind', next ? '1' : '0');
      return next;
    });
  }

  function handleNodeColorChange(typeId, color) {
    setNodeColorOverrides(prev => {
      const next = { ...prev, [typeId]: color };
      localStorage.setItem('nm_node_colors', JSON.stringify(next));
      return next;
    });
  }

  function handleNodeColorReset(typeId) {
    setNodeColorOverrides(prev => {
      const next = { ...prev };
      delete next[typeId];
      localStorage.setItem('nm_node_colors', JSON.stringify(next));
      return next;
    });
  }

  // Load graph data + annotations together
  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    const params = {};
    if (evidenceId) params.evidence_id = evidenceId;
    Promise.all([
      networkAPI.graphData(caseId, params),
      networkAPI.getAnnotations(caseId),
    ])
      .then(([graphRes, annotRes]) => {
        const data   = graphRes.data;
        const annot  = annotRes.data;
        setGraphData(data);
        setAnnotations(annot);
        const overrides = annot?.node_overrides ?? {};
        const { elements: els } = transformGraphData(data?.network ?? data, overrides);
        setElements(applyFilters(els, filters));
        setAllEdges(els.filter(e => e.data?.source));
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [caseId, evidenceId]);

  // Re-apply filters + overrides when they change
  useEffect(() => {
    if (!graphData) return;
    const overrides = annotations?.node_overrides ?? {};
    const { elements: els } = transformGraphData(graphData?.network || graphData, overrides);
    setElements(applyFilters(els, filters));
    setAllEdges(els.filter(e => e.data?.source));
  }, [filters, graphData, annotations]);

  function applyFilters(els, f) {
    if (!f?.hiddenTypes?.size && !f?.suspiciousOnly && !f?.search) return els;
    const hiddenNodeIds = new Set();
    return els.filter(el => {
      if (el.data?.source) {
        return !hiddenNodeIds.has(el.data.source) && !hiddenNodeIds.has(el.data.target);
      }
      if (el.classes === 'cluster') return true;
      const d = el.data || {};
      if (f.hiddenTypes?.has(d.nodeType)) { hiddenNodeIds.add(d.id); return false; }
      if (f.suspiciousOnly && !d.is_suspicious) { hiddenNodeIds.add(d.id); return false; }
      if (f.search && !String(d.id).toLowerCase().includes(f.search.toLowerCase())) { hiddenNodeIds.add(d.id); return false; }
      return true;
    });
  }

  function handleFilterChange(action, value) {
    setFilters(prev => {
      const next = { ...prev, hiddenTypes: new Set(prev.hiddenTypes) };
      if (action === 'toggleType') {
        if (next.hiddenTypes.has(value)) next.hiddenTypes.delete(value);
        else next.hiddenTypes.add(value);
      }
      if (action === 'suspiciousOnly') next.suspiciousOnly = value;
      return next;
    });
  }

  function persistAnnotations(updated) {
    setAnnotations(updated);
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      networkAPI.saveAnnotations(caseId, updated).catch(err => console.error('[annotations save]', err));
    }, 500);
  }

  function handleZoneDrawn(zone) {
    persistAnnotations({ ...annotations, zones: [...annotations.zones, zone] });
    setDrawingZoneType(null);
  }

  function handleZoneUpdate(id, patch) {
    persistAnnotations({
      ...annotations,
      zones: annotations.zones.map(z => z.id === id ? { ...z, ...patch } : z),
    });
  }

  function handleZoneDelete(id) {
    persistAnnotations({ ...annotations, zones: annotations.zones.filter(z => z.id !== id) });
  }

  function handleOverrideType(nodeId, typeId) {
    persistAnnotations({
      ...annotations,
      node_overrides: { ...annotations.node_overrides, [nodeId]: typeId },
    });
  }

  function handleResetType(nodeId) {
    const next = { ...annotations.node_overrides };
    delete next[nodeId];
    persistAnnotations({ ...annotations, node_overrides: next });
  }

  const handleSelectPeer = useCallback((peerId) => {
    const peerEl = elements.find(el => el.data?.id === peerId && !el.data?.source);
    if (peerEl) setSelectedNode(peerEl.data);
  }, [elements]);

  if (loading) return (
    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0c11', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
      {t('networkMap.loading_graph')}
    </div>
  );
  if (error) return (
    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0c11', color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
      {error}
    </div>
  );

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#0a0c11' }}>
      <Toolbar
        graphData={graphData?.network || graphData}
        filters={filters}
        onFilterChange={handleFilterChange}
        onSearch={v => setFilters(p => ({ ...p, search: v }))}
        onViewChange={setView}
        view={view}
      />
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <ZonePanel
          zones={annotations.zones}
          drawingZoneType={drawingZoneType}
          onStartDraw={type => setDrawingZoneType(type)}
          onCancelDraw={() => setDrawingZoneType(null)}
          onDeleteZone={handleZoneDelete}
          colorblindMode={colorblindMode}
          onToggleColorblind={toggleColorblind}
          nodeColorOverrides={nodeColorOverrides}
          onNodeColorChange={handleNodeColorChange}
          onNodeColorReset={handleNodeColorReset}
        />
        <NetworkExplorer
          elements={elements}
          onNodeSelect={setSelectedNode}
          onNodeDeselect={() => setSelectedNode(null)}
          selectedNodeId={selectedNode?.id}
          zones={annotations.zones}
          drawingZoneType={drawingZoneType}
          onZoneDrawn={handleZoneDrawn}
          onZoneUpdate={handleZoneUpdate}
          onZoneDelete={handleZoneDelete}
          colorblindMode={colorblindMode}
          nodeColorOverrides={nodeColorOverrides}
        />
        {selectedNode && (
          <InvestigationDrawer
            nodeData={selectedNode}
            caseId={caseId}
            allEdges={allEdges}
            onClose={() => setSelectedNode(null)}
            onSelectPeer={handleSelectPeer}
            nodeOverrides={annotations.node_overrides}
            onOverrideType={handleOverrideType}
            onResetType={handleResetType}
          />
        )}
      </div>
      <StatusBar graphData={graphData?.network || graphData} zoom={zoom} selectedNode={selectedNode?.id} />
    </div>
  );
}
