import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Globe, GitBranch, Share2, Download, Loader2, Target, Filter, PenLine } from 'lucide-react';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import { networkAPI, casesAPI, iocsAPI } from '../utils/api';
import { useTheme } from '../utils/theme';
import AttackPathD3 from '../components/network/AttackPathD3';
import LateralMovementD3 from '../components/network/LateralMovementD3';
import IntelViewSwitcher from '../components/network/IntelViewSwitcher';
import AptAttributionTab from '../components/mitre/AptAttributionTab';
import NetworkExplorer from '../components/networkmap/NetworkExplorer';
import TriagePanel from '../components/networkmap/TriagePanel';
import InvestigationDrawer from '../components/networkmap/InvestigationDrawer';
import ZonePanel from '../components/networkmap/ZonePanel';
import { transformGraphData } from '../components/networkmap/utils/graphDataTransform';

const VIEWS = [
  { id: 'network',     labelKey: 'caseIntelligence.views.network',     icon: Globe,     color: 'var(--fl-accent)' },
  { id: 'attack',      labelKey: 'caseIntelligence.views.attack',      icon: GitBranch, color: 'var(--fl-accent)' },
  { id: 'lateral',     labelKey: 'caseIntelligence.views.lateral',     icon: Share2,    color: 'var(--fl-warn)' },
  { id: 'attribution', labelKey: 'caseIntelligence.views.attribution', icon: Target,    color: 'var(--fl-danger)' },
];

export default function CaseIntelligencePage({ collectionId }) {
  const { t } = useTranslation();
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const T = useTheme();

  const { socket } = useSocket();
  const initialView = VIEWS.find(v => v.id === searchParams.get('view'))?.id || 'network';
  const initialEvidenceIds = searchParams.get('evidence_ids') || '';
  const currentUsername = useMemo(() => {
    try { const p = JSON.parse(atob(localStorage.getItem('heimdall_token')?.split('.')[1] || '')); return p?.username || null; } catch { return null; }
  }, []);

  const [view, setView] = useState(initialView);
  const [loading, setLoading] = useState(false);
  const [filterLoading, setFilterLoading] = useState(false);
  const [collectionScoped, setCollectionScoped] = useState(false);
  const [loadingLateral, setLoadingLateral] = useState(false);
  const [graphData, setGraphData] = useState({ network: null, attack: null });
  const [lateralData, setLateralData] = useState({ nodes: [], edges: [], chains: [], total_events: 0 });
  const [caseInfo, setCaseInfo] = useState(null);
  const [error, setError] = useState(null);
  const [activeEvidenceIds, setActiveEvidenceIds] = useState(
    initialEvidenceIds ? initialEvidenceIds.split(',').filter(Boolean) : []
  );
  const [fromTs, setFromTs] = useState('');
  const [toTs,   setToTs]   = useState('');
  const [beacons, setBeacons] = useState([]);
  const [schemaEditingBy, setSchemaEditingBy] = useState(null);
  const schemaEditTimer = useRef(null);

  const [selectedNode,      setSelectedNode]      = useState(null);
  const [cytoscapeElements, setCytoscapeElements] = useState([]);
  const [cyInstance,        setCyInstance]        = useState(null);
  const [allEdges,          setAllEdges]          = useState([]);

  const [annotations,     setAnnotations]     = useState({ zones: [], node_overrides: {} });
  const [drawingZoneType, setDrawingZoneType] = useState(null);
  const [colorblindMode,     setColorblindMode]     = useState(() => localStorage.getItem('nm_colorblind') === '1');
  const [nodeColorOverrides, setNodeColorOverrides] = useState(() => {
    try { return JSON.parse(localStorage.getItem('nm_node_colors') || '{}'); } catch { return {}; }
  });
  const [placingAsset, setPlacingAsset] = useState(null); // { typeId, label, colorOverride } | null
  const saveTimer = useRef(null);

  function handleAssetPlaced(position) {
    const mn = {
      id: `manual:${crypto.randomUUID()}`,
      typeId: placingAsset.typeId,
      label: placingAsset.label || '',
      position,
      colorOverride: placingAsset.colorOverride || null,
    };
    persistAnnotations({
      ...annotations,
      manual_nodes: [...(annotations.manual_nodes || []), mn],
    });
    setPlacingAsset(null);
  }

  function handleDeleteManualNode(nodeId) {
    persistAnnotations({
      ...annotations,
      manual_nodes: (annotations.manual_nodes || []).filter(n => n.id !== nodeId),
    });
  }

  function toggleColorblind() {
    setColorblindMode(v => { const n = !v; localStorage.setItem('nm_colorblind', n ? '1' : '0'); return n; });
  }
  function handleNodeColorChange(typeId, color) {
    setNodeColorOverrides(prev => { const n = { ...prev, [typeId]: color }; localStorage.setItem('nm_node_colors', JSON.stringify(n)); return n; });
  }
  function handleNodeColorReset(typeId) {
    setNodeColorOverrides(prev => { const n = { ...prev }; delete n[typeId]; localStorage.setItem('nm_node_colors', JSON.stringify(n)); return n; });
  }

  const attackSvgRef = useRef(null);
  const lateralSvgRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);

    const scopeIds = initialEvidenceIds || collectionId || '';
    const graphParams = scopeIds
      ? { view: 'network', evidence_ids: scopeIds }
      : { view: 'all' };

    Promise.allSettled([
      networkAPI.graphData(id, graphParams),
      casesAPI.get(id),
      networkAPI.beacons(id),
      networkAPI.getAnnotations(id),
    ]).then(([graphRes, caseRes, beaconRes, annotRes]) => {
      if (caseRes.status   === 'fulfilled') setCaseInfo(caseRes.value?.data);
      if (graphRes.status  === 'fulfilled') setGraphData(graphRes.value?.data || {});
      if (beaconRes.status === 'fulfilled') setBeacons(beaconRes.value?.data?.beacons || []);
      if (annotRes.status  === 'fulfilled') setAnnotations(annotRes.value?.data || { zones: [], node_overrides: {} });
      if (scopeIds) {
        setCollectionScoped(true);
        setActiveEvidenceIds(scopeIds.split(',').filter(Boolean));
      }
    }).catch(() => {
      setError(t('caseIntelligence.load_error'));
    }).finally(() => setLoading(false));
  }, [id, t]);

  const lateralLoaded = useRef(false);
  useEffect(() => {
    if (view !== 'lateral' || lateralLoaded.current || !id) return;
    lateralLoaded.current = true;
    setLoadingLateral(true);
    casesAPI.lateralMovement(id)
      .then(res => {
        const d = res?.data || {};
        setLateralData({ nodes: d.nodes || [], edges: d.edges || [], chains: d.chains || [], total_events: d.total_events || 0 });
      })
      .catch(() => {})
      .finally(() => setLoadingLateral(false));
  }, [view, id]);

  // Malicious IOC values for this case → highlight matching nodes on the map.
  const [iocHits, setIocHits] = useState(null);
  useEffect(() => {
    if (!id) return;
    iocsAPI.list(id).then(r => {
      const set = new Set((r.data?.iocs || [])
        .filter(i => i.is_malicious === true)
        .map(i => String(i.value || '').toLowerCase().trim())
        .filter(Boolean));
      setIocHits(set.size ? set : null);
    }).catch(() => {});
  }, [id]);

  useEffect(() => {
    if (!graphData.network) return;
    const overrides = annotations?.node_overrides ?? {};
    const { elements: els } = transformGraphData(graphData.network, overrides);
    if (iocHits) {
      els.forEach(el => {
        if (el.data?.source || !el.data?.id) return; // skip edges / structural
        const idv = String(el.data.id).toLowerCase();
        const lbl = String(el.data.label || '').toLowerCase().replace(/\s*\(\d+\)\s*$/, '');
        if (iocHits.has(idv) || iocHits.has(lbl)) el.data._iocHit = 1;
      });
    }
    setCytoscapeElements(els);
    setAllEdges(els.filter(e => e.data?.source));
  }, [graphData.network, annotations, iocHits]);


  useEffect(() => {
    if (!socket || !id) return;
    socket.emit('case:join', { caseId: id });
    return () => { socket.emit('case:leave', { caseId: id }); };
  }, [socket, id]);

  useSocketEvent(socket, 'network:schema_edited', ({ username }) => {
    if (username === currentUsername) return;
    clearTimeout(schemaEditTimer.current);
    setSchemaEditingBy(username);
    schemaEditTimer.current = setTimeout(() => setSchemaEditingBy(null), 5000);
  });

  function persistAnnotations(updated) {
    setAnnotations(updated);
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      networkAPI.saveAnnotations(id, updated).catch(err => console.error('[annotations save]', err));
    }, 500);
  }

  function handleZoneDrawn(zone) {
    persistAnnotations({ ...annotations, zones: [...annotations.zones, zone] });
    setDrawingZoneType(null);
  }
  function handleZoneUpdate(zoneId, patch) {
    persistAnnotations({ ...annotations, zones: annotations.zones.map(z => z.id === zoneId ? { ...z, ...patch } : z) });
  }
  function handleZoneDelete(zoneId) {
    persistAnnotations({ ...annotations, zones: annotations.zones.filter(z => z.id !== zoneId) });
  }
  function handleOverrideType(nodeId, typeId) {
    persistAnnotations({ ...annotations, node_overrides: { ...annotations.node_overrides, [nodeId]: typeId } });
  }
  function handleResetType(nodeId) {
    const next = { ...annotations.node_overrides };
    delete next[nodeId];
    persistAnnotations({ ...annotations, node_overrides: next });
  }

  function handlePositionsSave(positions) {
    persistAnnotations({ ...annotations, node_positions: positions });
  }

  const refetchNetwork = useCallback(async (ids, from, to) => {
    setFilterLoading(true);
    const params = { view: 'network' };
    if (ids.length > 0) params.evidence_ids = ids.join(',');
    if (from) params.from_ts = from;
    if (to)   params.to_ts   = to;
    const [graphRes, beaconRes] = await Promise.allSettled([
      networkAPI.graphData(id, params),
      networkAPI.beacons(id, { ...(from ? { from_ts: from } : {}), ...(to ? { to_ts: to } : {}) }),
    ]);
    if (graphRes.status  === 'fulfilled' && graphRes.value?.data?.network)
      setGraphData(prev => ({ ...prev, network: graphRes.value.data.network }));
    if (beaconRes.status === 'fulfilled')
      setBeacons(beaconRes.value?.data?.beacons || []);
    setFilterLoading(false);
  }, [id]);

  const handleEvidenceFilter = useCallback((ids) => {
    setActiveEvidenceIds(ids);
    refetchNetwork(ids, fromTs, toTs);
  }, [id, fromTs, toTs, refetchNetwork]);

  const handleTimeFilter = useCallback((from, to) => {
    setFromTs(from);
    setToTs(to);
    refetchNetwork(activeEvidenceIds, from, to);
  }, [id, activeEvidenceIds, refetchNetwork]);

  const svgRefForView = { attack: attackSvgRef, lateral: lateralSvgRef };

  const exportPng = useCallback(() => {
    const svgEl = svgRefForView[view]?.current;
    if (!svgEl) return;

    const svgClone = svgEl.cloneNode(true);
    const width = svgEl.clientWidth || 1200;
    const height = svgEl.clientHeight || 800;
    svgClone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    svgClone.setAttribute('width', width);
    svgClone.setAttribute('height', height);

    const watermark = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    watermark.setAttribute('x', '10');
    watermark.setAttribute('y', String(height - 8));
    watermark.setAttribute('fill', 'var(--fl-muted)');
    watermark.setAttribute('font-size', '11');
    watermark.setAttribute('font-family', 'var(--f-mono, "JetBrains Mono", monospace)');
    watermark.textContent = `Heimdall DFIR — ${caseInfo?.case_number || id} — ${new Date().toISOString().slice(0, 10)}`;
    svgClone.appendChild(watermark);

    const svgStr = new XMLSerializer().serializeToString(svgClone);
    const blob = new Blob([svgStr], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);

    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width; canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = 'var(--fl-bg)';
      ctx.fillRect(0, 0, width, height);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      const a = document.createElement('a');
      a.href = canvas.toDataURL('image/png');
      a.download = `heimdall-${view}-${id.slice(0, 8)}.png`;
      a.click();
    };
    img.src = url;
  }, [view, id, caseInfo]);

  const activeView = VIEWS.find(v => v.id === view) || VIEWS[0];
  const isLoading = loading || (view === 'lateral' && loadingLateral);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: T.bg }}>

      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 15, fontWeight: 700, color: T.text, letterSpacing: '-0.01em' }}>
                {t('caseIntelligence.title')}
              </span>
              {collectionScoped && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
                  <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)', flexShrink: 0 }} />
                  {t('caseIntelligence.collection_scoped')}
                </span>
              )}
            </div>
            <div style={{ fontSize: 11, color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontFeatureSettings: '"tnum"', marginTop: 2 }}>
              {caseInfo?.case_number || ''}{caseInfo?.title ? ` — ${caseInfo.title}` : ''}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <IntelViewSwitcher
            views={VIEWS.map(v => ({ id: v.id, label: t(v.labelKey), icon: v.icon }))}
            active={view}
            onChange={setView}
          />

          <button
            onClick={exportPng}
            title={t('caseIntelligence.export_png_title', { view: t(activeView.labelKey) })}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '6px 10px', fontSize: 12, border: `1px solid ${T.border}`,
              background: 'transparent', color: T.dim, borderRadius: 7, cursor: 'pointer',
              transition: 'color 0.15s, border-color 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-text)'; e.currentTarget.style.borderColor = 'var(--fl-border3)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = T.dim; e.currentTarget.style.borderColor = T.border; }}
          >
            <Download size={12} /> PNG
          </button>

          <div style={{ width: 1, height: 20, background: T.border }} />

          <IntelViewSwitcher
            views={[
              { id: 'case',   label: t('caseIntelligence.case_mode'),   icon: Filter },
              { id: 'global', label: t('caseIntelligence.global_mode'), icon: Globe },
            ]}
            active="case"
            onChange={(m) => { if (m === 'global') navigate(`/cases/${id}/global-map`); }}
          />
        </div>
      </div>

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {(isLoading || filterLoading) && (
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: T.bg + 'cc', zIndex: 10,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: T.dim, fontSize: 13 }}>
              <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
              {filterLoading ? t('caseIntelligence.filtering') : t('common.loading')}
            </div>
          </div>
        )}

        {schemaEditingBy && (
          <div style={{
            position: 'absolute', top: 8, left: '50%', transform: 'translateX(-50%)',
            zIndex: 20, display: 'flex', alignItems: 'center', gap: 6,
            background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)',
            borderRadius: 6, padding: '5px 12px', pointerEvents: 'none',
            boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
          }}>
              <PenLine size={11} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
              <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
              <span style={{ color: 'var(--fl-accent)', fontWeight: 700 }}>{schemaEditingBy}</span> {t('caseIntelligence.schema_editing')}
            </span>
          </div>
        )}

        {error && (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--fl-danger)', fontSize: 13 }}>{error}</div>
        )}

        {!error && (
          <>
            <div style={{ display: view === 'network' ? 'flex' : 'none', flex: 1, width: '100%', height: '100%', overflow: 'hidden' }}>
              <ZonePanel
                zones={annotations.zones}
                drawingZoneType={drawingZoneType}
                onStartDraw={type => setDrawingZoneType(type)}
                onCancelDraw={() => setDrawingZoneType(null)}
                onDeleteZone={handleZoneDelete}
                onZoneUpdate={handleZoneUpdate}
                colorblindMode={colorblindMode}
                onToggleColorblind={toggleColorblind}
                nodeColorOverrides={nodeColorOverrides}
                onNodeColorChange={handleNodeColorChange}
                onNodeColorReset={handleNodeColorReset}
                placingAsset={placingAsset}
                onStartPlace={setPlacingAsset}
                onCancelPlace={() => setPlacingAsset(null)}
              />
              <NetworkExplorer
                elements={cytoscapeElements}
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
                manualNodes={annotations.manual_nodes || []}
                placingAsset={placingAsset}
                onAssetPlaced={handleAssetPlaced}
                savedPositions={annotations.node_positions || {}}
                onPositionsSave={handlePositionsSave}
                onCyReady={setCyInstance}
              />
              {!selectedNode && (
                <TriagePanel
                  elements={cytoscapeElements}
                  cy={cyInstance}
                  caseId={id}
                  onPivot={(value) => navigate(`/cases/${id}/timeline?search=${encodeURIComponent(value)}`)}
                />
              )}
              {selectedNode && (
                <InvestigationDrawer
                  nodeData={selectedNode}
                  caseId={id}
                  allEdges={allEdges}
                  onClose={() => setSelectedNode(null)}
                  onSelectPeer={peerId => {
                    const el = cytoscapeElements.find(e => e.data?.id === peerId && !e.data?.source);
                    if (el) setSelectedNode(el.data);
                  }}
                  nodeOverrides={annotations.node_overrides}
                  onOverrideType={handleOverrideType}
                  onResetType={handleResetType}
                  onDeleteManualNode={nodeId => { handleDeleteManualNode(nodeId); setSelectedNode(null); }}
                />
              )}
            </div>
            <div style={{ display: view === 'attack' ? 'flex' : 'none', flex: 1, width: '100%', height: '100%' }}>
              <AttackPathD3
                svgRef={attackSvgRef}
                caseId={id}
                nodes={graphData.attack?.nodes || []}
                edges={graphData.attack?.edges || []}
                phasesCovered={graphData.attack?.phases_covered || []}
                theme={T}
              />
            </div>
            <div style={{ display: view === 'lateral' ? 'flex' : 'none', flex: 1, width: '100%', height: '100%' }}>
              <LateralMovementD3
                svgRef={lateralSvgRef}
                nodes={lateralData.nodes}
                edges={lateralData.edges}
                chains={lateralData.chains}
                totalEvents={lateralData.total_events}
                theme={T}
              />
            </div>
            <div style={{ display: view === 'attribution' ? 'flex' : 'none', flex: 1, overflow: 'auto' }}>
              {view === 'attribution' && <AptAttributionTab caseId={id} />}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
