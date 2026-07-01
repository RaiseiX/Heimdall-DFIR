// frontend/src/pages/GlobalNetworkMapPage.jsx
import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Globe, Share2, Filter } from 'lucide-react';
import NetworkExplorer from '../components/networkmap/NetworkExplorer';
import GlobalMapStats from '../components/globalnetworkmap/GlobalMapStats';
import GlobalMapToolbar from '../components/globalnetworkmap/GlobalMapToolbar';
import InvestigationDrawer from '../components/networkmap/InvestigationDrawer';
import ZonePanel from '../components/networkmap/ZonePanel';
import IntelViewSwitcher from '../components/network/IntelViewSwitcher';
import LateralMovementD3 from '../components/network/LateralMovementD3';
import { transformGlobalGraphData } from '../components/globalnetworkmap/utils/transformGlobalGraphData';
import { networkAPI, casesAPI } from '../utils/api';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import { useTheme } from '../utils/theme';
import { useTranslation } from 'react-i18next';

const GLOBAL_VIEWS = [
  { id: 'network', labelKey: 'caseIntelligence.views.network', icon: Globe },
  { id: 'lateral', labelKey: 'caseIntelligence.views.lateral', icon: Share2 },
];

const ALL_TYPES = new Set(['internal', 'external', 'domain', 'url', 'suspicious']);
const POSITIONS_KEY = (caseId) => `gnm_positions_${caseId}`;

export default function GlobalNetworkMapPage() {
  const { t } = useTranslation();
  const { id: caseId } = useParams();
  const navigate = useNavigate();
  const T = useTheme();

  // ── View (network | lateral) ──────────────────────────────────────────────
  const [view, setView] = useState('network');

  // ── Data ──────────────────────────────────────────────────────────────────
  const [loading,  setLoading]  = useState(true);
  const [rawData,  setRawData]  = useState(null);

  // ── Lateral movement (case-wide; same endpoint as case mode) ──────────────
  const [lateralData, setLateralData]       = useState({ nodes: [], edges: [], chains: [], total_events: 0 });
  const [lateralLoading, setLateralLoading] = useState(false);
  const lateralLoaded = useRef(false);

  // ── Filters ───────────────────────────────────────────────────────────────
  const [selectedNode,      setSelectedNode]      = useState(null);
  const [activeTypes,       setActiveTypes]       = useState(new Set(ALL_TYPES));
  const [activeEvidenceIds, setActiveEvidenceIds] = useState(new Set());
  const [search,            setSearch]            = useState('');

  // ── Shared canvas state (persisted to DB) ─────────────────────────────────
  const [annotations,     setAnnotations]     = useState({ zones: [], node_overrides: {}, manual_nodes: [], subnet_rules: [] });
  const [drawingZoneType, setDrawingZoneType] = useState(null);
  const [placingAsset,    setPlacingAsset]    = useState(null);
  const saveTimer = useRef(null);

  // ── Per-analyst canvas state (localStorage) ───────────────────────────────
  const [colorblindMode,     setColorblindMode]     = useState(() => localStorage.getItem('gnm_colorblind') === '1');
  const [nodeColorOverrides, setNodeColorOverrides] = useState(() => {
    try { return JSON.parse(localStorage.getItem('gnm_node_colors') || '{}'); } catch { return {}; }
  });
  const [savedPositions, setSavedPositions] = useState(() => {
    try { return JSON.parse(localStorage.getItem(POSITIONS_KEY(caseId)) || '{}'); } catch { return {}; }
  });

  // ── Live presence ─────────────────────────────────────────────────────────
  const [presenceUsers, setPresenceUsers] = useState([]);
  const { socket } = useSocket();

  useEffect(() => {
    if (!socket || !caseId) return;
    socket.emit('networkmap:join', { caseId });
    return () => socket.emit('networkmap:leave', { caseId });
  }, [socket, caseId]);

  useSocketEvent(socket, 'networkmap:presence', (users) => {
    setPresenceUsers(Array.isArray(users) ? users : []);
  });

  // ── Load graph + global annotations ──────────────────────────────────────
  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    Promise.all([
      networkAPI.globalGraph(caseId),
      networkAPI.getAnnotations(caseId),
    ])
      .then(([graphRes, annotRes]) => {
        const data  = graphRes.data;
        const annot = annotRes.data;
        setRawData(data);
        setActiveEvidenceIds(new Set((data.evidence_sources || []).map(e => e.id)));
        setAnnotations({
          zones:          annot.global_zones          || [],
          node_overrides: annot.global_node_overrides || {},
          manual_nodes:   annot.global_manual_nodes   || [],
          subnet_rules:   annot.global_subnet_rules   || [],
        });
      })
      .catch(err => console.error('[GlobalNetworkMap]', err))
      .finally(() => setLoading(false));
  }, [caseId]);

  // ── Lazy-load lateral movement on first switch to the lateral view ────────
  useEffect(() => {
    if (view !== 'lateral' || lateralLoaded.current || !caseId) return;
    lateralLoaded.current = true;
    setLateralLoading(true);
    casesAPI.lateralMovement(caseId)
      .then(res => {
        const d = res?.data || {};
        setLateralData({ nodes: d.nodes || [], edges: d.edges || [], chains: d.chains || [], total_events: d.total_events || 0 });
      })
      .catch(err => console.error('[GlobalNetworkMap lateral]', err))
      .finally(() => setLateralLoading(false));
  }, [view, caseId]);

  // ── Annotation persistence ────────────────────────────────────────────────
  function persistAnnotations(updated) {
    setAnnotations(updated);
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      networkAPI.saveGlobalAnnotations(caseId, {
        zones:          updated.zones,
        node_overrides: updated.node_overrides,
        manual_nodes:   updated.manual_nodes,
        subnet_rules:   updated.subnet_rules,
      }).catch(err => console.error('[global annotations save]', err));
    }, 500);
  }

  function handleZoneDrawn(zone)           { persistAnnotations({ ...annotations, zones: [...annotations.zones, zone] }); setDrawingZoneType(null); }
  function handleZoneUpdate(id, patch)     { persistAnnotations({ ...annotations, zones: annotations.zones.map(z => z.id === id ? { ...z, ...patch } : z) }); }
  function handleZoneDelete(id)            { persistAnnotations({ ...annotations, zones: annotations.zones.filter(z => z.id !== id) }); }

  // ── Colorblind + node color overrides ────────────────────────────────────
  function toggleColorblind() {
    setColorblindMode(v => { const n = !v; localStorage.setItem('gnm_colorblind', n ? '1' : '0'); return n; });
  }
  function handleNodeColorChange(typeId, color) {
    setNodeColorOverrides(prev => { const next = { ...prev, [typeId]: color }; localStorage.setItem('gnm_node_colors', JSON.stringify(next)); return next; });
  }
  function handleNodeColorReset(typeId) {
    setNodeColorOverrides(prev => { const next = { ...prev }; delete next[typeId]; localStorage.setItem('gnm_node_colors', JSON.stringify(next)); return next; });
  }

  // ── Manual asset placement ────────────────────────────────────────────────
  const handleAssetPlaced = useCallback((position) => {
    if (!placingAsset) return;
    const id = `manual-${Date.now()}`;
    persistAnnotations({ ...annotations, manual_nodes: [...annotations.manual_nodes, { id, typeId: placingAsset.typeId, label: placingAsset.label || placingAsset.typeId, position, colorOverride: placingAsset.colorOverride || null }] });
    setPlacingAsset(null);
  }, [placingAsset, annotations]);

  // ── Position persistence (per-analyst) ───────────────────────────────────
  const handlePositionsSave = useCallback((positions) => {
    setSavedPositions(positions);
    try { localStorage.setItem(POSITIONS_KEY(caseId), JSON.stringify(positions)); } catch {}
  }, [caseId]);

  // ── Subnet rule handlers ─────────────────────────────────────────────────
  function handleSubnetRuleAdd(rule) {
    persistAnnotations({ ...annotations, subnet_rules: [...(annotations.subnet_rules || []), rule] });
  }
  function handleSubnetRuleDelete(id) {
    persistAnnotations({ ...annotations, subnet_rules: (annotations.subnet_rules || []).filter(r => r.id !== id) });
  }

  // ── allElements — reactive to rawData + subnet_rules ────────────────────
  const allElements = useMemo(() => {
    if (!rawData) return [];
    return transformGlobalGraphData(rawData, annotations.subnet_rules || []);
  }, [rawData, annotations.subnet_rules]);

  // ── Client-side filters ───────────────────────────────────────────────────
  const evidenceSources = rawData?.evidence_sources || [];

  const elements = useMemo(() => {
    if (!allElements.length) return [];
    // No evidence selected → empty canvas (nothing to show)
    if (activeEvidenceIds.size === 0) return [];
    const activeNodeIds = new Set();

    // Pass 1: filter all non-cluster nodes
    for (const el of allElements) {
      if (el.data?.source != null) continue;
      if (el.data?.nodeType === 'cluster') continue;
      const logicalType    = el.data?._raw?.type || '';
      const passesType     = activeTypes.has(logicalType) || activeTypes.has(el.data?.nodeType || '') || (el.data?.is_suspicious && activeTypes.has('suspicious'));
      const evidenceIds    = el.data?.evidence_ids || [];
      const passesEvidence = evidenceIds.length === 0 || evidenceIds.some(eid => activeEvidenceIds.has(eid));
      const term           = search.toLowerCase();
      const passesSearch   = !term || (el.data?.id || '').toLowerCase().includes(term) || (el.data?.label || '').toLowerCase().includes(term);
      if (passesType && passesEvidence && passesSearch) activeNodeIds.add(el.data.id);
    }

    // Pass 2: include cluster nodes only if they have at least one active child
    // (Cytoscape requires parent nodes to exist when a child references them)
    for (const el of allElements) {
      if (el.data?.source != null || el.data?.nodeType !== 'cluster') continue;
      const hasActiveChild = allElements.some(
        child => child.data?.parent === el.data.id && activeNodeIds.has(child.data?.id)
      );
      if (hasActiveChild) activeNodeIds.add(el.data.id);
    }

    return allElements.filter(el =>
      el.data?.source != null
        ? activeNodeIds.has(el.data.source) && activeNodeIds.has(el.data.target)
        : activeNodeIds.has(el.data?.id)
    );
  }, [allElements, activeTypes, activeEvidenceIds, search]);

  const correlatedNodes = useMemo(() =>
    allElements
      .filter(el => el.data?.source == null && (el.data?.correlationCount || 0) >= 2)
      .map(el => ({ id: el.data.id, count: el.data.correlationCount, suspicious: el.data?.is_suspicious || false })),
  [allElements]);

  const stats = useMemo(() => {
    if (!rawData) return null;
    return {
      nodeCount:       rawData.nodes.length,
      edgeCount:       rawData.edges.length,
      evidenceCount:   (rawData.evidence_sources || []).length,
      correlatedCount: rawData.nodes.filter(n => (n.evidence_ids || []).length >= 2).length,
      truncated:       rawData.truncated,
    };
  }, [rawData]);

  const handleTypeToggle     = type => setActiveTypes(prev => { const n = new Set(prev); n.has(type) ? n.delete(type) : n.add(type); return n; });
  const handleEvidenceToggle = id   => setActiveEvidenceIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  // ── InvestigationDrawer integration ──────────────────────────────────────
  const allEdges = useMemo(() => elements.filter(el => el.data?.source != null), [elements]);

  const handleSelectPeer = useCallback((peerId) => {
    const peerEl = elements.find(el => el.data?.id === peerId && !el.data?.source);
    if (peerEl) setSelectedNode(peerEl.data);
  }, [elements]);

  function handleOverrideType(nodeId, typeId) {
    persistAnnotations({ ...annotations, node_overrides: { ...annotations.node_overrides, [nodeId]: typeId } });
  }
  function handleResetType(nodeId) {
    const next = { ...annotations.node_overrides };
    delete next[nodeId];
    persistAnnotations({ ...annotations, node_overrides: next });
  }
  function handleDeleteManualNode(nodeId) {
    persistAnnotations({ ...annotations, manual_nodes: annotations.manual_nodes.filter(n => n.id !== nodeId) });
    setSelectedNode(null);
  }

  // ── Network canvas state (loading/empty handled inline, not via early return,
  //     so the header + lateral view stay reachable regardless) ──────────────
  const networkEmpty = !rawData || rawData.nodes.length === 0;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--fl-bg)' }}>

      {/* ── Premium header: title + view switcher + mode toggle ─────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0,
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 15, fontWeight: 700, color: T.text, letterSpacing: '-0.01em' }}>
              {t('caseIntelligence.title')}
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
              <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)', flexShrink: 0 }} />
              {t('caseIntelligence.global_mode')}
            </span>
          </div>
          <div style={{ fontSize: 11, color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontFeatureSettings: '"tnum"', marginTop: 2 }}>
            {stats ? `${stats.nodeCount} nodes · ${stats.edgeCount} edges · ${stats.evidenceCount} sources` : '—'}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <IntelViewSwitcher
            views={GLOBAL_VIEWS.map(v => ({ id: v.id, label: t(v.labelKey), icon: v.icon }))}
            active={view}
            onChange={setView}
          />

          <div style={{ width: 1, height: 20, background: T.border }} />

          <IntelViewSwitcher
            views={[
              { id: 'case',   label: t('caseIntelligence.case_mode'),   icon: Filter },
              { id: 'global', label: t('caseIntelligence.global_mode'), icon: Globe },
            ]}
            active="global"
            onChange={(m) => { if (m === 'case') navigate(`/cases/${caseId}/graph`); }}
          />
        </div>
      </div>

      {/* ── Lateral view: full-bleed propagation graph (case-wide data) ──── */}
      <div style={{ display: view === 'lateral' ? 'flex' : 'none', flex: 1, position: 'relative', overflow: 'hidden' }}>
        {lateralLoading ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13 }}>
            {t('common.loading')}
          </div>
        ) : (
          <LateralMovementD3
            nodes={lateralData.nodes}
            edges={lateralData.edges}
            chains={lateralData.chains}
            totalEvents={lateralData.total_events}
            theme={T}
          />
        )}
      </div>

      {/* ── Network view: ZonePanel | Canvas | DetailPanel ─────────────── */}
      <div style={{ display: view === 'network' ? 'flex' : 'none', flex: 1, overflow: 'hidden', position: 'relative' }}>

        {loading && (
          <div style={{ position: 'absolute', inset: 0, zIndex: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-bg) 80%, transparent)', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13 }}>
            {t('networkMap.loading_global')}
          </div>
        )}
        {!loading && networkEmpty && (
          <div style={{ position: 'absolute', inset: 0, zIndex: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--fl-bg)', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13 }}>
            {t('networkMap.no_case_data')}
          </div>
        )}

        {/* Left: ZonePanel — always visible, same as NetworkMapPage */}
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
          onStartPlace={asset => setPlacingAsset(asset)}
          onCancelPlace={() => setPlacingAsset(null)}
          subnetRules={annotations.subnet_rules || []}
          onSubnetRuleAdd={handleSubnetRuleAdd}
          onSubnetRuleDelete={handleSubnetRuleDelete}
        />

        {/* Center: Graph canvas with floating overlays */}
        <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
          <NetworkExplorer
            elements={elements}
            onNodeSelect={node => setSelectedNode(node)}
            onNodeDeselect={() => setSelectedNode(null)}
            selectedNodeId={selectedNode?.id}
            correlatedNodes={correlatedNodes}
            zones={annotations.zones}
            drawingZoneType={drawingZoneType}
            onZoneDrawn={handleZoneDrawn}
            onZoneUpdate={handleZoneUpdate}
            onZoneDelete={handleZoneDelete}
            nodeColorOverrides={nodeColorOverrides}
            colorblindMode={colorblindMode}
            manualNodes={annotations.manual_nodes}
            placingAsset={placingAsset}
            onAssetPlaced={handleAssetPlaced}
            savedPositions={savedPositions}
            onPositionsSave={handlePositionsSave}
          />

          {/* Floating overlays — positioned absolute on the canvas */}
          <GlobalMapStats stats={stats} loading={false} />

          <GlobalMapToolbar
            evidenceSources={evidenceSources}
            activeTypes={activeTypes}
            activeEvidenceIds={activeEvidenceIds}
            onTypeToggle={handleTypeToggle}
            onEvidenceToggle={handleEvidenceToggle}
            search={search}
            onSearch={setSearch}
          />

          {/* Live presence — bottom right corner of canvas */}
          {presenceUsers.length > 0 && (
            <div style={{ position: 'absolute', bottom: 48, right: 12, zIndex: 20, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', letterSpacing: '0.06em' }}>SUR LA CARTE</span>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                {presenceUsers.slice(0, 6).map((u, i) => {
                  const col = ['var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-purple)', 'var(--fl-danger)', 'var(--fl-purple)'][i % 6];
                  const ini = u.full_name ? u.full_name.split(' ').map(p => p[0]).join('').substring(0, 2).toUpperCase() : (u.username || '?').substring(0, 2).toUpperCase();
                  return (
                    <div key={u.id + i} title={u.full_name || u.username} style={{ width: 22, height: 22, borderRadius: '50%', background: `color-mix(in srgb, ${col} 13%, transparent)`, border: `1.5px solid color-mix(in srgb, ${col} 50%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: col, marginLeft: i > 0 ? -6 : 0, boxShadow: '0 0 0 1px var(--fl-bg)' }}>{ini}</div>
                  );
                })}
                {presenceUsers.length > 6 && <div style={{ width: 22, height: 22, borderRadius: '50%', background: 'var(--fl-raised)', border: '1.5px solid var(--fl-border3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)', marginLeft: -6, boxShadow: '0 0 0 1px var(--fl-bg)' }}>+{presenceUsers.length - 6}</div>}
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fl-ok)', marginLeft: 5, boxShadow: '0 0 4px color-mix(in srgb, var(--fl-ok) 50%, transparent)' }} title="En direct" />
              </div>
            </div>
          )}

        </div>

        {/* Right: InvestigationDrawer — flex sibling so it shrinks canvas (same pattern as NetworkMapPage) */}
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
            onDeleteManualNode={handleDeleteManualNode}
          />
        )}
      </div>
    </div>
  );
}
