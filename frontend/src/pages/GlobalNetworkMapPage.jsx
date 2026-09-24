import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import NetworkExplorer from '../components/networkmap/NetworkExplorer';
import GlobalMapStats from '../components/globalnetworkmap/GlobalMapStats';
import GlobalMapToolbar from '../components/globalnetworkmap/GlobalMapToolbar';
import InvestigationDrawer from '../components/networkmap/InvestigationDrawer';
import ColorblindToggle from '../components/networkmap/ColorblindToggle';
import { Segment, Action } from '../components/networkmap/MapControls';
import LateralMovementD3 from '../components/network/LateralMovementD3';
import LinkRegister from '../components/networkmap/LinkRegister';
import { defaultNetworkView } from '../components/networkmap/utils/registerGroups';
import { declareZone, withdrawZone } from '../components/networkmap/utils/zoneDeclaration';
import { currentUser } from '../utils/auth';
import { foldUrlNodes, URL_SCOPES } from '../components/networkmap/utils/foldUrlNodes';
import { mapBandCounts } from '../components/globalnetworkmap/utils/mapBandCounts';
import { transformGlobalGraphData } from '../components/globalnetworkmap/utils/transformGlobalGraphData';
import { networkAPI, casesAPI } from '../utils/api';
import { formatCount } from '../utils/formatCount';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import { useTheme } from '../utils/theme';
import { useTranslation } from 'react-i18next';

const GLOBAL_VIEWS = [
  { id: 'network', labelKey: 'caseIntelligence.views.network' },
  { id: 'lateral', labelKey: 'caseIntelligence.views.lateral' },
];

const ALL_TYPES = new Set(['internal', 'external', 'collection', 'domain', 'url', 'suspicious']);
const LAYOUTS = ['organic', 'zones'];
const POSITIONS_KEY = (caseId) => `gnm_positions_${caseId}`;

export default function GlobalNetworkMapPage() {
  const { t } = useTranslation();
  const { id: caseId } = useParams();
  const navigate = useNavigate();
  const T = useTheme();

  const [view, setView] = useState('network');

  const [loading,  setLoading]  = useState(true);
  const [rawData,  setRawData]  = useState(null);

  const [registerData, setRegisterData] = useState(null);
  const [surface,      setSurface]      = useState('auto');

  const [urlScope, setUrlScope] = useState(URL_SCOPES.MACHINES);

  const [layoutMode, setLayoutMode] = useState('zones');
  const [relayout, setRelayout]     = useState(0);

  const [lateralData, setLateralData]       = useState({ nodes: [], edges: [], chains: [], total_events: 0 });
  const [lateralLoading, setLateralLoading] = useState(false);
  const lateralLoaded = useRef(false);

  const [selectedNode,      setSelectedNode]      = useState(null);
  const [activeTypes,       setActiveTypes]       = useState(new Set(ALL_TYPES));
  const [activeEvidenceIds, setActiveEvidenceIds] = useState(new Set());
  const [search,            setSearch]            = useState('');

  const [annotations,     setAnnotations]     = useState({ zones: [], node_overrides: {}, manual_nodes: [], subnet_rules: [], zone_declarations: {} });
  const saveTimer = useRef(null);

  const [colorblindMode, setColorblindMode] = useState(() => localStorage.getItem('gnm_colorblind') === '1');
  const [nodeColorOverrides] = useState(() => {
    try { return JSON.parse(localStorage.getItem('gnm_node_colors') || '{}'); } catch { return {}; }
  });
  const [savedPositions, setSavedPositions] = useState(() => {
    try { return JSON.parse(localStorage.getItem(POSITIONS_KEY(caseId)) || '{}'); } catch { return {}; }
  });

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

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    Promise.all([
      networkAPI.globalGraph(caseId),
      networkAPI.getAnnotations(caseId),
      networkAPI.register(caseId).catch(() => ({ data: null })),
    ])
      .then(([graphRes, annotRes, registerRes]) => {
        const data  = graphRes.data;
        const annot = annotRes.data;
        setRawData(data);
        setRegisterData(registerRes?.data || null);
        setActiveEvidenceIds(new Set((data.evidence_sources || []).map(e => e.id)));
        setAnnotations({
          zones:             annot.global_zones          || [],
          node_overrides:    annot.global_node_overrides || {},
          manual_nodes:      annot.global_manual_nodes   || [],
          subnet_rules:      annot.global_subnet_rules   || [],
          zone_declarations: annot.zone_declarations     || {},
        });
      })
      .catch(err => console.error('[GlobalNetworkMap]', err))
      .finally(() => setLoading(false));
  }, [caseId]);

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

  function persistAnnotations(updated) {
    setAnnotations(updated);
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      networkAPI.saveGlobalAnnotations(caseId, {
        zones:             updated.zones,
        node_overrides:    updated.node_overrides,
        manual_nodes:      updated.manual_nodes,
        subnet_rules:      updated.subnet_rules,
        zone_declarations: updated.zone_declarations,
      }).catch(err => console.error('[global annotations save]', err));
    }, 500);
  }

  function toggleColorblind() {
    setColorblindMode(v => { const n = !v; localStorage.setItem('gnm_colorblind', n ? '1' : '0'); return n; });
  }

  const handlePositionsSave = useCallback((positions) => {
    setSavedPositions(positions);
    try { localStorage.setItem(POSITIONS_KEY(caseId), JSON.stringify(positions)); } catch {}
  }, [caseId]);

  function handleSubnetRuleAdd(rule) {
    persistAnnotations({ ...annotations, subnet_rules: [...(annotations.subnet_rules || []), rule] });
  }
  function handleSubnetRuleDelete(id) {
    persistAnnotations({ ...annotations, subnet_rules: (annotations.subnet_rules || []).filter(r => r.id !== id) });
  }

  const folded = useMemo(
    () => foldUrlNodes(rawData, urlScope),
    [rawData, urlScope],
  );

  const allElements = useMemo(() => {
    if (!rawData) return [];
    const els = transformGlobalGraphData(
      { ...rawData, nodes: folded.nodes, edges: folded.edges },
      annotations.subnet_rules || [],
    );
    const decls = annotations.zone_declarations || {};
    for (const el of els) {
      if (el.data?.source != null || !el.data?.id) continue;
      const d = decls[el.data.id];
      if (d) el.data._zoneDeclared = d.zone;
      else delete el.data._zoneDeclared;
    }
    return els;
  }, [rawData, folded, annotations.subnet_rules, annotations.zone_declarations]);

  const evidenceSources = rawData?.evidence_sources || [];

  const elements = useMemo(() => {
    if (!allElements.length) return [];
    if (activeEvidenceIds.size === 0) return [];
    const activeNodeIds = new Set();

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

  const autoSurface = useMemo(() => defaultNetworkView({
    initiators: (registerData?.machines || []).length,
    machineLinks: 0,
  }), [registerData]);
  const activeSurface = surface === 'auto' ? autoSurface : surface;

  const bandCounts = useMemo(
    () => mapBandCounts({ rawData, elements, folded, declarations: annotations.zone_declarations }),
    [rawData, elements, folded, annotations.zone_declarations],
  );

  const surfaceSwitch = (
    <>
      {rawData ? (
        <Segment
          label={t('networkMap.register.title')}
          options={['register', 'graph'].map(s => ({ id: s, label: t(`networkMap.register.view_${s}`) }))}
          active={activeSurface}
          onChange={setSurface}
        />
      ) : null}

      {surface === 'auto' && activeSurface === 'register' && (
        <span style={{ fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-muted)' }}>
          {t(`networkMap.register.auto_${autoSurface}`)}
        </span>
      )}
    </>
  );

  const colorblindSwitch = <ColorblindToggle active={colorblindMode} onToggle={toggleColorblind} />;

  const handleTypeToggle     = type => setActiveTypes(prev => { const n = new Set(prev); n.has(type) ? n.delete(type) : n.add(type); return n; });
  const handleEvidenceToggle = id   => setActiveEvidenceIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

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

  function handleDeclareZone(nodeId, zone) {
    persistAnnotations({
      ...annotations,
      zone_declarations: declareZone(
        annotations.zone_declarations, nodeId, zone,
        currentUser().username, new Date().toISOString(),
      ),
    });
  }
  function handleWithdrawZone(nodeId) {
    persistAnnotations({
      ...annotations,
      zone_declarations: withdrawZone(annotations.zone_declarations, nodeId),
    });
  }

  const networkEmpty = !rawData || rawData.nodes.length === 0;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--fl-bg)' }}>

      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '9px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0, flexWrap: 'wrap', gap: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 14, fontWeight: 700, color: T.text, letterSpacing: '-0.01em' }}>
            {t('caseIntelligence.title')}
          </span>
          <span style={{ fontSize: 11, color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontFeatureSettings: '"tnum"' }}>
            {rawData
              ? `${formatCount(bandCounts.totalNodes)} ${t('networkMap.band.nodes')} · ${formatCount(bandCounts.totalEdges)} ${t('networkMap.band.edges')} · ${t('networkMap.evidences', { count: bandCounts.evidences })}`
              : t('networkMap.loading_global')}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <Segment
            label={t('caseIntelligence.title')}
            options={GLOBAL_VIEWS.map(v => ({ id: v.id, label: t(v.labelKey) }))}
            active={view}
            onChange={setView}
          />
          <span style={{ width: 1, height: 16, background: T.border }} />
          <Segment
            label={t('caseIntelligence.global_mode')}
            options={[
              { id: 'case',   label: t('caseIntelligence.case_mode') },
              { id: 'global', label: t('caseIntelligence.global_mode') },
            ]}
            active="global"
            onChange={(m) => { if (m === 'case') navigate(`/cases/${caseId}/graph`); }}
          />
        </div>
      </div>

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

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
          {activeSurface === 'graph' && (
          <div style={{
            display: 'flex', alignItems: 'center', flexWrap: 'wrap',
            borderBottom: '1px solid var(--fl-border)', background: 'var(--fl-panel)',
          }}>
            <div style={{
              display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap',
              padding: '8px 14px', flex: '1 1 auto',
            }}>
              <GlobalMapStats counts={bandCounts} loading={loading} />
              {bandCounts?.foldedUrls > 0 && (
                <span style={{ fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-muted)' }}>
                  {urlScope === URL_SCOPES.DOMAINS
                    ? t('networkMap.scope.folded', { urls: bandCounts.foldedUrls, hosts: bandCounts.foldedHosts })
                    : t('networkMap.scope.hidden', { count: bandCounts.foldedUrls })}
                </span>
              )}
              {bandCounts?.unfoldable > 0 && (
                <span style={{ fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-gold)' }}>
                  {t('networkMap.scope.unfoldable', { count: bandCounts.unfoldable })}
                </span>
              )}
            </div>

            <div style={{ width: 1, alignSelf: 'stretch', background: 'var(--fl-border2)', margin: '6px 0' }} />

            <div style={{
              display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
              padding: '8px 14px', flex: '0 0 auto',
            }}>
              {surfaceSwitch}

              <Segment
                label={t('networkMap.scope.machines')}
                options={[URL_SCOPES.MACHINES, URL_SCOPES.DOMAINS, URL_SCOPES.ALL]
                  .map(s => ({ id: s, label: t(`networkMap.scope.${s}`) }))}
                active={urlScope}
                onChange={setUrlScope}
              />

              <Segment
                label={t('networkMap.layout.organic')}
                options={LAYOUTS.map(id => ({ id, label: t(`networkMap.layout.${id}`) }))}
                active={layoutMode}
                onChange={setLayoutMode}
              />
              <Action onClick={() => setRelayout(n => n + 1)} title={t('networkMap.layout.reorganize_hint')}>
                {t('networkMap.layout.reorganize')}
              </Action>

              <GlobalMapToolbar
                evidenceSources={evidenceSources}
                activeTypes={activeTypes}
                activeEvidenceIds={activeEvidenceIds}
                onTypeToggle={handleTypeToggle}
                onEvidenceToggle={handleEvidenceToggle}
                search={search}
                onSearch={setSearch}
                subnetRules={annotations.subnet_rules || []}
                onSubnetRuleAdd={handleSubnetRuleAdd}
                onSubnetRuleDelete={handleSubnetRuleDelete}
              />

              {colorblindSwitch}
            </div>
          </div>
          )}

          <div style={{
            flex: 1, display: activeSurface === 'register' ? 'block' : 'none', overflow: 'hidden',
          }}>
            <LinkRegister
              data={registerData}
              loading={loading}
              onSelectPeer={peer => setSearch(peer)}
              declarations={annotations.zone_declarations}
              controls={surfaceSwitch}
              trailing={colorblindSwitch}
            />
          </div>

          <div style={{
            flex: 1, display: activeSurface === 'register' ? 'none' : 'flex', position: 'relative', overflow: 'hidden',
          }}>
          <NetworkExplorer
            elements={elements}
            onNodeSelect={node => setSelectedNode(node)}
            onNodeDeselect={() => setSelectedNode(null)}
            selectedNodeId={selectedNode?.id}
            nodeColorOverrides={nodeColorOverrides}
            colorblindMode={colorblindMode}
            layoutMode={layoutMode}
            relayoutNonce={relayout}
            zoneDeclarations={annotations.zone_declarations}
            machinesWithoutLink={bandCounts.withoutLinkNames}
            savedPositions={savedPositions}
            onPositionsSave={handlePositionsSave}
          />

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
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)', marginLeft: 5 }} title={t('networkMap.presence_live')} />
              </div>
            </div>
          )}

          </div>
        </div>

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
            zoneDeclarations={annotations.zone_declarations}
            onDeclareZone={handleDeclareZone}
            onWithdrawZone={handleWithdrawZone}
          />
        )}
      </div>
    </div>
  );
}
