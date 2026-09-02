import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Loader2, PenLine } from 'lucide-react';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import { networkAPI, casesAPI, iocsAPI, evidenceAPI } from '../utils/api';
import { useTheme } from '../utils/theme';
import AttackPathD3 from '../components/network/AttackPathD3';
import LateralMovementD3 from '../components/network/LateralMovementD3';
import AptAttributionTab from '../components/mitre/AptAttributionTab';
import NetworkExplorer from '../components/networkmap/NetworkExplorer';
import TriagePanel from '../components/networkmap/TriagePanel';
import InvestigationDrawer from '../components/networkmap/InvestigationDrawer';
import ColorblindToggle from '../components/networkmap/ColorblindToggle';
import { Segment, Action } from '../components/networkmap/MapControls';
import { triageStats } from '../components/networkmap/utils/triageStats';
import { foldUrlNodes, URL_SCOPES } from '../components/networkmap/utils/foldUrlNodes';
import { collectionLabel } from '../components/networkmap/utils/collectionLabel';
import { declareZone, withdrawZone, countZones, declaredZoneEntries } from '../components/networkmap/utils/zoneDeclaration';
import { transformGraphData } from '../components/networkmap/utils/graphDataTransform';

const VIEWS = [
  { id: 'network',     labelKey: 'caseIntelligence.views.network' },
  { id: 'attack',      labelKey: 'caseIntelligence.views.attack' },
  { id: 'lateral',     labelKey: 'caseIntelligence.views.lateral' },
  { id: 'attribution', labelKey: 'caseIntelligence.views.attribution' },
];

const LAYOUTS = ['organic', 'zones'];

const bandStat   = { fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)', whiteSpace: 'nowrap' };
const bandStrong = { color: 'var(--fl-text)', fontWeight: 600 };

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
  const [caseEvidences, setCaseEvidences] = useState([]);
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
  const [schemaEditingBy, setSchemaEditingBy] = useState(null);
  const schemaEditTimer = useRef(null);

  const [selectedNode,      setSelectedNode]      = useState(null);
  const [cytoscapeElements, setCytoscapeElements] = useState([]);
  const [cyInstance,        setCyInstance]        = useState(null);
  const [allEdges,          setAllEdges]          = useState([]);

  const [annotations,     setAnnotations]     = useState({ zones: [], node_overrides: {} });
  const [colorblindMode,  setColorblindMode]  = useState(() => localStorage.getItem('nm_colorblind') === '1');
  const [nodeColorOverrides] = useState(() => {
    try { return JSON.parse(localStorage.getItem('nm_node_colors') || '{}'); } catch { return {}; }
  });
  const saveTimer = useRef(null);

  const [layoutMode, setLayoutMode] = useState('zones');
  const [relayout, setRelayout]     = useState(0);
  const [urlScope, setUrlScope]     = useState(URL_SCOPES.MACHINES);
  const [folded, setFolded]         = useState(null);

  const caseStats = useMemo(() => triageStats(cytoscapeElements).stats, [cytoscapeElements]);
  const declaredZones = useMemo(() => countZones(
    cytoscapeElements
      .filter(el => el?.data?.source == null && el?.data?.nodeType !== 'cluster')
      .map(el => ({ id: el.data?.id, type: el.data?._raw?.type })),
    annotations.zone_declarations,
  ).declared, [cytoscapeElements, annotations.zone_declarations]);

  function handleDeleteManualNode(nodeId) {
    persistAnnotations({
      ...annotations,
      manual_nodes: (annotations.manual_nodes || []).filter(n => n.id !== nodeId),
    });
  }

  function toggleColorblind() {
    setColorblindMode(v => { const n = !v; localStorage.setItem('nm_colorblind', n ? '1' : '0'); return n; });
  }

  const attackSvgRef = useRef(null);
  const lateralSvgRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);

    evidenceAPI.list(id)
      .then(r => (Array.isArray(r?.data) ? r.data : (r?.data?.evidence || [])))
      .catch(() => [])
      .then(evidences => {
        setCaseEvidences(evidences);
        const scopeIds = initialEvidenceIds || collectionId || evidences[0]?.id || '';

        return Promise.allSettled([
          networkAPI.graphData(id, { view: 'network', evidence_ids: scopeIds }),
          casesAPI.get(id),
          networkAPI.getAnnotations(id),
        ]).then(([graphRes, caseRes, annotRes]) => {
          if (caseRes.status   === 'fulfilled') setCaseInfo(caseRes.value?.data);
          if (graphRes.status  === 'fulfilled') setGraphData(graphRes.value?.data || {});
          if (annotRes.status  === 'fulfilled') setAnnotations(annotRes.value?.data || { zones: [], node_overrides: {} });
          setCollectionScoped(Boolean(scopeIds));
          setActiveEvidenceIds(scopeIds ? scopeIds.split(',').filter(Boolean) : []);
        });
      })
      .catch(() => {
        setError(t('caseIntelligence.load_error'));
      })
      .finally(() => setLoading(false));
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
    const f = foldUrlNodes(graphData.network, urlScope);
    setFolded(f);
    const { elements: els } = transformGraphData(
      { ...graphData.network, nodes: f.nodes, edges: f.edges }, overrides);
    if (iocHits) {
      els.forEach(el => {
        if (el.data?.source || !el.data?.id) return;
        const idv = String(el.data.id).toLowerCase();
        const lbl = String(el.data.label || '').toLowerCase().replace(/\s*\(\d+\)\s*$/, '');
        if (iocHits.has(idv) || iocHits.has(lbl)) el.data._iocHit = 1;
      });
    }
    const decls = annotations?.zone_declarations || {};
    els.forEach(el => {
      if (el.data?.source || !el.data?.id) return;
      const d = decls[el.data.id];
      if (d) el.data._zoneDeclared = d.zone;
    });
    setCytoscapeElements(els);
    setAllEdges(els.filter(e => e.data?.source));
  }, [graphData.network, annotations, iocHits, urlScope]);

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

  function handleDeclareZone(nodeId, zone) {
    persistAnnotations({
      ...annotations,
      zone_declarations: declareZone(
        annotations.zone_declarations, nodeId, zone,
        currentUsername, new Date().toISOString(),
      ),
    });
  }
  function handleWithdrawZone(nodeId) {
    persistAnnotations({
      ...annotations,
      zone_declarations: withdrawZone(annotations.zone_declarations, nodeId),
    });
  }

  const refetchNetwork = useCallback(async (ids, from, to) => {
    setFilterLoading(true);
    const params = { view: 'network' };
    if (ids.length > 0) params.evidence_ids = ids.join(',');
    if (from) params.from_ts = from;
    if (to)   params.to_ts   = to;
    const [graphRes] = await Promise.allSettled([
      networkAPI.graphData(id, params),
    ]);
    if (graphRes.status  === 'fulfilled' && graphRes.value?.data?.network)
      setGraphData(prev => ({ ...prev, network: graphRes.value.data.network }));
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
        padding: '9px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0, flexWrap: 'wrap', gap: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 14, fontWeight: 700, color: T.text, letterSpacing: '-0.01em' }}>
            {t('caseIntelligence.title')}
          </span>
          <span style={{ fontSize: 11, color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontFeatureSettings: '"tnum"' }}>
            {caseInfo?.case_number || ''}{caseInfo?.title ? ` — ${caseInfo.title}` : ''}
          </span>
          {collectionScoped && (
            <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>
              {t('caseIntelligence.collection_scoped')}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <Segment
            label={t('caseIntelligence.title')}
            options={VIEWS.map(v => ({ id: v.id, label: t(v.labelKey) }))}
            active={view}
            onChange={setView}
          />

          <span style={{ width: 1, height: 16, background: T.border }} />

          <Segment
            label={t('caseIntelligence.case_mode')}
            options={[
              { id: 'case',   label: t('caseIntelligence.case_mode') },
              { id: 'global', label: t('caseIntelligence.global_mode') },
            ]}
            active="case"
            onChange={(m) => { if (m === 'global') navigate(`/cases/${id}/global-map`); }}
          />
        </div>
      </div>

      {view === 'network' && (
        <div style={{
          display: 'flex', alignItems: 'center', flexWrap: 'wrap',
          borderBottom: `1px solid ${T.border}`, background: T.panel, flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap', padding: '8px 14px', flex: '1 1 auto' }}>
            <span style={bandStat}><b style={bandStrong}>{caseStats.nodes}</b> {t('networkMap.band.nodes')}</span>
            <span style={bandStat}><b style={bandStrong}>{caseStats.edges}</b> {t('networkMap.band.edges')}</span>
            {caseStats.ext > 0 && (
              <span style={bandStat}><b style={bandStrong}>{caseStats.ext}</b> {t('networkMap.band.zone_external', { count: caseStats.ext })} {t('networkMap.band.zones_inferred', { count: caseStats.ext })}</span>
            )}
            {declaredZoneEntries(declaredZones).map(({ zone, count, key }) => (
              <span key={zone} style={{ ...bandStat, color: 'var(--fl-warn)' }}>
                <b style={{ ...bandStrong, color: 'var(--fl-warn)' }}>{count}</b> {t(key, { count })}
              </span>
            ))}
            {caseStats.susp > 0 && (
              <span style={{ ...bandStat, color: 'var(--fl-warn)' }}>{t('networkMap.triage.suspects', { count: caseStats.susp })}</span>
            )}
            {caseStats.ioc > 0 && (
              <span style={{ ...bandStat, color: 'var(--fl-danger)' }}>{t('networkMap.triage.ioc_count', { count: caseStats.ioc })}</span>
            )}
            {caseStats.nodes > 0 && caseStats.edges === 0 && (
              <span style={{ ...bandStat, color: 'var(--fl-warn)' }}>{t('networkMap.band.no_link_at_all')}</span>
            )}
            {folded?.folded?.urls > 0 && (
              <span style={bandStat}>
                {urlScope === URL_SCOPES.DOMAINS
                  ? t('networkMap.scope.folded', { urls: folded.folded.urls, hosts: folded.folded.hosts })
                  : t('networkMap.scope.hidden', { count: folded.folded.urls })}
              </span>
            )}
          </div>

          <div style={{ width: 1, alignSelf: 'stretch', background: 'var(--fl-border2)', margin: '6px 0' }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', padding: '8px 14px', flex: '0 0 auto' }}>
            {caseEvidences.length > 1 && (
              <Segment
                label={t('caseIntelligence.collection')}
                options={caseEvidences.map(e => ({
                  id: e.id,
                  label: collectionLabel(e.original_filename || e.name || e.id),
                }))}
                active={activeEvidenceIds[0] || ''}
                onChange={(evId) => handleEvidenceFilter([evId])}
              />
            )}
            <Segment
              label={t('networkMap.scope.machines')}
              options={[URL_SCOPES.MACHINES, URL_SCOPES.DOMAINS, URL_SCOPES.ALL]
                .map(sc => ({ id: sc, label: t(`networkMap.scope.${sc}`) }))}
              active={urlScope}
              onChange={setUrlScope}
            />
            <Segment
              label={t('networkMap.layout.organic')}
              options={LAYOUTS.map(l => ({ id: l, label: t(`networkMap.layout.${l}`) }))}
              active={layoutMode}
              onChange={setLayoutMode}
            />
            <Action onClick={() => setRelayout(n => n + 1)} title={t('networkMap.layout.reorganize_hint')}>
              {t('networkMap.layout.reorganize')}
            </Action>
            <ColorblindToggle active={colorblindMode} onToggle={toggleColorblind} />
            <Action onClick={exportPng} title={t('caseIntelligence.export_png_title', { view: t(activeView.labelKey) })}>
              PNG
            </Action>
          </div>
        </div>
      )}

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
            borderRadius: 4, padding: '5px 12px', pointerEvents: 'none',
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
              <NetworkExplorer
                elements={cytoscapeElements}
                onNodeSelect={setSelectedNode}
                onNodeDeselect={() => setSelectedNode(null)}
                selectedNodeId={selectedNode?.id}
                colorblindMode={colorblindMode}
                nodeColorOverrides={nodeColorOverrides}
                layoutMode={layoutMode}
                relayoutNonce={relayout}
                zoneDeclarations={annotations.zone_declarations}
                machinesWithoutLink={graphData.network?.identity?.machines_without_link || []}
                savedPositions={annotations.node_positions || {}}
                onPositionsSave={handlePositionsSave}
                onCyReady={setCyInstance}
              />
              {!selectedNode && (
                <TriagePanel
                  elements={cytoscapeElements}
                  cy={cyInstance}
                  caseId={id}
                  onPivot={(value) => navigate(`/super-timeline?caseId=${id}&search=${encodeURIComponent(value)}`)}
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
                  zoneDeclarations={annotations.zone_declarations}
                  onDeclareZone={handleDeclareZone}
                  onWithdrawZone={handleWithdrawZone}
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
