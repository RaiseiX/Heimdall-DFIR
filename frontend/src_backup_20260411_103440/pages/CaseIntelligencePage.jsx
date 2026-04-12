import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { Globe, GitBranch, Share2, Download, Loader2, Target, Filter } from 'lucide-react';
import { networkAPI, casesAPI, collectionAPI } from '../utils/api';
import { useTheme } from '../utils/theme';
import NetworkGraphD3 from '../components/network/NetworkGraphD3';
import AttackPathD3 from '../components/network/AttackPathD3';
import LateralMovementD3 from '../components/network/LateralMovementD3';
import AptAttributionTab from '../components/mitre/AptAttributionTab';

const VIEWS = [
  { id: 'network',     label: 'Topologie Réseau',    icon: Globe,     color: '#4d82c0' },
  { id: 'attack',      label: 'Kill Chain',           icon: GitBranch, color: '#8b5cf6' },
  { id: 'lateral',     label: 'Propagation Latérale', icon: Share2,    color: '#d97c20' },
  { id: 'attribution', label: 'Attribution APT',      icon: Target,    color: '#da3633' },
];

export default function CaseIntelligencePage({ collectionId }) {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const T = useTheme();

  const initialView = VIEWS.find(v => v.id === searchParams.get('view'))?.id || 'network';
  const initialEvidenceIds = searchParams.get('evidence_ids') || '';

  const [view, setView] = useState(initialView);
  const [loading, setLoading] = useState(false);
  const [filterLoading, setFilterLoading] = useState(false);
  const [collectionScoped, setCollectionScoped] = useState(false);
  const [loadingLateral, setLoadingLateral] = useState(false);
  const [graphData, setGraphData] = useState({ network: null, attack: null });
  const [lateralData, setLateralData] = useState({ nodes: [], edges: [], total_events: 0 });
  const [caseInfo, setCaseInfo] = useState(null);
  const [error, setError] = useState(null);
  const [activeEvidenceIds, setActiveEvidenceIds] = useState(
    initialEvidenceIds ? initialEvidenceIds.split(',').filter(Boolean) : []
  );

  const networkSvgRef = useRef(null);
  const attackSvgRef = useRef(null);
  const lateralSvgRef = useRef(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);

    Promise.allSettled([
      networkAPI.graphData(id, { view: 'all' }),
      casesAPI.get(id),
    ]).then(([graphRes, caseRes]) => {
      if (caseRes.status === 'fulfilled') setCaseInfo(caseRes.value?.data);
      if (graphRes.status === 'fulfilled') setGraphData(graphRes.value?.data || {});
    }).catch(() => {
      setError('Erreur lors du chargement');
    }).finally(() => setLoading(false));
  }, [id]);

  const lateralLoaded = useRef(false);
  useEffect(() => {
    if (view !== 'lateral' || lateralLoaded.current || !id) return;
    lateralLoaded.current = true;
    setLoadingLateral(true);
    casesAPI.lateralMovement(id)
      .then(res => {
        const d = res?.data || {};
        setLateralData({ nodes: d.nodes || [], edges: d.edges || [], total_events: d.total_events || 0 });
      })
      .catch(() => {})
      .finally(() => setLoadingLateral(false));
  }, [view, id]);

  useEffect(() => {
    if (!collectionId || !id) return;
    collectionAPI.evidenceIds(id)
      .then(res => {
        const ids = res?.data?.evidence_ids || [];
        if (ids.length > 0) {
          setActiveEvidenceIds(ids);
          setCollectionScoped(true);
          const params = { view: 'network', evidence_ids: ids.join(',') };
          return networkAPI.graphData(id, params).then(r => {
            if (r?.data?.network) setGraphData(prev => ({ ...prev, network: r.data.network }));
          });
        }
      })
      .catch(() => {});
  }, [collectionId, id]);

  const handleEvidenceFilter = useCallback(async (ids) => {
    setActiveEvidenceIds(ids);
    setFilterLoading(true);
    const params = ids.length > 0
      ? { view: 'network', evidence_ids: ids.join(',') }
      : { view: 'network' };
    const res = await networkAPI.graphData(id, params).catch(() => null);
    if (res?.data?.network) setGraphData(prev => ({ ...prev, network: res.data.network }));
    setFilterLoading(false);
  }, [id]);

  const svgRefForView = { network: networkSvgRef, attack: attackSvgRef, lateral: lateralSvgRef };

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
    watermark.setAttribute('fill', '#484f58');
    watermark.setAttribute('font-size', '11');
    watermark.setAttribute('font-family', 'monospace');
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
      ctx.fillStyle = '#0d1117';
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
        padding: '8px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: T.text, display: 'flex', alignItems: 'center', gap: 6 }}>
              <activeView.icon size={14} style={{ color: activeView.color }} />
              Intelligence du Cas
              {collectionScoped && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, fontFamily: 'monospace', padding: '1px 7px', borderRadius: 4, background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030' }}>
                  <Filter size={9} /> Données filtrées à cette collecte
                </span>
              )}
            </div>
            <div style={{ fontSize: 11, color: T.dim, fontFamily: 'monospace' }}>
              {caseInfo?.case_number || ''}{caseInfo?.title ? ` — ${caseInfo.title}` : ''}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ display: 'flex', background: T.bg, border: `1px solid ${T.border}`, borderRadius: 6, overflow: 'hidden' }}>
            {VIEWS.map((v, i) => (
              <button
                key={v.id}
                onClick={() => setView(v.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '5px 12px', fontSize: 12, border: 'none', cursor: 'pointer',
                  borderRight: i < VIEWS.length - 1 ? `1px solid ${T.border}` : 'none',
                  background: view === v.id ? `${v.color}15` : 'transparent',
                  color: view === v.id ? v.color : T.dim,
                  transition: 'all 0.15s',
                }}
              >
                <v.icon size={13} /> {v.label}
              </button>
            ))}
          </div>

          <button
            onClick={exportPng}
            title={`Exporter ${activeView.label} en PNG`}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 10px', fontSize: 12, border: `1px solid ${T.border}`,
              background: 'transparent', color: T.dim, borderRadius: 5, cursor: 'pointer',
            }}
          >
            <Download size={12} /> PNG
          </button>
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
              {filterLoading ? 'Filtrage…' : 'Chargement…'}
            </div>
          </div>
        )}

        {error && (
          <div style={{ padding: 24, textAlign: 'center', color: '#da3633', fontSize: 13 }}>{error}</div>
        )}

        {!error && (
          <>
            <div style={{ display: view === 'network' ? 'flex' : 'none', flex: 1, width: '100%', height: '100%' }}>
              <NetworkGraphD3
                svgRef={networkSvgRef}
                caseId={id}
                nodes={graphData.network?.nodes || []}
                edges={graphData.network?.edges || []}
                evidenceSources={graphData.network?.evidence_sources || []}
                activeEvidenceIds={activeEvidenceIds}
                onEvidenceFilter={handleEvidenceFilter}
                theme={T}
              />
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
