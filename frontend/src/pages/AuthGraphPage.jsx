// frontend/src/pages/AuthGraphPage.jsx
// LogonTracer-style authentication graph for an evidence: users ↔ machines.
// Three views (Graphe / Liens / Statistiques) + a detail drawer with the raw
// auth events behind each user↔machine link.
import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { KeyRound, RefreshCw, ChevronDown, Share2, Table2, BarChart3, X, Clock, ArrowRight, ExternalLink } from 'lucide-react';
import { networkAPI } from '../utils/api';
import { useTheme } from '../utils/theme';
import AuthGraphD3 from '../components/authgraph/AuthGraphD3';
import IntelViewSwitcher from '../components/network/IntelViewSwitcher';

const VIEWS = [
  { id: 'graph',  label: 'Graphe',  icon: Share2 },
  { id: 'links',  label: 'Liens',   icon: Table2 },
  { id: 'stats',  label: 'Stats',   icon: BarChart3 },
];

// LogonType code → color/label (shared with the D3 legend)
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

const ARTIFACT_COLOR = {
  evtx: 'var(--fl-accent)', hayabusa: 'var(--fl-danger)', sysmon: 'var(--fl-purple)',
  catscale_auth: '#f43f5e', catscale_logon: '#22c55e', catscale_ssh: '#10b981',
};

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

export default function AuthGraphPage({ evidenceId: initialEvidenceId = null }) {
  const { id: caseId } = useParams();
  const T = useTheme();

  const [evidenceList, setEvidenceList] = useState([]);
  const [evidenceId, setEvidenceId] = useState(initialEvidenceId);
  const [selectorOpen, setSelectorOpen] = useState(false);

  const [view, setView] = useState('graph');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  // Detail drawer state
  const [selEdge, setSelEdge] = useState(null);
  const [edgeEvents, setEdgeEvents] = useState([]);
  const [edgeEventsLoading, setEdgeEventsLoading] = useState(false);
  const [expandedEvent, setExpandedEvent] = useState(null);

  useEffect(() => { setEvidenceId(initialEvidenceId); }, [initialEvidenceId]);

  // Fetch evidence list for the selector (only needed at case level).
  useEffect(() => {
    if (!caseId) return;
    let alive = true;
    import('../utils/api').then(({ evidenceAPI }) => {
      evidenceAPI.list(caseId)
        .then(r => {
          if (!alive) return;
          const list = Array.isArray(r.data) ? r.data : (r.data?.evidence || []);
          setEvidenceList(list);
        })
        .catch(() => {});
    });
    return () => { alive = false; };
  }, [caseId]);

  const load = useCallback(() => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    setSelEdge(null);
    setEdgeEvents([]);
    const params = {};
    if (evidenceId) params.evidence_ids = evidenceId;
    networkAPI.authGraph(caseId, params)
      .then(res => setData(res.data))
      .catch(err => setError(err?.response?.data?.error || err.message))
      .finally(() => setLoading(false));
  }, [caseId, evidenceId]);

  useEffect(() => { load(); }, [load]);

  // Fetch raw events for a selected edge (user ↔ machine).
  const openEdge = useCallback((edge) => {
    if (!edge) { setSelEdge(null); setEdgeEvents([]); return; }
    setSelEdge(edge);
    setEdgeEventsLoading(true);
    setExpandedEvent(null);
    const params = {};
    if (evidenceId) params.evidence_ids = evidenceId;
    // user id is "u:name", machine id is "m:name"
    if (edge.source?.startsWith?.('u:')) params.user = edge.source.slice(2);
    if (edge.target?.startsWith?.('m:')) params.machine = edge.target.slice(2);
    if (edge.source?.startsWith?.('m:')) params.machine = edge.source.slice(2);
    if (edge.target?.startsWith?.('u:')) params.user = edge.target.slice(2);
    params.limit = 200;
    networkAPI.authGraphEvents(caseId, params)
      .then(res => setEdgeEvents(res.data?.events || []))
      .catch(() => setEdgeEvents([]))
      .finally(() => setEdgeEventsLoading(false));
  }, [caseId, evidenceId]);

  // When the graph view selects a node, keep the edge drawer closed.
  const handleSelectNode = useCallback(() => { setSelEdge(null); setEdgeEvents([]); }, []);

  const stats = useMemo(() => data?.stats || null, [data]);
  const nodes = useMemo(() => data?.nodes || [], [data]);
  const edges = useMemo(() => data?.edges || [], [data]);

  const userNodes = useMemo(() => nodes.filter(n => n.kind === 'user'), [nodes]);
  const machineNodes = useMemo(() => nodes.filter(n => n.kind === 'machine'), [nodes]);

  // ── Links view: sortable-ish table ──
  const sortedEdges = useMemo(() => [...edges].sort((a, b) => b.count - a.count), [edges]);

  // ── Stats view ──
  const topUsers = useMemo(() => [...userNodes].sort((a, b) => b.total_events - a.total_events).slice(0, 12), [userNodes]);
  const topMachines = useMemo(() => [...machineNodes].sort((a, b) => b.total_events - a.total_events).slice(0, 12), [machineNodes]);

  const edgeUser = selEdge
    ? nodes.find(n => n.id === (selEdge.source?.startsWith?.('u:') ? selEdge.source : selEdge.target))
    : null;
  const edgeMachine = selEdge
    ? nodes.find(n => n.id === (selEdge.source?.startsWith?.('m:') ? selEdge.source : selEdge.target))
    : null;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--fl-bg)' }}>

      {/* ── Header ── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', borderBottom: `1px solid ${T.border}`,
        background: T.panel, flexShrink: 0, gap: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={13} style={{ color: 'var(--fl-accent)' }} />
              <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 15, fontWeight: 700, color: T.text, letterSpacing: '-0.01em' }}>
                Authentification
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
                <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)', flexShrink: 0 }} />
                LogonTracer
              </span>
            </div>
            <div style={{ fontSize: 11, color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontFeatureSettings: '"tnum"', marginTop: 2 }}>
              {stats
                ? `${stats.users} utilisateurs · ${stats.machines} machines · ${stats.edges} liens · ${stats.total_events} événements${stats.truncated ? ' · tronqué' : ''}`
                : 'Windows Security.evtx (4624/4625/4648…) + auth Linux (SSH, last)'}
            </div>
          </div>

          <IntelViewSwitcher views={VIEWS} active={view} onChange={setView} />

          {!initialEvidenceId && evidenceList.length > 1 && (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setSelectorOpen(v => !v)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', borderRadius: 6, cursor: 'pointer',
                  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, maxWidth: 220,
                  border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', color: 'var(--fl-dim)',
                }}
              >
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {evidenceList.find(e => e.id === evidenceId)?.name ? `Evidence : ${evidenceList.find(e => e.id === evidenceId).name}` : 'Toutes les évidences'}
                </span>
                <ChevronDown size={11} style={{ flexShrink: 0, opacity: 0.6 }} />
              </button>
              {selectorOpen && (
                <div style={{
                  position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 40,
                  background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8,
                  boxShadow: 'var(--fl-shadow-lg)', minWidth: 260, maxWidth: 360, maxHeight: 320,
                  overflowY: 'auto', padding: 4,
                }}>
                  <button
                    onClick={() => { setEvidenceId(null); setSelectorOpen(false); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 7, width: '100%', padding: '6px 9px',
                      background: 'none', border: 'none', borderRadius: 5, cursor: 'pointer', textAlign: 'left',
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
                      color: !evidenceId ? 'var(--fl-accent)' : 'var(--fl-dim)',
                    }}
                  >
                    <span style={{ width: 6, height: 6, borderRadius: 2, background: !evidenceId ? 'var(--fl-accent)' : 'var(--fl-border)', flexShrink: 0 }} />
                    Toutes les évidences
                  </button>
                  <div style={{ height: 1, background: 'var(--fl-border)', margin: '3px 6px' }} />
                  {evidenceList.map(ev => (
                    <button
                      key={ev.id}
                      onClick={() => { setEvidenceId(ev.id); setSelectorOpen(false); }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 7, width: '100%', padding: '6px 9px',
                        background: 'none', border: 'none', borderRadius: 5, cursor: 'pointer', textAlign: 'left',
                        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
                        color: evidenceId === ev.id ? 'var(--fl-accent)' : 'var(--fl-dim)',
                      }}
                    >
                      <span style={{ width: 6, height: 6, borderRadius: 2, background: evidenceId === ev.id ? 'var(--fl-accent)' : 'var(--fl-border)', flexShrink: 0 }} />
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <button
          onClick={load}
          title="Recharger"
          style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', borderRadius: 6, cursor: 'pointer',
            fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
            border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', color: 'var(--fl-dim)',
          }}
        >
          <RefreshCw size={11} /> Actualiser
        </button>
      </div>

      {/* ── Body ── */}
      <div style={{ flex: 1, position: 'relative', overflow: 'hidden', display: 'flex' }}>

        {loading && (
          <div style={{ position: 'absolute', inset: 0, zIndex: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-bg) 80%, transparent)', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13 }}>
            Chargement du graphe d'authentification…
          </div>
        )}
        {!loading && error && (
          <div style={{ position: 'absolute', inset: 0, zIndex: 30, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center', justifyContent: 'center', background: 'var(--fl-bg)', color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
            <div>Erreur : {error}</div>
            <button onClick={load} style={{ padding: '5px 12px', borderRadius: 6, cursor: 'pointer', border: '1px solid var(--fl-border)', background: 'var(--fl-panel)', color: 'var(--fl-dim)', fontSize: 11 }}>Réessayer</button>
          </div>
        )}

        {!loading && !error && view === 'graph' && (
          <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
            <AuthGraphD3
              nodes={nodes}
              edges={edges}
              stats={stats}
              theme={T}
              onSelectNode={handleSelectNode}
              onSelectEdge={openEdge}
            />
          </div>
        )}

        {!loading && !error && view === 'links' && (
          <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
            <div style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
              {sortedEdges.length} liens utilisateur → machine (cliquer pour voir les events)
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--fl-border)', color: 'var(--fl-muted)', textAlign: 'left' }}>
                  {['Utilisateur', 'Machine', 'Events', 'OK', 'Échecs', 'Type de logon', 'Sources', 'Fenêtre'].map(h => (
                    <th key={h} style={{ padding: '6px 8px', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedEdges.map((e, i) => {
                  const lt = dominantLogonType(e);
                  const st = LOGON_STYLES[lt] || LOGON_STYLES.unknown;
                  const failedDominant = e.failed >= e.success && e.failed > 0;
                  return (
                    <tr
                      key={i}
                      onClick={() => openEdge(e)}
                      style={{
                        cursor: 'pointer', borderBottom: '1px solid var(--fl-sep)',
                        background: selEdge === e ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
                      }}
                      onMouseEnter={ev => { ev.currentTarget.style.background = selEdge === e ? ev.currentTarget.style.background : 'var(--fl-card)'; }}
                      onMouseLeave={ev => { ev.currentTarget.style.background = selEdge === e ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent'; }}
                    >
                      <td style={{ padding: '6px 8px', color: 'var(--fl-purple)', fontWeight: 600 }}>{e.source.replace('u:', '')}</td>
                      <td style={{ padding: '6px 8px', color: 'var(--fl-accent)', fontWeight: 600 }}>{e.target.replace('m:', '')}</td>
                      <td style={{ padding: '6px 8px', color: 'var(--fl-text)', fontWeight: 700 }}>{e.count}</td>
                      <td style={{ padding: '6px 8px', color: 'var(--fl-ok)' }}>{e.success}</td>
                      <td style={{ padding: '6px 8px', color: failedDominant ? 'var(--fl-danger)' : 'var(--fl-dim)', fontWeight: failedDominant ? 700 : 400 }}>{e.failed}</td>
                      <td style={{ padding: '6px 8px' }}>
                        <span style={{ color: st.color, background: `color-mix(in srgb, ${st.color} 10%, transparent)`, padding: '1px 6px', borderRadius: 3, fontSize: 9.5 }}>{st.label}</span>
                      </td>
                      <td style={{ padding: '6px 8px', color: 'var(--fl-muted)', fontSize: 10 }}>{(e.sources || []).slice(0, 3).join(', ')}{(e.sources || []).length > 3 ? '…' : ''}</td>
                      <td style={{ padding: '6px 8px', color: 'var(--fl-muted)', fontSize: 9.5, whiteSpace: 'nowrap' }}>
                        {fmtTs(e.first_seen)} → {fmtTs(e.last_seen)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {!loading && !error && view === 'stats' && (
          <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>

              {/* Top users */}
              <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: 8 }}>Top utilisateurs</div>
                {topUsers.map((n, i) => {
                  const ratio = n.total_events ? Math.round(n.failed / n.total_events * 100) : 0;
                  return (
                    <div key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--fl-sep)' }}>
                      <span style={{ width: 18, fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{i + 1}</span>
                      <span style={{ flex: 1, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={n.name}>{n.name}</span>
                      <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{n.degree} machines</span>
                      <span style={{ fontSize: 10, color: 'var(--fl-text)', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{n.total_events}</span>
                      {ratio >= 40 && <span style={{ fontSize: 9, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{ratio}% échecs</span>}
                    </div>
                  );
                })}
              </div>

              {/* Top machines */}
              <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: 8 }}>Top machines</div>
                {topMachines.map((n, i) => {
                  const ratio = n.total_events ? Math.round(n.failed / n.total_events * 100) : 0;
                  return (
                    <div key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--fl-sep)' }}>
                      <span style={{ width: 18, fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{i + 1}</span>
                      <span style={{ flex: 1, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={n.name}>{n.name}</span>
                      <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{n.degree} users</span>
                      <span style={{ fontSize: 10, color: 'var(--fl-text)', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{n.total_events}</span>
                      {ratio >= 40 && <span style={{ fontSize: 9, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{ratio}% échecs</span>}
                    </div>
                  );
                })}
              </div>

              {/* Logon types distribution */}
              <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: 8 }}>Types de logon</div>
                {(stats?.logon_types || []).map(([lt, count]) => {
                  const st = LOGON_STYLES[lt] || LOGON_STYLES.unknown;
                  const pct = stats.total_events ? Math.round(count / stats.total_events * 100) : 0;
                  return (
                    <div key={lt} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0' }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: st.color, flexShrink: 0 }} />
                      <span style={{ width: 120, color: 'var(--fl-dim)', fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={st.label}>{st.label}</span>
                      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--fl-card)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${pct}%`, background: st.color, borderRadius: 3 }} />
                      </div>
                      <span style={{ width: 50, textAlign: 'right', color: 'var(--fl-text)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600 }}>{count}</span>
                    </div>
                  );
                })}
              </div>

              {/* Top sources */}
              <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: 8 }}>Sources (IP / postes)</div>
                {(stats?.top_sources || []).slice(0, 12).map(([src, count], i) => (
                  <div key={src} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--fl-sep)' }}>
                    <span style={{ width: 18, fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{i + 1}</span>
                    <span style={{ flex: 1, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={src}>{src}</span>
                    <span style={{ fontSize: 10, color: 'var(--fl-text)', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{count}</span>
                  </div>
                ))}
              </div>

            </div>
          </div>
        )}

        {/* ── Detail drawer (edge events) ── */}
        {!loading && !error && selEdge && (
          <div style={{
            width: 'clamp(360px, 30vw, 500px)', flexShrink: 0,
            background: 'var(--fl-panel)', borderLeft: '1px solid var(--fl-border)',
            boxShadow: 'var(--fl-shadow-lg)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
                  <KeyRound size={13} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: 'var(--fl-purple)' }}>{edgeUser?.name || selEdge.source.replace('u:', '')}</span>
                      <ArrowRight size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
                      <span style={{ color: 'var(--fl-accent)' }}>{edgeMachine?.name || selEdge.target.replace('m:', '')}</span>
                    </div>
                    <div style={{ fontSize: 9, color: 'var(--fl-muted)', marginTop: 1, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                      {selEdge.count} events · {selEdge.success} OK · <span style={{ color: 'var(--fl-danger)' }}>{selEdge.failed} échecs</span>
                    </div>
                  </div>
                </div>
                <button onClick={() => openEdge(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', flexShrink: 0 }}>
                  <X size={14} />
                </button>
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 7 }}>
                {(selEdge.sources || []).slice(0, 6).map(s => (
                  <span key={s} style={{
                    padding: '1px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                    background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-muted)',
                  }}>{s}</span>
                ))}
              </div>
            </div>

            {/* Events list */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
              <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                Events ({edgeEvents.length})
              </div>
              {edgeEventsLoading ? (
                <div style={{ fontSize: 11, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Chargement…</div>
              ) : edgeEvents.length === 0 ? (
                <div style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Aucun event brut trouvé pour ce lien.</div>
              ) : edgeEvents.map((ev, i) => {
                const type = ev.artifact_type || '';
                const color = ARTIFACT_COLOR[type] || 'var(--fl-muted)';
                const isOpen = expandedEvent === i;
                const failed = ev.status === 'failed';
                return (
                  <div key={i} style={{ marginBottom: 3 }}>
                    <div
                      onClick={() => setExpandedEvent(isOpen ? null : i)}
                      style={{
                        padding: '5px 7px', borderRadius: isOpen ? '4px 4px 0 0' : 4,
                        background: isOpen ? 'var(--fl-raised)' : 'var(--fl-bg)',
                        cursor: 'pointer', borderLeft: `2px solid ${failed ? 'var(--fl-danger)' : color}`,
                      }}
                    >
                      <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                        <span style={{
                          fontSize: 7.5, padding: '1px 4px', borderRadius: 2, flexShrink: 0,
                          background: `color-mix(in srgb, ${color} 9%, transparent)`, color,
                          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                          border: `1px solid color-mix(in srgb, ${color} 19%, transparent)`,
                        }}>{type === 'catscale_auth' ? 'auth' : type === 'catscale_logon' ? 'logon' : type}</span>
                        {ev.event_id != null && (
                          <span style={{ fontSize: 7.5, color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>{ev.event_id}</span>
                        )}
                        {failed && (
                          <span style={{ fontSize: 7.5, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>ÉCHEC</span>
                        )}
                        <span style={{
                          fontSize: 9, color: 'var(--fl-text)', flex: 1, minWidth: 0,
                          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        }}>{ev.description || '—'}</span>
                        <span style={{ fontSize: 7.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0, whiteSpace: 'nowrap' }}>
                          {fmtTs(ev.timestamp)}
                        </span>
                      </div>
                    </div>
                    {isOpen && (
                      <div style={{
                        padding: '7px 9px', background: 'var(--fl-raised)', borderRadius: '0 0 4px 4px',
                        borderTop: '1px solid var(--fl-sep)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        color: 'var(--fl-dim)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                      }}>
                        {ev.description}
                        {ev.source && <div style={{ marginTop: 3, color: 'var(--fl-muted)' }}>Source : {ev.source}</div>}
                        {ev.src_ip && <div style={{ marginTop: 2, color: 'var(--fl-muted)' }}>IP : {ev.src_ip}</div>}
                        {ev.logon_type && <div style={{ marginTop: 2, color: 'var(--fl-muted)' }}>Logon type : {ev.logon_type}</div>}
                        {ev.process_name && <div style={{ marginTop: 2, color: 'var(--fl-muted)' }}>Processus : {ev.process_name}</div>}
                        {ev.raw && (
                          <details style={{ marginTop: 4 }}>
                            <summary style={{ cursor: 'pointer', color: 'var(--fl-muted)' }}>JSON brut</summary>
                            <pre style={{ fontSize: 9, margin: '4px 0 0', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--fl-muted)' }}>{JSON.stringify(ev.raw, null, 2).slice(0, 2000)}</pre>
                          </details>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
