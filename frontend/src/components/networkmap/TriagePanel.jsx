import { useState, useMemo, useEffect } from 'react';
import { Search, Crosshair, ExternalLink, Download } from 'lucide-react';
import { networkAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const EXT_RE = /internet|external|public|wan/i;
const SEV_COLOR = { CRITICAL: 'var(--fl-danger)', HIGH: 'var(--fl-warn)', MEDIUM: 'var(--fl-gold)', LOW: 'var(--fl-subtle)' };

// Network triage panel: search/center, live stats, risk-ranked suspects, focus filters,
// behavioural detections (Phase 2), and pivot to the Super Timeline. Drives Cytoscape via `cy`.
export default function TriagePanel({ elements, cy, caseId, onPivot }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState(null); // null | 'suspect' | 'ioc'
  const [analytics, setAnalytics] = useState(null);
  const findings = analytics?.findings || [];
  const geo = analytics?.geo || [];
  const zones = analytics?.zones || {};

  useEffect(() => {
    if (!caseId) return;
    networkAPI.analytics(caseId).then(r => setAnalytics(r.data || null)).catch(() => setAnalytics(null));
  }, [caseId]);

  const { stats, suspects } = useMemo(() => {
    const nodeEls = (elements || []).filter(e =>
      e.data && !e.data.source && e.data.id && !e.data._zone &&
      !['zone', 'zone-label', 'cluster'].includes(e.data.nodeType));
    const edgeEls = (elements || []).filter(e => e.data?.source);
    const deg = new Map();
    edgeEls.forEach(e => { deg.set(e.data.source, (deg.get(e.data.source) || 0) + 1); deg.set(e.data.target, (deg.get(e.data.target) || 0) + 1); });
    const score = (d) => (d._iocHit ? 40 : 0) + (d.is_suspicious ? 25 : 0)
      + (EXT_RE.test(d.nodeType || '') ? 15 : 0) + Math.min((deg.get(d.id) || 0) * 2, 20);
    const suspects = nodeEls
      .map(e => ({ id: e.data.id, label: e.data.label || e.data.id, ioc: !!e.data._iocHit, susp: !!e.data.is_suspicious, deg: deg.get(e.data.id) || 0, score: score(e.data) }))
      .filter(n => n.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 12);
    const stats = {
      nodes: nodeEls.length, edges: edgeEls.length,
      ioc: nodeEls.filter(e => e.data._iocHit).length,
      susp: nodeEls.filter(e => e.data.is_suspicious).length,
      ext: nodeEls.filter(e => EXT_RE.test(e.data.nodeType || '')).length,
    };
    return { stats, suspects };
  }, [elements]);

  const focus = (id) => {
    if (!cy) return;
    const n = cy.$id(id);
    if (n.nonempty()) { cy.nodes().unselect(); n.select(); cy.animate({ center: { eles: n }, zoom: 1.6 }, { duration: 300 }); }
  };

  const runSearch = (e) => {
    e.preventDefault();
    if (!cy || !q.trim()) return;
    const term = q.trim().toLowerCase();
    const n = cy.nodes().filter(x => {
      const d = x.data();
      return String(d.id || '').toLowerCase().includes(term) || String(d.label || '').toLowerCase().includes(term);
    });
    if (n.nonempty()) { cy.nodes().unselect(); n[0].select(); cy.animate({ center: { eles: n[0] }, zoom: 1.6 }, { duration: 300 }); }
  };

  const applyFilter = (f) => {
    const next = filter === f ? null : f;
    setFilter(next);
    if (!cy) return;
    cy.batch(() => cy.nodes().forEach(x => {
      const d = x.data();
      if (['zone', 'zone-label'].includes(d.nodeType)) return;
      const match = !next || (next === 'suspect' && d.is_suspicious) || (next === 'ioc' && d._iocHit);
      x.style('opacity', match ? 1 : 0.1);
    }));
  };

  const exportReport = () => {
    const report = { caseId, generatedAt: new Date().toISOString(), stats, zones, geo, suspects, findings };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `network-report-${caseId}.json`;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  };

  const Stat = ({ label, value, color }) => (
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ fontSize: 16, fontWeight: 700, fontFamily: MONO, color: color || 'var(--fl-text)', fontFeatureSettings: '"tnum"' }}>{value}</div>
      <div style={{ fontSize: 8.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-muted)' }}>{label}</div>
    </div>
  );
  const Chip = ({ k, label, color }) => (
    <button onClick={() => applyFilter(k)} style={{
      flex: 1, padding: '4px 6px', borderRadius: 6, cursor: 'pointer', fontFamily: MONO, fontSize: 10, fontWeight: 600,
      background: filter === k ? `color-mix(in srgb, ${color} 14%, transparent)` : 'transparent',
      color: filter === k ? color : 'var(--fl-muted)',
      border: `1px solid ${filter === k ? `color-mix(in srgb, ${color} 35%, transparent)` : 'var(--fl-border)'}` }}>
      {label}
    </button>
  );

  return (
    <div style={{ position: 'absolute', top: 12, right: 12, width: 264, zIndex: 20,
      background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10,
      boxShadow: 'var(--fl-shadow-lg)', padding: 12, display: 'flex', flexDirection: 'column', gap: 11 }}>
      <form onSubmit={runSearch} style={{ position: 'relative' }}>
        <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)' }} />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search IP / host…"
          style={{ width: '100%', padding: '7px 9px 7px 28px', borderRadius: 7, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11.5, outline: 'none' }} />
      </form>

      <div style={{ display: 'flex', gap: 6, textAlign: 'left' }}>
        <Stat label="nodes" value={stats.nodes} />
        <Stat label="links" value={stats.edges} />
        <Stat label="external" value={stats.ext} color="var(--fl-warn)" />
        <Stat label="IOC" value={stats.ioc} color={stats.ioc ? 'var(--fl-danger)' : undefined} />
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        <Chip k="suspect" label={`Suspects ${stats.susp}`} color="var(--fl-warn)" />
        <Chip k="ioc" label={`IOC ${stats.ioc}`} color="var(--fl-danger)" />
      </div>

      <div>
        <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
          Hosts to prioritize
        </div>
        {suspects.length === 0 ? (
          <div style={{ fontSize: 11, color: 'var(--fl-subtle)', fontFamily: MONO }}>No risky hosts.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: 260, overflowY: 'auto' }}>
            {suspects.map(s => {
              const col = s.ioc ? 'var(--fl-danger)' : s.susp ? 'var(--fl-warn)' : 'var(--fl-gold)';
              return (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 6px', borderRadius: 6, background: 'var(--fl-bg)' }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2, background: col, flexShrink: 0 }} />
                  <button onClick={() => focus(s.id)} title="Centrer sur la carte"
                    style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                      fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.label}
                  </button>
                  <span style={{ fontSize: 9.5, fontFamily: MONO, color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{s.score}</span>
                  <button onClick={() => focus(s.id)} title="Centrer" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex' }}><Crosshair size={12} /></button>
                  <button onClick={() => onPivot?.(s.label || s.id)} title="Open in Super Timeline" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex' }}><ExternalLink size={12} /></button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {findings.length > 0 && (
        <div style={{ borderTop: '1px solid var(--fl-border2)', paddingTop: 10 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
            Network detections <span style={{ color: 'var(--fl-subtle)' }}>· {findings.length}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: 220, overflowY: 'auto' }}>
            {findings.map((f, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 6px', borderRadius: 6, background: 'var(--fl-bg)' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: SEV_COLOR[f.severity] || 'var(--fl-subtle)', flexShrink: 0 }} />
                <button onClick={() => focus(f.dst || f.src)} title={f.mitre ? `${f.mitre} — centrer` : 'Centrer'}
                  style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                    fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: 1.35 }}>
                  {f.label}
                </button>
                <button onClick={() => onPivot?.(f.src || f.dst)} title="Open in Super Timeline" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex', flexShrink: 0 }}><ExternalLink size={11} /></button>
              </div>
            ))}
          </div>
        </div>
      )}

      {(geo.length > 0 || zones.internal != null || zones.external != null) && (
        <div style={{ borderTop: '1px solid var(--fl-border2)', paddingTop: 10 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>Geo &amp; zones</div>
          <div style={{ display: 'flex', gap: 6, marginBottom: geo.length ? 8 : 0 }}>
            <Stat label="internal" value={zones.internal ?? 0} />
            <Stat label="external" value={zones.external ?? 0} color="var(--fl-warn)" />
            <Stat label="cloud" value={zones.cloud ?? 0} color="var(--fl-purple)" />
          </div>
          {geo.slice(0, 5).map(g => (
            <div key={g.country} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 2px', fontFamily: MONO, fontSize: 10.5 }}>
              <span style={{ flex: 1, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.country}</span>
              <span style={{ color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{g.hosts}</span>
            </div>
          ))}
        </div>
      )}

      <button onClick={exportReport} title="Export the network report (JSON)"
        style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '7px 10px', borderRadius: 7,
          background: 'var(--fl-card)', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)', cursor: 'pointer',
          fontFamily: MONO, fontSize: 11, fontWeight: 600 }}>
        <Download size={12} /> Export report
      </button>
    </div>
  );
}
