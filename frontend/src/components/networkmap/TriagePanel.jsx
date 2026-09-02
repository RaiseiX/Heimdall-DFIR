import { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Search, Crosshair, ExternalLink, Download } from 'lucide-react';
import { triageStats } from './utils/triageStats';
import { networkAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const SEV_COLOR = { CRITICAL: 'var(--fl-danger)', HIGH: 'var(--fl-warn)', MEDIUM: 'var(--fl-gold)', LOW: 'var(--fl-subtle)' };

export default function TriagePanel({ elements, cy, caseId, onPivot }) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const findings = analytics?.findings || [];
  const geo = analytics?.geo || [];
  const zones = analytics?.zones || {};
  const av = analytics?.availability || {};
  const unavailable = Object.entries(av).filter(([, a]) => a && a.state !== 'available');
  const Dash = () => <span style={{ color: 'var(--fl-subtle)' }}>&mdash;</span>;

  useEffect(() => {
    if (!caseId) return;
    networkAPI.analytics(caseId).then(r => setAnalytics(r.data || null)).catch(() => setAnalytics(null));
  }, [caseId]);

  const { stats, suspects } = useMemo(() => triageStats(elements), [elements]);

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
      <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, color: 'var(--fl-muted)' }}>{label}</div>
    </div>
  );
  const Chip = ({ k, label, color }) => (
    <button onClick={() => applyFilter(k)} aria-pressed={filter === k} style={{
      padding: '3px 4px', background: 'none', border: 0, cursor: 'pointer',
      fontFamily: MONO, fontSize: 11, whiteSpace: 'nowrap',
      color: filter === k ? color : 'var(--fl-muted)',
      borderBottom: `1px solid ${filter === k ? color : 'transparent'}` }}>
      {label}
    </button>
  );

  return (
    <div style={{ width: 264, flexShrink: 0, overflowY: 'auto',
      background: 'var(--fl-panel)', borderLeft: '1px solid var(--fl-border)',
      padding: 12, display: 'flex', flexDirection: 'column', gap: 11 }}>
      <form onSubmit={runSearch} style={{ position: 'relative' }}>
        <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)' }} />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('networkMap.triage.search_ph')}
          style={{ width: '100%', padding: '7px 9px 7px 28px', borderRadius: 7, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, outline: 'none' }} />
      </form>

      <div style={{ display: 'flex', gap: 6, textAlign: 'left' }}>
        <Stat label={t('networkMap.triage.nodes')} value={stats.nodes} />
        <Stat label={t('networkMap.triage.links')} value={stats.edges} />
        <Stat label={t('networkMap.triage.external')} value={stats.ext} color="var(--fl-warn)" />
        <Stat label={t('networkMap.triage.ioc')} value={stats.ioc} color={stats.ioc ? 'var(--fl-danger)' : undefined} />
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        <Chip k="suspect" label={t('networkMap.triage.suspects', { count: stats.susp })} color="var(--fl-warn)" />
        <Chip k="ioc" label={t('networkMap.triage.ioc_count', { count: stats.ioc })} color="var(--fl-danger)" />
      </div>

      <div>
        <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
          {t('networkMap.triage.prioritize')}
        </div>
        {suspects.length === 0 ? (
          <div style={{ fontSize: 11, color: 'var(--fl-subtle)', fontFamily: MONO }}>{t('networkMap.triage.no_risky')}</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: 260, overflowY: 'auto' }}>
            {suspects.map(s => {
              const col = s.ioc ? 'var(--fl-danger)' : s.susp ? 'var(--fl-warn)' : 'var(--fl-gold)';
              return (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 2px', borderBottom: '1px solid var(--fl-border2)' }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2, background: col, flexShrink: 0 }} />
                  <button onClick={() => focus(s.id)} title={t('networkMap.triage.center')}
                    style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                      fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.label}
                  </button>
                  <span style={{ fontSize: 9, fontFamily: MONO, color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{s.score}</span>
                  <button onClick={() => focus(s.id)} title={t('networkMap.triage.center')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex' }}><Crosshair size={12} /></button>
                  <button onClick={() => onPivot?.(s.label || s.id)} title={t('networkMap.triage.open_timeline')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex' }}><ExternalLink size={12} /></button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {findings.length > 0 && (
        <div style={{ borderTop: '1px solid var(--fl-border2)', paddingTop: 10 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
            {t('networkMap.triage.detections')} <span style={{ color: 'var(--fl-subtle)' }}>· {findings.length}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: 220, overflowY: 'auto' }}>
            {findings.map((f, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 2px', borderBottom: '1px solid var(--fl-border2)' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: SEV_COLOR[f.severity] || 'var(--fl-subtle)', flexShrink: 0 }} />
                <button onClick={() => focus(f.dst || f.src)} title={f.mitre ? `${f.mitre} — ${t('networkMap.triage.center')}` : t('networkMap.triage.center')}
                  style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                    fontFamily: MONO, fontSize: 10, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: 1.35 }}>
                  {f.label}
                </button>
                <button onClick={() => onPivot?.(f.src || f.dst)} title="Open in Super Timeline" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, display: 'inline-flex', flexShrink: 0 }}><ExternalLink size={11} /></button>
              </div>
            ))}
          </div>
        </div>
      )}

      {zones.internal != null && (
        <div style={{ borderTop: '1px solid var(--fl-border2)', paddingTop: 10 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
            {t('networkMap.triage.zones_title')}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <Stat label={t('networkMap.triage.internal')} value={zones.internal} />
            <Stat label={t('networkMap.triage.external')} value={zones.external} color="var(--fl-warn)" />
            {av.cloud?.state === 'available'
              ? <Stat label={t('networkMap.triage.cloud')} value={zones.cloud} color="var(--fl-purple)" />
              : <Stat label={t('networkMap.triage.cloud')} value={<Dash />} />}
          </div>
        </div>
      )}

      {(geo.length > 0 || unavailable.length > 0) && (
        <div style={{ borderTop: '1px solid var(--fl-border2)', paddingTop: 10 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>
            {t('networkMap.triage.geo_title')}
          </div>
          {geo.slice(0, 5).map(g => (
            <div key={g.country} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 2px', fontFamily: MONO, fontSize: 10 }}>
              <span style={{ flex: 1, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.country}</span>
              <span style={{ color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{g.hosts}</span>
            </div>
          ))}
          {unavailable.map(([key, a]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'baseline', gap: 8, padding: '3px 2px', fontFamily: MONO, fontSize: 10 }}>
              <span style={{ flex: '0 0 auto', color: 'var(--fl-dim)' }}>{t(`networkMap.triage.analysis_${key}`)}</span>
              <span style={{ flex: 1, color: a.state === 'partial' ? 'var(--fl-gold)' : 'var(--fl-subtle)', textAlign: 'right' }}>
                {t(`networkMap.triage.reason_${a.reason}`, a.facts)}
              </span>
            </div>
          ))}
        </div>
      )}

      <button onClick={exportReport} title={t('networkMap.triage.export_title')}
        style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '7px 10px', borderRadius: 7,
          background: 'var(--fl-card)', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)', cursor: 'pointer',
          fontFamily: MONO, fontSize: 11, fontWeight: 600 }}>
        <Download size={12} /> {t('networkMap.triage.export')}
      </button>
    </div>
  );
}
