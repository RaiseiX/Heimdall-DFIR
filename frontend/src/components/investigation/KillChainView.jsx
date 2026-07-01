import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Download, ArrowRight } from 'lucide-react';
import { bookmarksAPI, investigationAPI } from '../../utils/api';

const PHASES = [
  { id: 'Reconnaissance',       short: 'RECON',    color: 'var(--fl-dim)' },
  { id: 'Resource Development', short: 'RESOURCE', color: 'var(--fl-dim)' },
  { id: 'Initial Access',       short: 'INIT',     color: 'var(--fl-warn)' },
  { id: 'Execution',            short: 'EXEC',     color: 'var(--fl-danger)' },
  { id: 'Persistence',          short: 'PERSIST',  color: 'var(--fl-pink)' },
  { id: 'Privilege Escalation', short: 'PRIVESC',  color: 'var(--fl-purple)' },
  { id: 'Defense Evasion',      short: 'EVADE',    color: 'var(--fl-accent)' },
  { id: 'Credential Access',    short: 'CREDS',    color: 'var(--fl-danger)' },
  { id: 'Discovery',            short: 'DISC',     color: 'var(--fl-gold)' },
  { id: 'Lateral Movement',     short: 'LATERAL',  color: 'var(--fl-warn)' },
  { id: 'Collection',           short: 'COLLECT',  color: 'var(--fl-ok)' },
  { id: 'Command and Control',  short: 'C2',       color: 'var(--fl-danger)' },
  { id: 'Exfiltration',         short: 'EXFIL',    color: 'var(--fl-danger)' },
  { id: 'Impact',               short: 'IMPACT',   color: 'var(--fl-danger)' },
];

const W = { high: 1, medium: 0.6, low: 0.3 };
const weight = c => (W[c] != null ? W[c] : 0.3);

function PhaseColumn({ phase, items, titleById }) {
  const active = items.length > 0;
  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      border: active ? `1px solid ${phase.color}35` : '1px dashed var(--fl-sep)',
      borderTop: `2px solid ${active ? phase.color : 'var(--fl-sep)'}`,
      borderRadius: '0 0 6px 6px',
      background: active ? `color-mix(in srgb, ${phase.color} 3%, transparent)` : 'transparent',
      minWidth: 150, maxWidth: 190, flex: '0 0 150px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 8px' }}>
        <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, letterSpacing: '0.08em', color: active ? phase.color : 'var(--fl-card)' }}>{phase.short}</span>
        {active
          ? <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, background: `color-mix(in srgb, ${phase.color} 15%, transparent)`, color: phase.color, padding: '1px 5px', borderRadius: 10 }}>{items.length}</span>
          : <span style={{ fontSize: 10, color: 'var(--fl-sep)' }}>—</span>}
      </div>
      <div style={{ padding: '0 8px 4px', fontSize: 8.5, color: active ? 'var(--fl-dim)' : 'var(--fl-card)' }}>{phase.id}</div>
      {active && (
        <div style={{ padding: '4px 6px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {items.map(b => (
            <div key={b.id} style={{ borderRadius: 5, border: `1px solid color-mix(in srgb, ${b.color || phase.color} 19%, transparent)`, borderLeft: `2px solid ${b.color || phase.color}`, background: '#0a1625', padding: '4px 7px' }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--fl-on-dark)', lineHeight: 1.3 }}>{b.title}</span>
              {b.mitre_technique && <div style={{ fontSize: 8.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>{b.mitre_technique}</div>}
              {b.links_to && titleById.get(b.links_to) && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 2, fontSize: 8, color: 'var(--fl-accent)', marginTop: 2 }}>
                  <ArrowRight size={8} /> {titleById.get(b.links_to)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function KillChainView({ caseId, refreshKey }) {
  const { t } = useTranslation();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading]   = useState(false);

  const load = useCallback(() => {
    if (!caseId) return;
    setLoading(true);
    bookmarksAPI.list(caseId)
      .then(res => setFindings((res.data || []).filter(b => b.mitre_tactic)))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [caseId]);

  useEffect(() => { load(); }, [load, refreshKey]);

  const byTactic = {};
  for (const b of findings) (byTactic[b.mitre_tactic] ||= []).push(b);
  const titleById = new Map(findings.map(f => [f.id, f.title]));

  // confidence-weighted coverage
  const covered = Object.keys(byTactic).length;
  const weightSum = Object.entries(byTactic).reduce((acc, [, items]) => acc + Math.max(...items.map(i => weight(i.confidence))), 0);
  const score = weightSum / PHASES.length;
  const blindSpots = PHASES.filter(p => !(byTactic[p.id]?.length)).map(p => p.id);

  async function exportNavigator() {
    try {
      const r = await investigationAPI.navigator(caseId);
      const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `killchain-navigator-${caseId}.json`;
      a.click(); URL.revokeObjectURL(url);
    } catch { /* noop */ }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {t('investigation.killchain_title')} · {covered}/{PHASES.length}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {findings.length > 0 && (
            <button onClick={exportNavigator} style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer', padding: '3px 8px', color: 'var(--fl-subtle)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              <Download size={10} /> {t('investigation.export_navigator')}
            </button>
          )}
          <button onClick={load} style={{ background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer', padding: '3px 7px', color: 'var(--fl-subtle)' }}><RefreshCw size={11} /></button>
        </div>
      </div>

      {loading && <div style={{ textAlign: 'center', color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: 12 }}>{t('common.loading')}</div>}

      {!loading && findings.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: '24px 16px', border: '1px dashed var(--fl-sep)', borderRadius: 8 }}>
          {t('bookmark.empty')}
        </div>
      )}

      {!loading && findings.length > 0 && (
        <>
          <div style={{ overflowX: 'auto', paddingBottom: 8 }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', minWidth: 'max-content' }}>
              {PHASES.map((phase, i) => (
                <div key={phase.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                  <PhaseColumn phase={phase} items={byTactic[phase.id] || []} titleById={titleById} />
                  {i < PHASES.length - 1 && <span style={{ alignSelf: 'center', fontSize: 14, color: 'var(--fl-sep)', marginTop: 18 }}>→</span>}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)', textTransform: 'uppercase' }}>{t('investigation.coverage')}</span>
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>{Math.round(score * 100)}%</span>
            </div>
            <div style={{ height: 4, background: 'var(--fl-bg)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', borderRadius: 2, width: `${score * 100}%`, background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-danger))', transition: 'width 0.4s' }} />
            </div>
          </div>

          {blindSpots.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)', textTransform: 'uppercase' }}>{t('investigation.blind_spots')}:</span>
              {blindSpots.map(b => (
                <span key={b} style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', border: '1px dashed var(--fl-sep)', borderRadius: 4, padding: '1px 6px' }}>{b}</span>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
