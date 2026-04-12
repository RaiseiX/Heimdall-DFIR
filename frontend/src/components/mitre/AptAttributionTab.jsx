import { useState, useEffect } from 'react';
import { attributionAPI } from '../../utils/api';

export default function AptAttributionTab({ caseId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    attributionAPI.getCaseAttribution(caseId)
      .then(r => setData(r.data))
      .catch(() => setData({ case_techniques: [], attributions: [] }))
      .finally(() => setLoading(false));
  }, [caseId]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--fl-dim)', fontSize: 13 }}>
      Analyse en cours…
    </div>
  );

  if (!data?.case_techniques?.length) return (
    <div style={{ padding: 32, textAlign: 'center', color: 'var(--fl-dim)', fontSize: 13 }}>
      <div style={{ fontSize: 32, marginBottom: 12 }}>🎯</div>
      <div style={{ fontWeight: 700, color: 'var(--fl-text)', marginBottom: 6 }}>Aucune technique MITRE détectée</div>
      <div>Enrichissez la Kill Chain via les onglets Bookmarks, Techniques MITRE ou Hayabusa</div>
    </div>
  );

  const confColor = { high: 'var(--fl-danger)', medium: 'var(--fl-warn)', low: 'var(--fl-accent)' };
  const confLabel = { high: 'ÉLEVÉE', medium: 'MOYENNE', low: 'FAIBLE' };

  return (
    <div style={{ padding: 16, overflow: 'auto', height: '100%', background: 'var(--fl-bg)' }}>
      
      <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ fontSize: 13, color: 'var(--fl-dim)' }}>
          <span style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{data.total_case_techniques}</span> techniques détectées dans ce cas
          {data.attributions.length > 0
            ? <> — <span style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{data.attributions.length}</span> groupe(s) APT corrélé(s)</>
            : ' — Aucune corrélation APT'}
        </div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 20 }}>
        {data.case_techniques.map(t => (
          <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: 'var(--fl-panel)', color: 'var(--fl-dim)', borderRadius: 4, fontFamily: 'monospace', border: '1px solid var(--fl-border)' }}>{t}</span>
        ))}
      </div>

      {data.attributions.length === 0 ? (
        <div style={{ textAlign: 'center', color: 'var(--fl-dim)', padding: 32, fontSize: 12 }}>
          Aucune corrélation APT trouvée avec les techniques actuelles
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {data.attributions.map(apt => (
            <div key={apt.id} style={{ background: 'var(--fl-panel)', border: `1px solid ${apt.color}30`, borderRadius: 10, padding: '14px 16px', borderLeft: `3px solid ${apt.color}` }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--fl-text)' }}>{apt.name}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', background: apt.color + '20', color: apt.color, borderRadius: 4, border: `1px solid ${apt.color}40` }}>{apt.id}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', background: `${confColor[apt.confidence]}20`, color: confColor[apt.confidence], borderRadius: 4, fontWeight: 700 }}>
                      {confLabel[apt.confidence]}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--fl-dim)', marginTop: 3 }}>
                    {apt.aliases.join(' · ')}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: apt.match_score >= 60 ? 'var(--fl-danger)' : apt.match_score >= 30 ? 'var(--fl-warn)' : 'var(--fl-accent)' }}>
                    {apt.match_score}%
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--fl-dim)' }}>{apt.match_count} technique(s) correspondante(s)</div>
                </div>
              </div>

              <div style={{ height: 5, background: 'var(--fl-panel)', borderRadius: 3, marginBottom: 10, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${apt.match_score}%`, background: apt.match_score >= 60 ? 'var(--fl-danger)' : apt.match_score >= 30 ? 'var(--fl-warn)' : 'var(--fl-accent)', borderRadius: 3, transition: 'width 0.5s ease' }} />
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 8 }}>
                <span style={{ fontSize: 10, padding: '2px 6px', background: 'var(--fl-panel)', color: 'var(--fl-dim)', borderRadius: 4 }}>🌍 {apt.origin}</span>
                <span style={{ fontSize: 10, padding: '2px 6px', background: 'var(--fl-panel)', color: 'var(--fl-dim)', borderRadius: 4 }}>🎯 {apt.motivation}</span>
              </div>

              <div style={{ fontSize: 11, color: 'var(--fl-dim)', marginBottom: 4 }}>Techniques correspondantes :</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {apt.matched_techniques.map(t => (
                  <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: apt.color + '15', color: apt.color, borderRadius: 4, fontFamily: 'monospace', border: `1px solid ${apt.color}30` }}>{t}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
