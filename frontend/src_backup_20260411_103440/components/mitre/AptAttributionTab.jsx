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
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#7d8590', fontSize: 13 }}>
      Analyse en cours…
    </div>
  );

  if (!data?.case_techniques?.length) return (
    <div style={{ padding: 32, textAlign: 'center', color: '#7d8590', fontSize: 13 }}>
      <div style={{ fontSize: 32, marginBottom: 12 }}>🎯</div>
      <div style={{ fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Aucune technique MITRE détectée</div>
      <div>Enrichissez la Kill Chain via les onglets Bookmarks, Techniques MITRE ou Hayabusa</div>
    </div>
  );

  const confColor = { high: '#da3633', medium: '#d97c20', low: '#4d82c0' };
  const confLabel = { high: 'ÉLEVÉE', medium: 'MOYENNE', low: 'FAIBLE' };

  return (
    <div style={{ padding: 16, overflow: 'auto', height: '100%', background: '#0d1117' }}>
      
      <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ fontSize: 13, color: '#7d8590' }}>
          <span style={{ color: '#e6edf3', fontWeight: 700 }}>{data.total_case_techniques}</span> techniques détectées dans ce cas
          {data.attributions.length > 0
            ? <> — <span style={{ color: '#e6edf3', fontWeight: 700 }}>{data.attributions.length}</span> groupe(s) APT corrélé(s)</>
            : ' — Aucune corrélation APT'}
        </div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 20 }}>
        {data.case_techniques.map(t => (
          <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: '#21303f', color: '#7d8590', borderRadius: 4, fontFamily: 'monospace', border: '1px solid #30363d' }}>{t}</span>
        ))}
      </div>

      {data.attributions.length === 0 ? (
        <div style={{ textAlign: 'center', color: '#7d8590', padding: 32, fontSize: 12 }}>
          Aucune corrélation APT trouvée avec les techniques actuelles
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {data.attributions.map(apt => (
            <div key={apt.id} style={{ background: '#161b22', border: `1px solid ${apt.color}30`, borderRadius: 10, padding: '14px 16px', borderLeft: `3px solid ${apt.color}` }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 15, fontWeight: 700, color: '#e6edf3' }}>{apt.name}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', background: apt.color + '20', color: apt.color, borderRadius: 4, border: `1px solid ${apt.color}40` }}>{apt.id}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', background: `${confColor[apt.confidence]}20`, color: confColor[apt.confidence], borderRadius: 4, fontWeight: 700 }}>
                      {confLabel[apt.confidence]}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: '#7d8590', marginTop: 3 }}>
                    {apt.aliases.join(' · ')}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: apt.match_score >= 60 ? '#da3633' : apt.match_score >= 30 ? '#d97c20' : '#4d82c0' }}>
                    {apt.match_score}%
                  </div>
                  <div style={{ fontSize: 10, color: '#7d8590' }}>{apt.match_count} technique(s) correspondante(s)</div>
                </div>
              </div>

              <div style={{ height: 5, background: '#21303f', borderRadius: 3, marginBottom: 10, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${apt.match_score}%`, background: apt.match_score >= 60 ? '#da3633' : apt.match_score >= 30 ? '#d97c20' : '#4d82c0', borderRadius: 3, transition: 'width 0.5s ease' }} />
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 8 }}>
                <span style={{ fontSize: 10, padding: '2px 6px', background: '#21303f', color: '#7d8590', borderRadius: 4 }}>🌍 {apt.origin}</span>
                <span style={{ fontSize: 10, padding: '2px 6px', background: '#21303f', color: '#7d8590', borderRadius: 4 }}>🎯 {apt.motivation}</span>
              </div>

              <div style={{ fontSize: 11, color: '#7d8590', marginBottom: 4 }}>Techniques correspondantes :</div>
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
