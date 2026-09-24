import { useState, useEffect, useCallback } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Boxes, RefreshCw, ExternalLink } from 'lucide-react';
import { collectionAPI } from '../utils/api';
import { timelinePivotUrl } from '../utils/timelinePivot';
import { Button, Spinner, Alert, EmptyState } from '../components/ui';
import { tableStyle, headStyle, cellStyle } from '../components/ui/tableIdiom';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  page: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 },
  barre: { display: 'flex', alignItems: 'center', gap: 14, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexWrap: 'wrap' },
  titre: { display: 'flex', alignItems: 'center', gap: 6, margin: 0, fontFamily: MONO, fontSize: 12, fontWeight: 600, color: 'var(--fl-text)' },
  chiffres: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)' },
  droite: { marginLeft: 'auto' },
  note: { padding: '6px 12px', fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' },
  defile: { overflow: 'auto', flex: 1, minHeight: 0 },
  bouton: { display: 'inline-flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--fl-accent)', fontFamily: MONO, fontSize: 11, textAlign: 'left' },
  mono: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'nowrap' },
  alerte: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-warn)', whiteSpace: 'nowrap' },
};

export default function CollectionArtifactsPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { caseId, collectionId } = useOutletContext() || {};
  const [resume, setResume] = useState(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState(null);

  const charger = useCallback(async () => {
    if (!caseId || !collectionId) return;
    setChargement(true);
    setErreur(null);
    try {
      const r = await collectionAPI.artifactSummary(caseId, collectionId);
      setResume(r.data);
    } catch (e) {
      setErreur(e?.response?.data?.error || e?.message || String(e));
    } finally {
      setChargement(false);
    }
  }, [caseId, collectionId]);

  useEffect(() => { charger(); }, [charger]);

  const nombre = (n) => Number(n || 0).toLocaleString(i18n.language);
  const date = (iso) => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');
  const ouvrir = (type) => navigate(timelinePivotUrl({ caseId, collectionId, filters: { artifactTypes: type } }));

  return (
    <div style={S.page}>
      <div style={S.barre}>
        <h2 style={S.titre}><Boxes size={13} color="var(--fl-accent)" aria-hidden="true" />{t('collection.artifacts.title')}</h2>
        {resume && (
          <span style={S.chiffres}>
            {t('collection.artifacts.summary', { types: resume.types.length, rows: nombre(resume.total) })}
          </span>
        )}
        <div style={S.droite}>
          <Button size="sm" variant="ghost" icon={RefreshCw} loading={chargement} onClick={charger}>{t('collection.artifacts.refresh')}</Button>
        </div>
      </div>
      <div style={S.note}>{t('collection.artifacts.hint')}</div>
      {resume && resume.sansDate > 0 && (
        <Alert variant="warn" style={{ margin: '0 12px 8px' }} message={t('collection.artifacts.undated', { rows: nombre(resume.sansDate) })} />
      )}
      {erreur && <Alert message={erreur} style={{ margin: 12 }} />}
      {chargement && !resume && <Spinner full text={t('collection.artifacts.loading')} />}
      {resume && resume.types.length === 0 && <EmptyState icon={Boxes} title={t('collection.artifacts.empty')} />}
      {resume && resume.types.length > 0 && (
        <div style={S.defile}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={headStyle(false)}>{t('collection.artifacts.col_type')}</th>
                <th style={headStyle(false)}>{t('collection.artifacts.col_name')}</th>
                <th style={{ ...headStyle(true), textAlign: 'right' }}>{t('collection.artifacts.col_rows')}</th>
                <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.artifacts.col_undated')}</th>
                <th style={headStyle(false)}>{t('collection.artifacts.col_first')}</th>
                <th style={headStyle(false)}>{t('collection.artifacts.col_last')}</th>
              </tr>
            </thead>
            <tbody>
              {resume.types.map((a) => (
                <tr key={a.type}>
                  <td style={cellStyle()}>
                    <button type="button" style={S.bouton} onClick={() => ouvrir(a.type)}
                      title={t('collection.artifacts.open_timeline')} aria-label={`${t('collection.artifacts.open_timeline')} : ${a.type}`}>
                      {a.type}
                      <ExternalLink size={10} aria-hidden="true" />
                    </button>
                  </td>
                  <td style={{ ...cellStyle(), ...S.mono }}>{a.nom}</td>
                  <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{nombre(a.lignes)}</td>
                  <td style={{ ...cellStyle({ numeric: true }), ...(a.sansDate ? S.alerte : S.mono) }}>{nombre(a.sansDate)}</td>
                  <td style={{ ...cellStyle(), ...S.mono }}>{date(a.premier)}</td>
                  <td style={{ ...cellStyle(), ...S.mono }}>{date(a.dernier)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
