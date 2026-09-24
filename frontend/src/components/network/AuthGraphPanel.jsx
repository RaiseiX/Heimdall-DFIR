import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { KeyRound, RefreshCw, ExternalLink, BookOpen } from 'lucide-react';
import { networkAPI, notebookAPI } from '../../utils/api';
import { entreeArete } from '../../utils/notebookEntry';
import { timelinePivotUrl } from '../../utils/timelinePivot';
import { Button, Spinner, Alert, EmptyState } from '../ui';
import { tableStyle, headStyle, cellStyle } from '../ui/tableIdiom';
import AuthGraphCanvas from './AuthGraphCanvas';
import { elementsCytoscape, aretesVisibles, filtresDePivot, repartition } from './authGraphView';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  racine: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 },
  barre: { display: 'flex', alignItems: 'center', gap: 14, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexWrap: 'wrap' },
  titre: { display: 'flex', alignItems: 'center', gap: 6, margin: 0, fontFamily: MONO, fontSize: 12, fontWeight: 600, color: 'var(--fl-text)' },
  chiffres: { display: 'flex', gap: 14, fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', flexWrap: 'wrap' },
  option: { display: 'flex', alignItems: 'center', gap: 5, fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', cursor: 'pointer' },
  actions: { display: 'flex', alignItems: 'center', gap: 10, marginLeft: 'auto' },
  note: { padding: '6px 12px', fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' },
  corps: { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(360px, 44%)', flex: 1, minHeight: 0 },
  graphe: { minHeight: 0, borderRight: '1px solid var(--fl-border)' },
  tableau: { overflow: 'auto', minHeight: 0 },
  ligne: (active) => ({ background: active ? 'var(--fl-surface-active, var(--fl-card))' : 'transparent' }),
  bouton: { background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, textAlign: 'left' },
  mono: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)' },
  echec: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-danger)', fontWeight: 600 },
  detail: { padding: '8px 12px', borderTop: '1px solid var(--fl-border)', fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', display: 'grid', gap: 4 },
};

export default function AuthGraphPanel({ caseId, collectionId }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [graphe, setGraphe] = useState(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState(null);
  const [services, setServices] = useState(false);
  const [echecsSeulement, setEchecsSeulement] = useState(false);
  const [selection, setSelection] = useState(null);
  const [carnet, setCarnet] = useState(null);

  const charger = useCallback(async () => {
    if (!caseId || !collectionId) return;
    setChargement(true);
    setErreur(null);
    try {
      const r = await networkAPI.authGraph(caseId, collectionId, { services });
      setGraphe(r.data);
      setSelection(null);
    } catch (e) {
      setErreur(e?.response?.data?.error || e?.message || String(e));
    } finally {
      setChargement(false);
    }
  }, [caseId, collectionId, services]);

  useEffect(() => { charger(); }, [charger]);

  const elements = useMemo(() => elementsCytoscape(graphe, { echecsSeulement }), [graphe, echecsSeulement]);
  const aretes = useMemo(() => aretesVisibles(graphe, { echecsSeulement }), [graphe, echecsSeulement]);
  const areteChoisie = aretes.find((a) => a.id === selection) || null;
  const ignores = graphe?.stats?.ignores || {};
  const date = (iso) => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const pivoter = (a) => navigate(timelinePivotUrl({ caseId, collectionId, filters: filtresDePivot(a) }));

  useEffect(() => { setCarnet(null); }, [selection]);

  const versLeCarnet = (a) => {
    setCarnet('envoi');
    notebookAPI.append(caseId, entreeArete(
      { ...a, sources: repartition(a.sources), filtres: filtresDePivot(a) },
      { source: t('collection.auth.source_label'), caseId, evidenceId: collectionId },
    ))
      .then(() => setCarnet('ok'))
      .catch(() => setCarnet('echec'));
  };

  return (
    <div style={S.racine}>
      <div style={S.barre}>
        <h2 style={S.titre}><KeyRound size={13} color="var(--fl-accent)" aria-hidden="true" />{t('collection.auth.title')}</h2>
        {graphe && (
          <div style={S.chiffres}>
            <span>{t('collection.auth.users', { count: graphe.stats.utilisateurs })}</span>
            <span>{t('collection.auth.machines', { count: graphe.stats.machines })}</span>
            <span>{t('collection.auth.events', { count: graphe.stats.evenements })}</span>
            <span style={S.echec}>{t('collection.auth.failures', { count: graphe.stats.echecs })}</span>
          </div>
        )}
        <div style={S.actions}>
          <label style={S.option}>
            <input type="checkbox" checked={echecsSeulement} onChange={(e) => setEchecsSeulement(e.target.checked)} />
            {t('collection.auth.failures_only')}
          </label>
          <label style={S.option}>
            <input type="checkbox" checked={services} onChange={(e) => setServices(e.target.checked)} />
            {t('collection.auth.include_services')}
          </label>
          <Button size="sm" variant="ghost" icon={RefreshCw} loading={chargement} onClick={charger}>{t('collection.auth.refresh')}</Button>
        </div>
      </div>

      {graphe && (
        <div style={S.note}>
          {t('collection.auth.ignored', {
            machines: ignores.compte_machine || 0,
            systeme: ignores.compte_systeme || 0,
            services: ignores.logon_service || 0,
            anonymes: ignores.sans_identite || 0,
          })}
          {' '}{t('collection.auth.sources_note')}
        </div>
      )}
      {graphe?.tronque && <Alert variant="warn" message={t('collection.auth.truncated')} style={{ margin: '0 12px 8px' }} />}
      {erreur && <Alert message={erreur} style={{ margin: 12 }} />}
      {chargement && !graphe && <Spinner full text={t('collection.auth.loading')} />}

      {graphe && aretes.length === 0 && (
        <EmptyState icon={KeyRound} title={t('collection.auth.empty')} subtitle={t('collection.auth.empty_hint')} />
      )}

      {graphe && aretes.length > 0 && (
        <div style={S.corps}>
          <div style={S.graphe}>
            <AuthGraphCanvas elements={elements} selection={selection} onSelect={setSelection} libelle={t('collection.auth.graph_label')} />
          </div>
          <div style={S.tableau}>
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={headStyle(false)}>{t('collection.auth.col_user')}</th>
                  <th style={headStyle(false)}>{t('collection.auth.col_machine')}</th>
                  <th style={{ ...headStyle(true), textAlign: 'right' }}>{t('collection.auth.col_failures')}</th>
                  <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.auth.col_success')}</th>
                  <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.auth.col_explicit')}</th>
                </tr>
              </thead>
              <tbody>
                {aretes.map((a) => (
                  <tr key={a.id} style={S.ligne(a.id === selection)} aria-selected={a.id === selection}>
                    <td style={cellStyle()}>
                      <button type="button" style={S.bouton} onClick={() => setSelection(a.id)}>{a.utilisateur}</button>
                    </td>
                    <td style={{ ...cellStyle(), ...S.mono }}>{a.machine}</td>
                    <td style={{ ...cellStyle({ numeric: true }), ...(a.echec ? S.echec : S.mono) }}>{a.echec}</td>
                    <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{a.succes}</td>
                    <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{a.explicite}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {areteChoisie && (
              <div style={S.detail}>
                <div>{t('collection.auth.detail_sources')} : {repartition(areteChoisie.sources) || '—'}</div>
                <div>{t('collection.auth.detail_logon_types')} : {repartition(areteChoisie.typesLogon) || '—'}</div>
                <div>{t('collection.auth.detail_event_ids')} : {repartition(areteChoisie.eventIds) || '—'}</div>
                <div>{t('collection.auth.detail_window', { from: date(areteChoisie.premier), to: date(areteChoisie.dernier) })}</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <Button size="sm" icon={ExternalLink} onClick={() => pivoter(areteChoisie)}>{t('collection.auth.open_timeline')}</Button>
                  <Button size="sm" variant="ghost" icon={BookOpen} loading={carnet === 'envoi'} onClick={() => versLeCarnet(areteChoisie)}>
                    {carnet === 'ok' ? t('notebook.sent') : carnet === 'echec' ? t('notebook.send_failed') : t('collection.auth.to_notebook')}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
