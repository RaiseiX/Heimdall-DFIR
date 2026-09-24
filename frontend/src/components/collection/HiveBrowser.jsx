import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, ChevronRight, Search, X, ArrowLeft } from 'lucide-react';
import { collectionAPI } from '../../utils/api';
import { Button, Spinner, Alert, EmptyState } from '../ui';
import { tableStyle, headStyle, cellStyle } from '../ui/tableIdiom';
import { segmentsDeCle, hexGroupe } from '../../pages/collectionFiles';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  racine: { display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 },
  barre: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexWrap: 'wrap' },
  fil: { display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap', fontFamily: MONO, fontSize: 11, minWidth: 0, flex: 1 },
  segment: (actif) => ({ background: 'none', border: 'none', padding: '2px 4px', cursor: actif ? 'default' : 'pointer', fontFamily: MONO, fontSize: 11, color: actif ? 'var(--fl-text)' : 'var(--fl-accent)' }),
  formulaire: { display: 'flex', alignItems: 'center', gap: 6 },
  champ: { width: 200, fontFamily: MONO, fontSize: 11 },
  section: { padding: '8px 12px 4px', fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', letterSpacing: '0.06em' },
  bouton: { display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, textAlign: 'left' },
  mono: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'nowrap' },
  donnee: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-text)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' },
  note: { padding: '6px 12px', fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' },
  resultat: { padding: '6px 12px', borderBottom: '1px solid var(--fl-border)' },
  extrait: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', wordBreak: 'break-all' },
  defile: { overflow: 'auto', flex: 1, minHeight: 0 },
};

export default function HiveBrowser({ caseId, evidenceId, chemin, onClose }) {
  const { t, i18n } = useTranslation();
  const [cle, setCle] = useState('');
  const [niveau, setNiveau] = useState(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState(null);
  const [terme, setTerme] = useState('');
  const [recherche, setRecherche] = useState(null);

  const messageErreur = (e) => e?.response?.data?.error || e?.message || String(e);

  const ouvrirCle = useCallback(async (cible) => {
    setChargement(true);
    setErreur(null);
    setRecherche(null);
    try {
      const r = await collectionAPI.fileHive(caseId, evidenceId, chemin, { key: cible });
      setNiveau(r.data);
      setCle(r.data.path || '');
    } catch (e) {
      setErreur(messageErreur(e));
    } finally {
      setChargement(false);
    }
  }, [caseId, evidenceId, chemin]);

  useEffect(() => { ouvrirCle(''); }, [ouvrirCle]);

  const chercher = async (e) => {
    e.preventDefault();
    if (terme.trim().length < 2) return;
    setChargement(true);
    setErreur(null);
    try {
      const r = await collectionAPI.fileHive(caseId, evidenceId, chemin, { search: terme.trim() });
      setRecherche(r.data);
    } catch (err) {
      setErreur(messageErreur(err));
    } finally {
      setChargement(false);
    }
  };

  const date = (iso) => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');
  const segments = segmentsDeCle(cle);
  const erreursLecture = (recherche || niveau)?.errors || [];

  return (
    <div style={S.racine}>
      <div style={S.barre}>
        <Button size="sm" variant="ghost" icon={ArrowLeft} onClick={onClose}>{t('collection.hive.back')}</Button>
        <nav aria-label={t('collection.hive.breadcrumb')} style={S.fil}>
          <button type="button" style={S.segment(segments.length === 0)} onClick={() => ouvrirCle('')} disabled={segments.length === 0}>
            {chemin.split('/').pop()}
          </button>
          {segments.map((s, i) => (
            <span key={s.chemin} style={S.fil}>
              <ChevronRight size={11} color="var(--fl-muted)" aria-hidden="true" />
              <button type="button" style={S.segment(i === segments.length - 1)} onClick={() => ouvrirCle(s.chemin)} disabled={i === segments.length - 1}>
                {s.nom}
              </button>
            </span>
          ))}
        </nav>
        <form onSubmit={chercher} style={S.formulaire} role="search">
          <input className="fl-input" style={S.champ} value={terme} maxLength={200}
            onChange={(e) => setTerme(e.target.value)}
            placeholder={t('collection.hive.search_placeholder')} aria-label={t('collection.hive.search_placeholder')} />
          <Button type="submit" size="sm" icon={Search} disabled={terme.trim().length < 2}>{t('collection.hive.search')}</Button>
          {recherche && <Button size="sm" variant="ghost" icon={X} onClick={() => setRecherche(null)}>{t('collection.hive.clear_search')}</Button>}
        </form>
      </div>

      <div style={S.note}>{t('collection.hive.primary_only')}</div>
      {erreur && <Alert message={erreur} style={{ margin: 12 }} />}
      {erreursLecture.length > 0 && (
        <Alert variant="warn" style={{ margin: '0 12px 8px' }}
          message={t('collection.hive.read_errors', { count: erreursLecture.length, first: `${erreursLecture[0].path || '\\'} : ${erreursLecture[0].error}` })} />
      )}
      {chargement && !niveau && <Spinner full text={t('collection.files.loading')} />}

      <div style={S.defile}>
        {recherche ? (
          <>
            <div style={S.note}>
              {t('collection.hive.search_summary', { count: recherche.matches.length, visited: recherche.visited })}
              {recherche.truncated && ` · ${t(`collection.hive.stopped.${recherche.stoppedBy}`)}`}
            </div>
            {recherche.matches.length === 0 && <EmptyState icon={Search} title={t('collection.hive.search_empty')} />}
            {recherche.matches.map((m, i) => (
              <div key={`${m.path}-${m.name}-${i}`} style={S.resultat}>
                <button type="button" style={S.bouton} onClick={() => ouvrirCle(m.path)}>
                  <KeyRound size={12} color="var(--fl-accent)" aria-hidden="true" />
                  {m.path || '\\'}
                </button>
                <div style={S.extrait}>
                  {m.kind === 'key' ? t('collection.hive.match_key') : `${t('collection.hive.match_value')} ${m.name}`}
                  {m.snippet ? ` — ${m.snippet}` : ''}
                </div>
              </div>
            ))}
          </>
        ) : niveau && (
          <>
            <div style={S.section}>{t('collection.hive.subkeys', { count: niveau.subkeysTotal })}</div>
            {niveau.subkeys.length > 0 && (
              <table style={tableStyle}>
                <thead>
                  <tr>
                    <th style={headStyle(false)}>{t('collection.hive.col_key')}</th>
                    <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.hive.col_values')}</th>
                    <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.hive.col_subkeys')}</th>
                    <th style={headStyle(false)}>{t('collection.hive.col_last_write')}</th>
                  </tr>
                </thead>
                <tbody>
                  {niveau.subkeys.map((sk) => (
                    <tr key={sk.path}>
                      <td style={cellStyle()}>
                        <button type="button" style={S.bouton} onClick={() => ouvrirCle(sk.path)}>
                          <KeyRound size={12} color="var(--fl-accent)" aria-hidden="true" />{sk.name}
                        </button>
                      </td>
                      <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{sk.valueCount ?? '?'}</td>
                      <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{sk.subkeyCount ?? '?'}</td>
                      <td style={{ ...cellStyle(), ...S.mono }}>{date(sk.lastWrite)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {niveau.subkeysTruncated && <div style={S.note}>{t('collection.hive.truncated', { shown: niveau.subkeys.length, total: niveau.subkeysTotal })}</div>}

            <div style={S.section}>{t('collection.hive.values', { count: niveau.valuesTotal })}</div>
            {niveau.values.length > 0 && (
              <table style={tableStyle}>
                <thead>
                  <tr>
                    <th style={headStyle(false)}>{t('collection.hive.col_name')}</th>
                    <th style={headStyle(false)}>{t('collection.hive.col_type')}</th>
                    <th style={headStyle(false)}>{t('collection.hive.col_data')}</th>
                  </tr>
                </thead>
                <tbody>
                  {niveau.values.map((v, i) => (
                    <tr key={`${v.name}-${i}`}>
                      <td style={{ ...cellStyle(), ...S.mono }}>{v.name}</td>
                      <td style={{ ...cellStyle(), ...S.mono }}>{v.type}</td>
                      <td style={{ ...cellStyle(), ...S.donnee }}>
                        {v.binary ? hexGroupe(v.data) : v.data}
                        {v.truncated && ` ${t('collection.hive.value_truncated')}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {niveau.valuesTruncated && <div style={S.note}>{t('collection.hive.truncated', { shown: niveau.values.length, total: niveau.valuesTotal })}</div>}
          </>
        )}
      </div>
    </div>
  );
}
