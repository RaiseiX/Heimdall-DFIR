import { useState, useEffect, useCallback } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Folder, FileText, Link2, Download, Search, X, ChevronRight, KeyRound, BookOpen } from 'lucide-react';
import { collectionAPI, notebookAPI } from '../utils/api';
import { entreeFichier } from '../utils/notebookEntry';
import { Button, Spinner, Alert, EmptyState } from '../components/ui';
import { tableStyle, headStyle, cellStyle } from '../components/ui/tableIdiom';
import HiveBrowser from '../components/collection/HiveBrowser';
import { formatOctets, segmentsDeChemin, lignesHex, estUneRuche } from './collectionFiles';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  page: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 },
  barre: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexWrap: 'wrap' },
  fil: { display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap', fontFamily: MONO, fontSize: 11, minWidth: 0 },
  segment: (actif) => ({ background: 'none', border: 'none', padding: '2px 4px', cursor: actif ? 'default' : 'pointer', fontFamily: MONO, fontSize: 11, color: actif ? 'var(--fl-text)' : 'var(--fl-accent)' }),
  recherche: { display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' },
  champ: { width: 260, fontFamily: MONO, fontSize: 11 },
  corps: { display: 'grid', gridTemplateColumns: 'minmax(280px, 42%) 1fr', flex: 1, minHeight: 0 },
  gauche: { overflow: 'auto', borderRight: '1px solid var(--fl-border)' },
  droite: { overflow: 'auto', display: 'flex', flexDirection: 'column', minWidth: 0 },
  ligneBouton: { display: 'flex', alignItems: 'center', gap: 6, width: '100%', background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, textAlign: 'left' },
  mono: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'nowrap' },
  enteteApercu: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', flexWrap: 'wrap' },
  titreApercu: { fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', wordBreak: 'break-all', flex: 1, minWidth: 0 },
  texte: { margin: 0, padding: 12, fontFamily: MONO, fontSize: 11, lineHeight: 1.5, color: 'var(--fl-text)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' },
  hex: { margin: 0, padding: 12, fontFamily: MONO, fontSize: 11, lineHeight: 1.5, color: 'var(--fl-text)', whiteSpace: 'pre' },
  note: { padding: '6px 12px', fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' },
  resultat: { padding: '8px 12px', borderBottom: '1px solid var(--fl-border)' },
  extrait: { margin: '4px 0 0', fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' },
};

function IconeEntree({ type }) {
  if (type === 'dir') return <Folder size={12} color="var(--fl-accent)" aria-hidden="true" />;
  if (type === 'lien') return <Link2 size={12} color="var(--fl-muted)" aria-hidden="true" />;
  return <FileText size={12} color="var(--fl-dim)" aria-hidden="true" />;
}

export default function CollectionFilesPage() {
  const { t, i18n } = useTranslation();
  const { caseId, collectionId } = useOutletContext() || {};
  const [parametres] = useSearchParams();
  const cheminDemande = parametres.get('path') || '';
  const fichierDemande = parametres.get('file') || '';

  const [chemin, setChemin] = useState('');
  const [liste, setListe] = useState(null);
  const [chargementListe, setChargementListe] = useState(false);
  const [erreurListe, setErreurListe] = useState(null);

  const [selection, setSelection] = useState(null);
  const [apercu, setApercu] = useState(null);
  const [chargementApercu, setChargementApercu] = useState(false);
  const [erreurApercu, setErreurApercu] = useState(null);

  const [terme, setTerme] = useState('');
  const [resultats, setResultats] = useState(null);
  const [chargementRecherche, setChargementRecherche] = useState(false);
  const [erreurRecherche, setErreurRecherche] = useState(null);
  const [telechargement, setTelechargement] = useState(false);
  const [vueRuche, setVueRuche] = useState(false);
  const [carnet, setCarnet] = useState(null);

  const messageErreur = (e) => e?.response?.data?.error || e?.message || String(e);

  const chargerListe = useCallback(async (cible) => {
    if (!caseId || !collectionId) return;
    setChargementListe(true);
    setErreurListe(null);
    try {
      const r = await collectionAPI.files(caseId, collectionId, cible);
      setListe(r.data);
      setChemin(r.data.chemin || '');
    } catch (e) {
      setErreurListe(messageErreur(e));
    } finally {
      setChargementListe(false);
    }
  }, [caseId, collectionId]);

  useEffect(() => {
    setSelection(null);
    setApercu(null);
    setResultats(null);
    chargerListe(cheminDemande);
  }, [chargerListe, cheminDemande]);

  const ouvrirFichier = useCallback(async (cible, offset = 0, ajout = false) => {
    setSelection(cible);
    if (!ajout) setVueRuche(false);
    setChargementApercu(true);
    setErreurApercu(null);
    try {
      const r = await collectionAPI.fileContent(caseId, collectionId, cible, { offset });
      setApercu((precedent) => (ajout && precedent && !r.data.binaire
        ? { ...r.data, texte: precedent.texte + r.data.texte, offset: precedent.offset, longueur: precedent.longueur + r.data.longueur }
        : r.data));
    } catch (e) {
      setErreurApercu(messageErreur(e));
      if (!ajout) setApercu(null);
    } finally {
      setChargementApercu(false);
    }
  }, [caseId, collectionId]);

  useEffect(() => {
    if (fichierDemande) ouvrirFichier(fichierDemande);
  }, [fichierDemande, ouvrirFichier]);

  useEffect(() => { setCarnet(null); }, [selection]);

  const versLeCarnet = () => {
    if (!selection || !caseId) return;
    const entree = (liste?.entrees || []).find((e) => e.chemin === selection);
    setCarnet('envoi');
    notebookAPI.append(caseId, entreeFichier(
      { chemin: selection, taille: apercu?.chemin === selection ? apercu.taille : entree?.taille, modifie: entree?.modifie },
      { source: t('collection.files.source_label'), caseId, evidenceId: collectionId },
    ))
      .then(() => setCarnet('ok'))
      .catch(() => setCarnet('echec'));
  };

  const ouvrirEntree = (entree) => {
    if (entree.type === 'dir') {
      setResultats(null);
      chargerListe(entree.chemin);
    } else {
      ouvrirFichier(entree.chemin);
    }
  };

  const lancerRecherche = async (e) => {
    e.preventDefault();
    if (terme.trim().length < 2) return;
    setChargementRecherche(true);
    setErreurRecherche(null);
    try {
      const r = await collectionAPI.filesSearch(caseId, collectionId, terme.trim(), chemin);
      setResultats(r.data);
    } catch (err) {
      setErreurRecherche(messageErreur(err));
    } finally {
      setChargementRecherche(false);
    }
  };

  const effacerRecherche = () => {
    setTerme('');
    setResultats(null);
    setErreurRecherche(null);
  };

  const telecharger = async () => {
    if (!selection) return;
    setTelechargement(true);
    try {
      const r = await collectionAPI.fileDownload(caseId, collectionId, selection);
      const url = URL.createObjectURL(r.data);
      const lien = document.createElement('a');
      lien.href = url;
      lien.download = selection.split('/').pop() || 'fichier';
      document.body.appendChild(lien);
      lien.click();
      lien.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErreurApercu(messageErreur(e));
    } finally {
      setTelechargement(false);
    }
  };

  const dateCourte = (iso) => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');
  const segments = segmentsDeChemin(chemin);

  return (
    <div style={S.page}>
      <div style={S.barre}>
        <nav aria-label={t('collection.files.breadcrumb')} style={S.fil}>
          <button type="button" style={S.segment(segments.length === 0)} onClick={() => chargerListe('')} disabled={segments.length === 0}>
            {t('collection.files.root')}
          </button>
          {segments.map((s, i) => (
            <span key={s.chemin} style={S.fil}>
              <ChevronRight size={11} color="var(--fl-muted)" aria-hidden="true" />
              <button type="button" style={S.segment(i === segments.length - 1)} onClick={() => chargerListe(s.chemin)} disabled={i === segments.length - 1}>
                {s.nom}
              </button>
            </span>
          ))}
        </nav>
        <form onSubmit={lancerRecherche} style={S.recherche} role="search">
          <input
            className="fl-input"
            style={S.champ}
            value={terme}
            onChange={(e) => setTerme(e.target.value)}
            placeholder={t('collection.files.search_placeholder')}
            aria-label={t('collection.files.search_placeholder')}
            maxLength={200}
          />
          <Button type="submit" size="sm" icon={Search} loading={chargementRecherche} disabled={terme.trim().length < 2}>
            {t('collection.files.search')}
          </Button>
          {resultats && (
            <Button size="sm" variant="ghost" icon={X} onClick={effacerRecherche} title={t('collection.files.clear_search')}>
              {t('collection.files.clear_search')}
            </Button>
          )}
        </form>
      </div>

      <div style={S.corps}>
        <div style={S.gauche}>
          {erreurRecherche && <Alert message={erreurRecherche} style={{ margin: 12 }} />}
          {resultats ? (
            <div>
              <div style={S.note}>
                {t('collection.files.search_summary', { count: resultats.resultats.length, scanned: resultats.fichiersParcourus })}
                {resultats.tronque && ` · ${t(`collection.files.search_truncated.${resultats.raison}`)}`}
              </div>
              {resultats.resultats.length === 0 && <EmptyState icon={Search} title={t('collection.files.search_empty')} />}
              {resultats.resultats.map((r) => (
                <div key={r.chemin} style={S.resultat}>
                  <button type="button" style={S.ligneBouton} onClick={() => ouvrirFichier(r.chemin)}>
                    <FileText size={12} color="var(--fl-dim)" aria-hidden="true" />
                    {r.chemin}
                  </button>
                  {r.lignes.map((l) => (
                    <pre key={l.numero} style={S.extrait}>{`${l.numero}: ${l.texte}`}</pre>
                  ))}
                </div>
              ))}
            </div>
          ) : (
            <>
              {erreurListe && <Alert message={erreurListe} style={{ margin: 12 }} />}
              {chargementListe && !liste && <Spinner full text={t('collection.files.loading')} />}
              {liste && (
                <table style={tableStyle}>
                  <thead>
                    <tr>
                      <th style={headStyle(false)}>{t('collection.files.col_name')}</th>
                      <th style={{ ...headStyle(false), textAlign: 'right' }}>{t('collection.files.col_size')}</th>
                      <th style={headStyle(false)}>{t('collection.files.col_modified')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liste.parent !== null && (
                      <tr>
                        <td style={cellStyle()} colSpan={3}>
                          <button type="button" style={S.ligneBouton} onClick={() => chargerListe(liste.parent)}>
                            <Folder size={12} color="var(--fl-muted)" aria-hidden="true" />..
                          </button>
                        </td>
                      </tr>
                    )}
                    {liste.entrees.map((e) => (
                      <tr key={e.chemin} aria-selected={selection === e.chemin}>
                        <td style={cellStyle()}>
                          <button type="button" style={S.ligneBouton} onClick={() => ouvrirEntree(e)}
                            title={e.type === 'lien' ? t('collection.files.symlink_hint') : e.nom}>
                            <IconeEntree type={e.type} />
                            {e.nom}
                          </button>
                        </td>
                        <td style={{ ...cellStyle({ numeric: true }), ...S.mono }}>{formatOctets(e.taille)}</td>
                        <td style={{ ...cellStyle(), ...S.mono }}>{dateCourte(e.modifie)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {liste && liste.entrees.length === 0 && <EmptyState icon={Folder} title={t('collection.files.empty_dir')} />}
              {liste?.tronque && (
                <div style={S.note}>{t('collection.files.list_truncated', { shown: liste.entrees.length, total: liste.total })}</div>
              )}
            </>
          )}
        </div>

        <div style={S.droite}>
          {!selection && <EmptyState icon={FileText} title={t('collection.files.pick_file')} />}
          {selection && vueRuche && (
            <HiveBrowser caseId={caseId} evidenceId={collectionId} chemin={selection} onClose={() => setVueRuche(false)} />
          )}
          {selection && !vueRuche && (
            <>
              <div style={S.enteteApercu}>
                <span style={S.titreApercu}>{selection}</span>
                {apercu && <span style={S.mono}>{formatOctets(apercu.taille)}</span>}
                {estUneRuche(selection.split('/').pop()) && (
                  <Button size="sm" icon={KeyRound} onClick={() => setVueRuche(true)}>
                    {t('collection.hive.open')}
                  </Button>
                )}
                <Button size="sm" icon={Download} loading={telechargement} onClick={telecharger}>
                  {t('collection.files.download')}
                </Button>
                <Button size="sm" variant="ghost" icon={BookOpen} loading={carnet === 'envoi'} onClick={versLeCarnet}>
                  {carnet === 'ok' ? t('notebook.sent') : carnet === 'echec' ? t('notebook.send_failed') : t('collection.files.to_notebook')}
                </Button>
              </div>
              {erreurApercu && <Alert message={erreurApercu} style={{ margin: 12 }} />}
              {chargementApercu && !apercu && <Spinner full text={t('collection.files.loading')} />}
              {apercu && apercu.chemin === selection && (apercu.binaire ? (
                <>
                  <div style={S.note}>
                    {t('collection.files.binary_preview', { from: apercu.offset, to: apercu.offset + apercu.longueur, total: apercu.taille })}
                    {' '}
                    {apercu.offset > 0 && (
                      <Button size="xs" variant="ghost" loading={chargementApercu}
                        onClick={() => ouvrirFichier(selection, Math.max(0, apercu.offset - 4096))}>
                        {t('collection.files.previous_block')}
                      </Button>
                    )}
                    {apercu.tronque && (
                      <Button size="xs" variant="ghost" loading={chargementApercu}
                        onClick={() => ouvrirFichier(selection, apercu.offset + apercu.longueur)}>
                        {t('collection.files.next_block')}
                      </Button>
                    )}
                  </div>
                  <pre style={S.hex}>
                    {lignesHex(apercu.hex, apercu.ascii, apercu.offset).map((l) => `${l.adresse}  ${l.hex.padEnd(47)}  ${l.ascii}`).join('\n')}
                  </pre>
                </>
              ) : (
                <>
                  <pre style={S.texte}>{apercu.texte}</pre>
                  {apercu.tronque && (
                    <div style={S.note}>
                      {t('collection.files.text_truncated', { shown: formatOctets(apercu.offset + apercu.longueur), total: formatOctets(apercu.taille) })}
                      {' '}
                      <Button size="xs" variant="ghost" loading={chargementApercu}
                        onClick={() => ouvrirFichier(selection, apercu.offset + apercu.longueur, true)}>
                        {t('collection.files.load_more')}
                      </Button>
                    </div>
                  )}
                </>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
