import { useState, useEffect, useMemo, Fragment } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { timelinePivotUrl } from '../../utils/timelinePivot';
import { entreeProcessus } from '../../utils/notebookEntry';
import { notebookAPI, iocsAPI } from '../../utils/api';
import { collectionAPI } from '../../utils/api';
import { controlStyle, separatorStyle } from '../ui/controlIdiom';
import { buildTreeRows, markKernel, collapsibleIds, filtrerProcessus, racinesDe, sessionsDe, ecartLisible, cheminBinaire, cleDe } from './processTree';
import { binaireRemplaceApres, taillesConcordent } from './dossier';
import { classeDensite, largeurPanneauValide, DENSITES, LARGEUR_PANNEAU } from './presentation';
import { AlignJustify, Menu, StretchHorizontal } from 'lucide-react';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const FS_TITRE  = 13;
const FS_DONNEE = 12;
const FS_TEXTE  = 11;
const FS_MICRO  = 10;

const WRAP = { display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 };
const BARRE = {
  display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
  borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap',
};
const SOMMAIRE = { marginLeft: 'auto', display: 'flex', gap: 16, fontSize: FS_TEXTE, color: 'var(--fl-dim)' };
const FORT = { fontFamily: MONO, color: 'var(--fl-text)', fontVariantNumeric: 'tabular-nums' };
const PANNEAUX = { display: 'grid', gridTemplateColumns: 'minmax(0,1fr) var(--fl-panneau, 340px)', flex: 1, minHeight: 0 };
const COL = { overflow: 'auto', minHeight: 0 };
const TABLE = {};
const TH = {};
const TH_NUM = { textAlign: 'right' };
const TH_QUAND = { width: 92 };
const TH_PROC = { width: 420 };
const TH_PID = { textAlign: 'right', width: 64 };
const TH_USER = { width: 120 };
const TD = { whiteSpace: 'nowrap' };
const NUM = { ...TD, textAlign: 'right', fontVariantNumeric: 'tabular-nums', color: 'var(--fl-dim)' };
const TD_QUAND = { ...TD, color: 'var(--fl-muted)', fontVariantNumeric: 'tabular-nums' };
const TD_USER = { ...TD, color: 'var(--fl-muted)' };
const TD_SESSION = {
  paddingLeft: 10, paddingRight: 10, borderBottom: '1px solid var(--fl-border)',
  fontFamily: MONO, fontSize: FS_TEXTE, whiteSpace: 'nowrap', cursor: 'pointer',
};
const SESSION_DATE = { color: 'var(--fl-text)', fontWeight: 500 };
const SESSION_META = { color: 'var(--fl-muted)' };
const SESSION_ECART = { color: 'var(--fl-dim)' };
const BASCULE_SESSION = { display: 'inline-block', width: 12, color: 'var(--fl-muted)', userSelect: 'none', verticalAlign: 'middle', lineHeight: 1 };
const BLOC = { marginBottom: 16 };
const ALERTE = {
  marginTop: 8, fontSize: FS_TEXTE, lineHeight: 1.5,
  color: 'var(--fl-warning, var(--fl-text))',
  borderLeft: '2px solid var(--fl-warning, var(--fl-border))', paddingLeft: 10,
};
const ABSENT = { fontSize: FS_TEXTE, color: 'var(--fl-muted)', lineHeight: 1.5, margin: 0 };
const EVTS_TABLE = { width: '100%', borderCollapse: 'collapse' };
const EVTS_TD = {
  fontFamily: MONO, fontSize: FS_TEXTE, padding: '2px 0',
  borderBottom: '1px solid var(--fl-border2, var(--fl-border))', verticalAlign: 'baseline',
};
const EVTS_N = { ...EVTS_TD, textAlign: 'right', width: 42, color: 'var(--fl-text)', fontVariantNumeric: 'tabular-nums', paddingRight: 10 };
const EVTS_EID = { ...EVTS_TD, width: 52, color: 'var(--fl-dim)', fontVariantNumeric: 'tabular-nums' };
const EVTS_LIB = { ...EVTS_TD, color: 'var(--fl-muted)' };
const DETAIL = { overflow: 'auto', minHeight: 0, padding: '12px 14px', borderLeft: '1px solid var(--fl-border)', position: 'relative' };
const DENSITE_ICONES = { compact: AlignJustify, normal: Menu, relaxed: StretchHorizontal };
const ETIQ = {
  fontSize: FS_MICRO,
  color: 'var(--fl-dim)', marginBottom: 3,
};
const VAL = { fontFamily: MONO, fontSize: FS_TEXTE, wordBreak: 'break-all', marginBottom: 12 };
const VAL_SOURD = { ...VAL, color: 'var(--fl-muted)' };
const VAL_DIM = { ...VAL, color: 'var(--fl-dim)' };
const VAL_ALERTE = { ...VAL, color: 'var(--fl-warning, var(--fl-text))' };
const NOTE = { fontSize: FS_TEXTE, color: 'var(--fl-dim)', lineHeight: 1.5, marginBottom: 12 };

const TR = { borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))', cursor: 'pointer' };
const TR_SEL = { ...TR, background: 'var(--fl-accent-soft, transparent)' };
const INDENT = { color: 'var(--fl-dim)', userSelect: 'none', whiteSpace: 'pre', verticalAlign: 'middle' };
const BASCULE = { display: 'inline-block', width: 14, color: 'var(--fl-dim)', verticalAlign: 'middle', lineHeight: 1 };
const NOM = { color: 'var(--fl-text)', verticalAlign: 'middle' };
const NOM_NOYAU = { color: 'var(--fl-dim)', verticalAlign: 'middle' };
const TD_BIN = { ...TD, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--fl-dim)' };
const TD_BIN_SUPPR = { ...TD_BIN, color: 'var(--fl-warning, var(--fl-text))' };
const NUM_ALERTE = { ...NUM, color: 'var(--fl-warning, var(--fl-dim))' };

function heureDe(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
}

function CelluleProcessus({ name, profondeur, aDesEnfants, replie, noyau, onBasculer }) {
  return (
    <td className="fl-td-mono" style={TD}>
      <span style={INDENT}>{'  '.repeat(profondeur)}</span>
      <span role={aDesEnfants ? 'button' : undefined}
        onClick={aDesEnfants ? onBasculer : undefined}
        style={BASCULE}>
        {aDesEnfants ? (replie ? '+' : '\u2212') : ' '}
      </span>
      <span style={noyau ? NOM_NOYAU : NOM}>{name}</span>
    </td>
  );
}

export default function CollectionProcessesTab({ caseId, collectionId }) {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [donnees, setDonnees] = useState(null);
  const [erreur, setErreur] = useState(null);
  const [chargement, setChargement] = useState(true);
  const [vue, setVue] = useState('arbre');
  const [recherche, setRecherche] = useState('');
  const [replies, setReplies] = useState(() => new Set());
  const [sansNoyau, setSansNoyau] = useState(false);
  const [choisi, setChoisi] = useState(null);
  const [fichierChoisi, setFichierChoisi] = useState(null);
  const [comptes, setComptes] = useState(null);
  const [source, setSource] = useState('snapshot');
  const [seulExpose, setSeulExpose] = useState(false);
  const [seulExterne, setSeulExterne] = useState(false);
  const [fichiers, setFichiers] = useState(null);
  const [fichiersPour, setFichiersPour] = useState(null);
  const [carnet, setCarnet] = useState(null);
  const [iocHash, setIocHash] = useState(null);
  const [seulSupprime, setSeulSupprime] = useState(false);
  const [evts, setEvts] = useState(null);
  const [evtsPour, setEvtsPour] = useState(null);
  const [sessionsRepliees, setSessionsRepliees] = useState(() => new Set());
  const [dossier, setDossier] = useState(null);
  const [densite, setDensite] = useState(() => localStorage.getItem('fl_proc_densite') || 'normal');
  const [largeurPanneau, setLargeurPanneau] = useState(
    () => largeurPanneauValide(localStorage.getItem('fl_proc_panneau')));

  useEffect(() => {
    try { localStorage.setItem('fl_proc_densite', densite); } catch { }
  }, [densite]);

  useEffect(() => {
    document.documentElement.style.setProperty('--fl-panneau', `${largeurPanneau}px`);
    try { localStorage.setItem('fl_proc_panneau', String(largeurPanneau)); } catch { }
    return () => document.documentElement.style.removeProperty('--fl-panneau');
  }, [largeurPanneau]);

  const classeTable = `fl-table ${classeDensite(densite)}`;

  const debutRedim = (e) => {
    e.preventDefault();
    const depart = e.clientX;
    const initiale = largeurPanneau;
    const bouger = (ev) => setLargeurPanneau(largeurPanneauValide(initiale + (depart - ev.clientX)));
    const relacher = () => {
      document.removeEventListener('mousemove', bouger);
      document.removeEventListener('mouseup', relacher);
    };
    document.addEventListener('mousemove', bouger);
    document.addEventListener('mouseup', relacher);
  };

  useEffect(() => {
    if (!caseId || !collectionId) return;
    let vivant = true;
    setChargement(true);
    setErreur(null);
    collectionAPI.processes(caseId, collectionId)
      .then(r => {
        if (!vivant) return;
        if ((r.data?.processes || []).length > 0) { setDonnees(r.data); setSource('snapshot'); return null; }
        return collectionAPI.windowsProcesses(caseId, collectionId).then(w => {
          if (!vivant) return;
          setDonnees({ ...w.data, shared: [] });
          setSource('events');
        });
      })
      .catch(e => {
        if (vivant) setErreur(e?.response?.data?.error || e?.message || t('processes.unreachable'));
      })
      .finally(() => { if (vivant) setChargement(false); });
    return () => { vivant = false; };
  }, [caseId, collectionId, t]);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    let vivant = true;
    setComptes(null);
    collectionAPI.processFileCounts(caseId, collectionId)
      .then(r => { if (vivant) setComptes(r.data?.counts || []); })
      .catch(() => { if (vivant) setComptes([]); });
    return () => { vivant = false; };
  }, [caseId, collectionId]);

  const procs = useMemo(() => {
    const brut = (donnees?.processes || []).map(p => p.name
      ? p
      : { ...p, name: String(p.image || '').split(/[\\/]/).pop() || String(p.pid) });
    const base = markKernel(brut);
    if (source === 'events' || !comptes) return base;
    const parPid = new Map(comptes.map(c => [c.pid, c]));
    return base.map(p => {
      const c = parPid.get(p.pid);
      return { ...p, fd: Number(c?.fd || 0), maps: Number(c?.maps || 0), deleted_count: Number(c?.deleted_count || 0) };
    });
  }, [donnees, comptes, source]);
  const estEvts = source === 'events';

  const blocs = useMemo(() => {
    if (!estEvts) return [];
    return sessionsDe(procs).map(s => ({
      depart: s.depart,
      evenements: s.evenements,
      ecart: ecartLisible(s.ecartMs),
      replie: sessionsRepliees.has(s.depart),
      lignes: buildTreeRows(filtrerProcessus(s.evenements, { seulSupprime, seulExpose, seulExterne }),
                            { replies, recherche, sansNoyau }),
    }));
  }, [estEvts, procs, replies, recherche, sansNoyau, seulSupprime, seulExpose, seulExterne, sessionsRepliees]);

  const toutDeplier = () => { setReplies(new Set()); setSessionsRepliees(new Set()); };
  const toutReplier = () => {
    setReplies(collapsibleIds(procs));
    setSessionsRepliees(new Set(blocs.map(x => x.depart)));
  };

  const basculerSession = (depart) => setSessionsRepliees(prev => {
    const suiv = new Set(prev);
    suiv.has(depart) ? suiv.delete(depart) : suiv.add(depart);
    return suiv;
  });

  const lignes = useMemo(
    () => buildTreeRows(filtrerProcessus(procs, { seulSupprime, seulExpose, seulExterne }),
                        { replies, recherche, sansNoyau }),
    [procs, replies, recherche, sansNoyau, seulSupprime, seulExpose, seulExterne],
  );

  const nomsParSha1 = useMemo(() => {
    const m = new Map();
    for (const p of procs) {
      if (!p.sha1) continue;
      if (!m.has(p.sha1)) m.set(p.sha1, new Set());
      m.get(p.sha1).add(p.name);
    }
    return m;
  }, [procs]);

  const socketsParPid = useMemo(() => {
    const m = new Map();
    for (const c of (donnees?.network || [])) {
      if (!m.has(c.pid)) m.set(c.pid, []);
      m.get(c.pid).push(c);
    }
    return m;
  }, [donnees]);
  const parPid = useMemo(() => new Map(procs.map(p => [p.pid, p])), [procs]);
  const parCle = useMemo(() => new Map(procs.map(p => [cleDe(p), p])), [procs]);
  const partages = donnees?.shared || [];

  const sommaire = useMemo(() => ({
    total: procs.length,
    racines: racinesDe(procs).length,
    binaires: new Set(procs.map(p => p.name).filter(Boolean)).size,
    comptes: [...new Set(procs.map(p => p.user_name).filter(Boolean))],
    avecFichiers: procs.filter(p => p.fd > 0 || p.maps > 0).length,
    deleted_count: procs.filter(p => p.deleted_count > 0).length,
    comptesPrets: comptes != null,
    binairesSupprimes: procs.filter(p => p.exe_deleted).length,
    ecoutesExposees: procs.reduce((a, p) => a + Number(p.net_listen_exposed || 0), 0),
    etabliesExternes: procs.reduce((a, p) => a + Number(p.net_estab_external || 0), 0),
    procExposes: procs.filter(p => Number(p.net_listen_exposed) > 0).length,
    procExternes: procs.filter(p => Number(p.net_estab_external) > 0).length,
  }), [procs, comptes]);

  useEffect(() => {
    if (!caseId) return;
    iocsAPI.hashMatches(caseId)
      .then(r => setIocHash(r.data))
      .catch(() => setIocHash({ matches: [], unmatchable: [], erreur: true }));
  }, [caseId]);

  const parSha1 = useMemo(() => {
    const m = new Map();
    for (const x of (iocHash?.matches || [])) m.set(x.sha1, x);
    return m;
  }, [iocHash]);

  const versLeCarnet = (p) => {
    setCarnet('envoi');
    notebookAPI.append(caseId, entreeProcessus(p, { source: t('processes.title'), caseId, evidenceId: collectionId }))
      .then(() => setCarnet('ok'))
      .catch(() => setCarnet('echec'));
  };

  const chargerFichiers = (p) => {
    setFichiersPour(p.pid);
    setFichiers('chargement');
    collectionAPI.processFiles(caseId, collectionId, p.pid)
      .then(r => setFichiers(r.data))
      .catch(() => setFichiers({ files: [], erreur: true }));
  };

  const fenetreDe = (p) => {
    if (!estEvts) return null;
    const i = blocs.findIndex(b => b.evenements.some(e => e.id === p.id));
    if (i < 0) return null;
    return { from: p.timestamp || blocs[i].depart, to: blocs[i + 1]?.depart || null };
  };

  const chargerEvenements = (p) => {
    setEvtsPour(p.pid);
    setEvts('chargement');
    collectionAPI.processEvents(caseId, collectionId, p.pid, p.name, fenetreDe(p))
      .then(r => setEvts(r.data))
      .catch(() => setEvts({ events: [], scope: null, reason: 'error' }));
  };

  const basculer = (pid) => setReplies(prev => {
    const s = new Set(prev);
    s.has(pid) ? s.delete(pid) : s.add(pid);
    return s;
  });

  const selection = choisi != null ? parCle.get(choisi) : null;
  const parent = selection
    ? (parCle.get(selection.parent_id) || parPid.get(selection.ppid) || null)
    : null;
  const chemin = cheminBinaire(selection);

  useEffect(() => {
    if (!estEvts || !selection || !chemin) { setDossier(null); return undefined; }
    let vivant = true;
    setDossier('chargement');
    collectionAPI.processDossier(caseId, collectionId, selection.pid, chemin, fenetreDe(selection))
      .then(r => { if (vivant) setDossier(r.data); })
      .catch(() => { if (vivant) setDossier({ erreur: true }); });
    return () => { vivant = false; };
  }, [estEvts, caseId, collectionId, selection, chemin]);

  const dossierPret = dossier && dossier !== 'chargement' && !dossier.erreur ? dossier : null;
  const concordance = dossierPret
    ? taillesConcordent(dossierPret.amcache?.taille, dossierPret.mft?.taille) : null;
  const remplace = dossierPret
    ? binaireRemplaceApres(selection?.timestamp, dossierPret.mft?.cree) : null;
  const ecartRemplace = remplace ? ecartLisible(remplace.ecartMs) : null;

  if (chargement) {
    return <div style={{ padding: 16, color: 'var(--fl-dim)', fontSize: FS_DONNEE }}>{t('processes.loading')}</div>;
  }
  if (erreur) {
    return (
      <div style={{ padding: 16, color: 'var(--fl-danger)', fontFamily: MONO, fontSize: FS_TEXTE }}>
        {t('processes.failed')} — {erreur}
      </div>
    );
  }
  if (!procs.length) {
    const vide = source === 'events' ? 'processes.none_windows' : 'processes.none';
    return (
      <div style={{ padding: 16, color: 'var(--fl-dim)', fontSize: FS_DONNEE, maxWidth: '70ch', lineHeight: 1.6 }}>
        {t(vide)}
      </div>
    );
  }
  const porteurs = fichierChoisi
    ? (partages.find(f => f.target === fichierChoisi)?.pids || [])
    : [];

  return (
    <div style={WRAP}>
      <div style={BARRE}>
        <button type="button" onClick={() => setVue('arbre')} aria-pressed={vue === 'arbre'}
          style={{ ...controlStyle(vue === 'arbre'), color: vue === 'arbre' ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
          {t('processes.view_tree')}
        </button>
        {source !== 'events' && <button type="button" onClick={() => setVue('partage')} aria-pressed={vue === 'partage'}
          style={{ ...controlStyle(vue === 'partage'), color: vue === 'partage' ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
          {t('processes.view_shared')}
        </button>}

        {vue === 'arbre' && (
          <>
            <input type="search" value={recherche} onChange={e => setRecherche(e.target.value)}
              placeholder={t('processes.filter_placeholder')} aria-label={t('processes.filter_placeholder')}
              style={{ ...controlStyle(false), fontFamily: MONO, width: 230 }} />
            <button type="button" onClick={toutDeplier} style={controlStyle(false)}>
              {t('processes.expand_all')}
            </button>
            <button type="button" onClick={toutReplier} style={controlStyle(false)}>
              {t('processes.collapse_all')}
            </button>
            <span style={separatorStyle} />
            {DENSITES.map(d => {
              const Icone = DENSITE_ICONES[d];
              return (
                <button key={d} type="button" onClick={() => setDensite(d)}
                  aria-pressed={densite === d} title={t(`timeline.density_${d}`)}
                  style={controlStyle(densite === d)}>
                  <Icone size={11} strokeWidth={1.6} />
                </button>
              );
            })}
            {sommaire.binairesSupprimes > 0 && (
              <button type="button" onClick={() => setSeulSupprime(v => !v)} aria-pressed={seulSupprime}
                style={{ ...controlStyle(seulSupprime), color: seulSupprime ? 'var(--fl-warning, var(--fl-accent))' : 'var(--fl-dim)' }}>
                {t('processes.only_deleted_binary')} ({sommaire.binairesSupprimes})
              </button>
            )}
            {sommaire.procExposes > 0 && (
              <button type="button" onClick={() => setSeulExpose(v => !v)} aria-pressed={seulExpose}
                style={{ ...controlStyle(seulExpose), color: seulExpose ? 'var(--fl-warning, var(--fl-accent))' : 'var(--fl-dim)' }}>
                {t('processes.only_exposed_listen')} ({sommaire.procExposes})
              </button>
            )}
            {sommaire.procExternes > 0 && (
              <button type="button" onClick={() => setSeulExterne(v => !v)} aria-pressed={seulExterne}
                style={{ ...controlStyle(seulExterne), color: seulExterne ? 'var(--fl-warning, var(--fl-accent))' : 'var(--fl-dim)' }}>
                {t('processes.only_external_estab')} ({sommaire.procExternes})
              </button>
            )}
            <button type="button" onClick={() => setSansNoyau(v => !v)} aria-pressed={sansNoyau}
              style={{ ...controlStyle(sansNoyau), color: sansNoyau ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
              {t('processes.hide_kernel')}
            </button>
          </>
        )}

        <div style={SOMMAIRE}>
          {estEvts && <span><b style={FORT}>{blocs.length}</b> {t('processes.count_boots')}</span>}
          <span>
            <b style={FORT}>{sommaire.total}</b>{' '}
            {estEvts ? t('processes.count_creations') : t('processes.count_processes')}
          </span>
          {estEvts
            ? <span><b style={FORT}>{sommaire.binaires}</b> {t('processes.count_binaries')}</span>
            : <span><b style={FORT}>{sommaire.racines}</b> {t('processes.count_roots')}</span>}
          {estEvts && sommaire.comptes.length === 1 && <span style={FORT}>{sommaire.comptes[0]}</span>}
          {sommaire.binairesSupprimes > 0 && (
            <span style={{ color: 'var(--fl-warning, var(--fl-dim))' }}>
              <b style={{ ...FORT, color: 'inherit' }}>{sommaire.binairesSupprimes}</b> {t('processes.count_deleted_binary')}
            </span>
          )}
          {sommaire.ecoutesExposees > 0 && (
            <span style={{ color: 'var(--fl-warning, var(--fl-dim))' }}>
              <b style={{ ...FORT, color: 'inherit' }}>{sommaire.ecoutesExposees}</b> {t('processes.count_exposed_listen')}
            </span>
          )}
          {sommaire.etabliesExternes > 0 && (
            <span><b style={FORT}>{sommaire.etabliesExternes}</b> {t('processes.count_estab_external')}</span>
          )}
          {source === 'events' ? null : sommaire.comptesPrets ? (
            <>
              <span><b style={FORT}>{sommaire.avecFichiers}</b> {t('processes.count_with_files')}</span>
              <span><b style={FORT}>{sommaire.deleted_count}</b> {t('processes.count_holding_deleted')}</span>
            </>
          ) : (
            <span>{t('processes.counting_files')}</span>
          )}
        </div>
      </div>

      <div style={{ padding: '7px 12px', fontSize: FS_TEXTE, color: 'var(--fl-dim)',
                    borderBottom: '1px solid var(--fl-border)', lineHeight: 1.5 }}>
        {source === 'events'
          ? t('processes.source_events', {
              n: procs.length,
              from: procs.length ? new Date(procs[0].timestamp).toLocaleString() : '',
              to: procs.length ? new Date(procs[procs.length - 1].timestamp).toLocaleString() : '',
            })
          : t('processes.source_snapshot')}
      </div>

      {vue === 'arbre' ? (
        <div style={PANNEAUX}>
          <div style={COL}>
            <table className={classeTable} style={TABLE}>
              <thead>
                <tr>
                  {estEvts && <th style={TH_QUAND}>{t('processes.col_when')}</th>}
                  <th style={estEvts ? TH_PROC : TH}>{t('processes.col_process')}</th>
                  <th style={estEvts ? TH_PID : TH_NUM}>{t('processes.col_pid')}</th>
                  <th style={estEvts ? TH_USER : TH}>{t('processes.col_user')}</th>
                  {estEvts && <th style={TH} />}
                  {!estEvts && <th style={TH}>{t('processes.col_state')}</th>}
                  {!estEvts && <th style={TH}>{t('processes.col_binary')}</th>}
                  {!estEvts && <th style={TH_NUM}>{t('processes.col_network')}</th>}
                  {!estEvts && <th style={TH_NUM}>{t('processes.col_fd')}</th>}
                  {!estEvts && <th style={TH_NUM}>{t('processes.col_maps')}</th>}
                  {!estEvts && <th style={TH_NUM}>{t('processes.col_deleted')}</th>}
                </tr>
              </thead>
              <tbody>
                {estEvts ? blocs.map(bloc => (
                  <Fragment key={bloc.depart}>
                    <tr onClick={() => basculerSession(bloc.depart)}>
                      <td className="fl-session" style={TD_SESSION} colSpan={5}>
                        <span style={BASCULE_SESSION}>{bloc.replie ? '+' : '\u2212'}</span>
                        <span style={SESSION_DATE}>{new Date(bloc.depart).toLocaleString()}</span>
                        <span style={SESSION_META}>{' \u00b7 '}{t('processes.session_creations', { n: bloc.evenements.length })}</span>
                        {bloc.ecart && (
                          <span style={SESSION_ECART}>
                            {' \u00b7 '}{t(`processes.gap_${bloc.ecart.unite}`, { n: bloc.ecart.n })}
                          </span>
                        )}
                      </td>
                    </tr>
                    {!bloc.replie && bloc.lignes.map(({ cle, pid, name, profondeur, aDesEnfants, proc }) => (
                      <tr key={cle} onClick={() => setChoisi(cle)}
                        aria-selected={choisi === cle}
                        style={choisi === cle ? TR_SEL : TR}>
                        <td className="fl-td-mono" style={TD_QUAND}>{heureDe(proc.timestamp)}</td>
                        <CelluleProcessus name={name} profondeur={profondeur} aDesEnfants={aDesEnfants}
                          replie={replies.has(cle)} noyau={proc.noyau}
                          onBasculer={(e) => { e.stopPropagation(); basculer(cle); }} />
                        <td className="fl-td-mono" style={NUM}>{pid}</td>
                        <td className="fl-td-mono" style={TD_USER}>{proc.user_name || '\u2014'}</td>
                        <td style={TD} />
                      </tr>
                    ))}
                  </Fragment>
                )) : lignes.map(({ cle, pid, name, profondeur, aDesEnfants, proc }) => (
                  <tr key={cle} onClick={() => setChoisi(cle)}
                    aria-selected={choisi === cle}
                    style={choisi === cle ? TR_SEL : TR}>
                    <CelluleProcessus name={name} profondeur={profondeur} aDesEnfants={aDesEnfants}
                      replie={replies.has(cle)} noyau={proc.noyau}
                      onBasculer={(e) => { e.stopPropagation(); basculer(cle); }} />
                    <td className="fl-td-mono" style={NUM}>{pid}</td>
                    <td className="fl-td-mono" style={TD}>{proc.user_name || '\u2014'}</td>
                    <td className="fl-td-mono" style={TD}>{proc.state || ''}</td>
                    <td className="fl-td-mono" style={proc.exe_deleted ? TD_BIN_SUPPR : TD_BIN}
                        title={proc.exe || ''}>
                      {proc.exe_deleted
                        ? `${proc.exe} \u00b7 ${t('processes.binary_deleted')}`
                        : proc.exe || (proc.exe_unreadable ? '\u00b7' : '')}
                    </td>
                    <td className="fl-td-mono" style={Number(proc.net_listen_exposed) ? NUM_ALERTE : NUM}
                        title={Number(proc.net_total)
                          ? `${proc.net_listen_exposed} ${t('processes.net_exposed')} \u00b7 ${proc.net_estab_external} ${t('processes.net_external')}`
                          : ''}>
                      {Number(proc.net_total)
                        ? `${proc.net_total}${Number(proc.net_listen_exposed) ? ' \u25B8' : ''}`
                        : '\u00b7'}
                    </td>
                    <td className="fl-td-mono" style={NUM}>{comptes == null ? '' : (proc.fd || '\u00b7')}</td>
                    <td className="fl-td-mono" style={NUM}>{comptes == null ? '' : (proc.maps || '\u00b7')}</td>
                    <td className="fl-td-mono" style={proc.deleted_count ? NUM_ALERTE : NUM}>
                      {comptes == null ? '' : (proc.deleted_count || '\u00b7')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <aside style={DETAIL}>
            <div className="fl-poignee" role="separator" aria-orientation="vertical"
              aria-label={t('processes.resize_panel')} onMouseDown={debutRedim} />
            {!selection ? (
              <div style={{ color: 'var(--fl-dim)', fontSize: FS_DONNEE }}>{t('processes.pick_a_row')}</div>
            ) : (
              <>
                <div style={{ fontSize: FS_TITRE, fontWeight: 600, marginBottom: 2 }}>{selection.name}</div>
                <div style={{ fontFamily: MONO, fontSize: FS_TEXTE, color: 'var(--fl-dim)', marginBottom: 14 }}>
                  pid {selection.pid} · {selection.user_name || '—'} · {selection.state || ''}
                </div>
                {(selection.sha1 || chemin) && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
                    {selection.sha1 && (
                      <button type="button" style={controlStyle(false)}
                        onClick={() => navigate(timelinePivotUrl({
                          caseId, collectionId, filters: { sha1Filter: selection.sha1, sha1FilterOp: 'equals' },
                        }))}>
                        {t('processes.pivot_hash')}
                      </button>
                    )}
                    {chemin && (
                      <button type="button" style={controlStyle(false)}
                        onClick={() => navigate(timelinePivotUrl({ caseId, collectionId, search: chemin }))}>
                        {t('processes.pivot_path')}
                      </button>
                    )}
                    <button type="button" style={controlStyle(false)}
                      onClick={() => versLeCarnet(selection)}>
                      {t('processes.to_notebook')}
                    </button>
                    {carnet === 'ok' && (
                      <span style={{ ...NOTE, marginBottom: 0, color: 'var(--fl-ok)', alignSelf: 'center' }}>
                        {t('notebook.sent')}
                      </span>
                    )}
                    {carnet === 'echec' && (
                      <span role="alert" style={{ ...NOTE, marginBottom: 0, color: 'var(--fl-danger)', alignSelf: 'center' }}>
                        {t('notebook.send_failed')}
                      </span>
                    )}
                  </div>
                )}
                {estEvts && selection.timestamp && (
                  <>
                    <div style={ETIQ}>{t('processes.col_started')}</div>
                    <div style={VAL}>{new Date(selection.timestamp).toLocaleString()}</div>
                  </>
                )}
                <div style={ETIQ}>{t('processes.started_by')}</div>
                <div style={VAL}>{parent ? `${parent.name} (pid ${parent.pid})` : t('processes.is_root')}</div>
                {chemin && (
                  <>
                    <div style={ETIQ}>{t('processes.col_binary')}</div>
                    <div style={{ ...VAL, color: selection.exe_deleted ? 'var(--fl-warning, var(--fl-text))' : undefined }}>
                      {chemin}
                      {selection.exe_deleted ? ` · ${t('processes.binary_deleted')}` : ''}
                    </div>
                  </>
                )}

                {estEvts && dossier === 'chargement' && <p style={ABSENT}>{t('processes.dossier_loading')}</p>}

                {dossierPret && (
                  <>
                    <div style={BLOC}>
                      <div style={ETIQ}>{t('processes.dossier_binary')}</div>
                      {!dossierPret.amcache && !dossierPret.mft ? (
                        <p style={ABSENT}>{t('processes.dossier_no_binary')}</p>
                      ) : (
                        <>
                          {dossierPret.amcache?.sha1 && (
                            <>
                              <div style={ETIQ}>{t('processes.col_sha1')}</div>
                              <div style={VAL}>{dossierPret.amcache.sha1}</div>
                            </>
                          )}
                          {concordance !== null && (
                            <>
                              <div style={ETIQ}>{t('processes.dossier_size')}</div>
                              <div style={concordance ? VAL_DIM : VAL_ALERTE}>
                                {concordance
                                  ? t('processes.dossier_sizes_agree', { n: dossierPret.amcache.taille })
                                  : t('processes.dossier_sizes_differ', { a: dossierPret.amcache.taille, b: dossierPret.mft.taille })}
                              </div>
                            </>
                          )}
                          {dossierPret.amcache?.version && (
                            <>
                              <div style={ETIQ}>{t('processes.dossier_version')}</div>
                              <div style={VAL}>{dossierPret.amcache.version}</div>
                            </>
                          )}
                          {dossierPret.mft?.cree && (
                            <>
                              <div style={ETIQ}>{t('processes.dossier_mft_created')}</div>
                              <div style={VAL}>{dossierPret.mft.cree}</div>
                            </>
                          )}
                          {dossierPret.mft?.modifie && (
                            <>
                              <div style={ETIQ}>{t('processes.dossier_mft_modified')}</div>
                              <div style={VAL}>{dossierPret.mft.modifie}</div>
                            </>
                          )}
                          {dossierPret.mft?.accede && (
                            <>
                              <div style={ETIQ}>{t('processes.dossier_mft_access')}</div>
                              <div style={VAL}>{dossierPret.mft.accede}</div>
                            </>
                          )}
                        </>
                      )}
                      {ecartRemplace && (
                        <p role="alert" style={ALERTE}>
                          {t('processes.dossier_replaced', {
                            ecart: t(`processes.gap_${ecartRemplace.unite}`, { n: ecartRemplace.n }),
                          })}
                        </p>
                      )}
                    </div>

                    <div style={BLOC}>
                      <div style={ETIQ}>{t('processes.dossier_homonyms')}</div>
                      {dossierPret.homonymes.length === 0 ? (
                        <p style={ABSENT}>{t('processes.dossier_homonyms_none')}</p>
                      ) : (
                        <>
                          {dossierPret.homonymes.map(h => (
                            <Fragment key={h.chemin}>
                              <div style={ETIQ}>{String(h.sha1 || '').slice(0, 8)}</div>
                              <div style={VAL_SOURD}>{h.chemin}</div>
                            </Fragment>
                          ))}
                        </>
                      )}
                    </div>

                    <div style={BLOC}>
                      <div style={ETIQ}>{t('processes.dossier_execution')}</div>
                      <>
                        <div style={ETIQ}>{t('processes.dossier_prefetch')}</div>
                        <div style={dossierPret.prefetch.length ? VAL : VAL_SOURD}>
                          {dossierPret.prefetch.length
                            ? t('processes.dossier_prefetch_runs', {
                                n: dossierPret.prefetch[0].executions,
                                quand: dossierPret.prefetch[0].derniere,
                              })
                            : t('processes.dossier_prefetch_none')}
                        </div>
                        <div style={ETIQ}>{t('processes.dossier_srum')}</div>
                        <div style={dossierPret.srum ? VAL : VAL_SOURD}>
                          {dossierPret.srum
                            ? t('processes.dossier_srum_value', {
                                quand: dossierPret.srum.quand, n: dossierPret.srum.ecrits || '0',
                              })
                            : t('processes.dossier_srum_none')}
                        </div>
                      </>
                    </div>

                    {dossierPret.repartition.length > 0 && (
                      <div style={BLOC}>
                        <div style={ETIQ}>{t('processes.dossier_events_dist')}</div>
                        <table style={EVTS_TABLE}>
                          <tbody>
                            {dossierPret.repartition.map(r => (
                              <tr key={r.event_id}>
                                <td style={EVTS_N}>{r.n}</td>
                                <td style={EVTS_EID}>{r.event_id}</td>
                                <td style={EVTS_LIB}>{r.libelle || '\u2014'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </>
                )}

                {selection.exe_deleted && (
                  <div style={NOTE}>
                    {t('processes.binary_deleted_note')}
                  </div>
                )}
                {selection.sha1 && (
                  <>
                    <div style={ETIQ}>{t('processes.col_sha1')}</div>
                    <div style={{ ...VAL, fontFamily: MONO, wordBreak: 'break-all', userSelect: 'all' }}>
                      {selection.sha1}
                    </div>
                    {selection.exe_deleted && (
                      <div style={NOTE}>
                        {t('processes.sha1_from_memory')}
                      </div>
                    )}
                    {iocHash && (parSha1.has(selection.sha1) ? (
                      <div role="alert" style={{ ...VAL, color: 'var(--fl-danger)' }}>
                        {t('processes.ioc_match')}
                        {parSha1.get(selection.sha1).severity != null
                          ? ` · ${t('processes.ioc_match_sev', { sev: parSha1.get(selection.sha1).severity })}`
                          : ''}
                      </div>
                    ) : (
                      <div style={NOTE}>
                        {t('processes.ioc_none')}
                        {(iocHash.unmatchable || []).map(u => (
                          <div key={u.ioc_type} style={{ color: 'var(--fl-warning, var(--fl-dim))', marginTop: 4 }}>
                            {t('processes.ioc_unmatchable', { n: u.total, type: u.ioc_type.replace('hash_', '').toUpperCase() })}
                          </div>
                        ))}
                      </div>
                    ))}
                    {Number(selection.sha1_names) > 1 && (
                      <>
                        <div style={ETIQ}>{t('processes.sha1_also_as')}</div>
                        <div style={{ ...VAL, color: 'var(--fl-warning, var(--fl-text))' }}>
                          {[...(nomsParSha1.get(selection.sha1) || [])]
                            .filter(n => n !== selection.name).join(', ') || '—'}
                        </div>
                        <div style={NOTE}>
                          {t('processes.sha1_shared_note')}
                        </div>
                      </>
                    )}
                  </>
                )}
                <div style={NOTE}>
                  {estEvts
                    ? t('processes.pivot_why_session', { n: blocs.length })
                    : t('processes.pivot_why_no_pid')}
                </div>
                {(socketsParPid.get(selection.pid) || []).length > 0 && (
                  <>
                    <div style={ETIQ}>{t('processes.col_network')}</div>
                    <table style={{ ...TABLE, marginBottom: 10 }}>
                      <thead>
                        <tr>
                          <th style={TH}>{t('processes.net_state')}</th>
                          <th style={TH}>{t('processes.net_proto')}</th>
                          <th style={TH}>{t('processes.net_local_addr')}</th>
                          <th style={TH}>{t('processes.net_peer')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(socketsParPid.get(selection.pid) || []).map((c, i) => (
                          <tr key={`${c.local_addr}-${c.peer}-${i}`}
                            style={{ borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                            <td style={{ ...TD, color: c.exposed ? 'var(--fl-warning, var(--fl-text))' : 'var(--fl-dim)' }}>
                              {c.state === 'LISTEN' ? t('processes.net_listen') : c.state === 'ESTAB' ? t('processes.net_estab') : c.state}
                            </td>
                            <td style={{ ...TD, color: 'var(--fl-dim)' }}>{c.proto}</td>
                            <td style={{ ...TD, fontFamily: MONO, color: c.exposed ? 'var(--fl-warning, var(--fl-text))' : undefined }}>
                              {c.local_addr}
                            </td>
                            <td style={{ ...TD, fontFamily: MONO, color: c.external ? 'var(--fl-warning, var(--fl-text))' : 'var(--fl-dim)' }}>
                              {c.external ? (
                                <span role="button" tabIndex={0}
                                  title={t('processes.pivot_peer')}
                                  onClick={() => navigate(timelinePivotUrl({
                                    caseId, collectionId, search: String(c.peer).replace(/:[0-9*]+$/, '').replace(/^\[|\]$/g, ''),
                                  }))}
                                  onKeyDown={e => { if (e.key === 'Enter') e.currentTarget.click(); }}
                                  style={{ cursor: 'pointer', textDecoration: 'underline' }}>
                                  {c.peer}
                                </span>
                              ) : c.peer}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
                {Number(selection.net_listen_exposed) > 0 && (
                  <div style={NOTE}>
                    {t('processes.net_exposed_note')}
                  </div>
                )}
                {Number(selection.net_estab_external) > 0 && Number(selection.net_listen_exposed) === 0 && (
                  <div style={NOTE}>
                    {t('processes.net_external_note')}
                  </div>
                )}
                {selection.exe_unreadable && !selection.exe && (
                  <div style={NOTE}>
                    {t('processes.binary_unreadable_note')}
                  </div>
                )}
                <div style={ETIQ}>{t('processes.command_line')}</div>
                <div style={VAL}>{selection.command_line || t('processes.not_collected')}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
                  <button type="button" style={controlStyle(false)}
                    onClick={() => chargerEvenements(selection)}>
                    {t('processes.events_button')}
                  </button>
                  {(Number(selection.fd) > 0 || Number(selection.maps) > 0) && (
                    <button type="button" style={controlStyle(false)}
                      onClick={() => chargerFichiers(selection)}>
                      {t('processes.files_show')} ({Number(selection.fd || 0) + Number(selection.maps || 0)})
                    </button>
                  )}
                </div>

                {fichiersPour === selection.pid && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={ETIQ}>{t('processes.files_title')}</div>
                    {fichiers === 'chargement' ? (
                      <div style={{ fontSize: FS_TEXTE, color: 'var(--fl-dim)' }}>{t('processes.files_loading')}</div>
                    ) : !fichiers?.files?.length ? (
                      <div style={{ fontSize: FS_TEXTE, color: 'var(--fl-dim)' }}>{t('processes.files_none')}</div>
                    ) : (
                      <>
                        {fichiers.capped && (
                          <div style={{ fontSize: FS_MICRO, color: 'var(--fl-dim)', lineHeight: 1.5, marginBottom: 6 }}>
                            {t('processes.files_capped')}
                          </div>
                        )}
                        <table className={classeTable} style={TABLE}>
                          <thead>
                            <tr>
                              <th style={TH}>{t('processes.files_col_kind')}</th>
                              <th style={TH}>{t('processes.files_col_path')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {fichiers.files.map((f, i) => (
                              <tr key={`${f.kind}-${f.target}-${i}`}
                                style={{ borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                                <td style={{ ...TD, color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
                                  {f.kind === 'catscale_proc_open_fd'
                                    ? t('processes.files_kind_fd')
                                    : t('processes.files_kind_map')}
                                </td>
                                <td style={{ ...TD, fontFamily: MONO, wordBreak: 'break-all',
                                             color: (f.deleted || f.memfd) ? 'var(--fl-warning, var(--fl-text))' : undefined }}>
                                  {f.target}
                                  {f.deleted ? ` · ${t('processes.files_flag_deleted')}` : ''}
                                  {f.memfd ? ` · ${t('processes.files_flag_memfd')}` : ''}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {fichiers.files.some(f => f.memfd) && (
                          <div style={{ ...NOTE, marginBottom: 0, marginTop: 6 }}>
                            {t('processes.files_memfd_note')}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {evtsPour === selection.pid && (
                  <div style={{ marginBottom: 14 }}>
                    {evts === 'chargement' ? (
                      <div style={{ fontSize: FS_TEXTE, color: 'var(--fl-dim)' }}>{t('processes.events_loading')}</div>
                    ) : !evts?.scope ? (
                      <div style={{ fontSize: FS_TEXTE, color: 'var(--fl-warning, var(--fl-dim))', lineHeight: 1.5 }}>
                        {t('processes.events_no_boot')}
                      </div>
                    ) : (
                      <>
                        <div style={{ fontSize: FS_MICRO, color: 'var(--fl-dim)', lineHeight: 1.5, marginBottom: 6 }}>
                          {t(estEvts ? 'processes.events_scope_session' : 'processes.events_scope', {
                            taken: new Date(evts.scope.taken_at).toLocaleString(),
                          })}
                          {evts.capped ? ' ' + t('processes.events_capped', { n: evts.events.length }) : ''}
                        </div>
                        {evts.events.length === 0 ? (
                          <div style={{ fontSize: FS_TEXTE, color: 'var(--fl-dim)' }}>{t('processes.events_none')}</div>
                        ) : (
                          <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontFamily: MONO, fontSize: FS_MICRO }}>
                            {evts.events.slice(0, 60).map(e => (
                              <li key={e.id} style={{ padding: '2px 0', borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                                <span style={{ color: 'var(--fl-dim)' }}>
                                  {new Date(e.timestamp).toISOString().slice(0, 19).replace('T', ' ')}
                                </span>
                                <span> {e.description}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </>
                    )}
                  </div>
                )}

                {!estEvts && (
                  <>
                    <div style={ETIQ}>{t('processes.holds_open')}</div>
                    <div style={VAL}>
                      {comptes == null ? t('processes.counting_files') : t('processes.holds_summary', {
                        fd: selection.fd, maps: selection.maps, deleted: selection.deleted_count,
                      })}
                    </div>
                  </>
                )}
              </>
            )}
          </aside>
        </div>
      ) : (
        <div style={PANNEAUX}>
          <div style={COL}>
            <div style={{ padding: '10px 14px', fontSize: FS_DONNEE, color: 'var(--fl-dim)', maxWidth: '76ch', lineHeight: 1.6 }}>
              {t('processes.shared_explainer')}
            </div>
            <table className={classeTable} style={TABLE}>
              <thead>
                <tr>
                  <th style={TH_NUM}>{t('processes.col_holders')}</th>
                  <th style={TH}>{t('processes.col_deleted_file')}</th>
                </tr>
              </thead>
              <tbody>
                {partages.map(f => (
                  <tr key={f.target} onClick={() => setFichierChoisi(f.target)}
                    aria-selected={fichierChoisi === f.target}
                    style={{
                      borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))',
                      cursor: 'pointer',
                      background: fichierChoisi === f.target ? 'var(--fl-accent-soft, transparent)' : undefined,
                    }}>
                    <td className="fl-td-mono" style={NUM}>{f.holders}</td>
                    <td style={{ ...TD, direction: 'rtl', textAlign: 'left', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {f.target}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <aside style={DETAIL}>
            {!fichierChoisi ? (
              <div style={{ color: 'var(--fl-dim)', fontSize: FS_DONNEE }}>{t('processes.pick_a_file')}</div>
            ) : (
              <>
                <div style={ETIQ}>{t('processes.col_deleted_file')}</div>
                <div style={VAL}>{fichierChoisi}</div>
                <div style={ETIQ}>{t('processes.holders_count', { count: porteurs.length })}</div>
                <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontFamily: MONO, fontSize: FS_TEXTE }}>
                  {porteurs.map(pid => {
                    const p = parPid.get(pid);
                    return (
                      <li key={pid} style={{ padding: '2px 0', borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                        <span style={{ color: p ? 'var(--fl-text)' : 'var(--fl-dim)' }}>
                          {p ? p.name : t('processes.absent_from_tree')}
                        </span>
                        <span style={{ color: 'var(--fl-dim)' }}> {pid}</span>
                      </li>
                    );
                  })}
                </ul>
              </>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
