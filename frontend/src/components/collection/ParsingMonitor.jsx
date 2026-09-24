import { useState, useEffect, useRef, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { collectionAPI } from '../../utils/api';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { avancement, lignesIndexees, parseursOrdonnes, masquesParPlateforme, dureeLisible, parseurPrincipal } from './parsingView';
import { fmtOctets } from './octets';

const PARSER_TACTIC = {
  registry: 'persistence', lnk: 'persistence', jumplist: 'persistence', bits: 'persistence', schtasks: 'persistence', wmi: 'persistence',
  amcache: 'execution', appcompat: 'execution', prefetch: 'execution', srum: 'execution', pwsh: 'execution', userassist: 'execution',
  usn: 'defense-evasion', indx: 'defense-evasion', recycle: 'defense-evasion',
  shellbags: 'discovery', evtx: 'discovery', netprofile: 'discovery',
  sqle: 'collection', webcache: 'collection', sum: 'lateral-movement',
  usb: 'exfiltration', dns: 'command-and-control', 'vuln-drivers': 'privilege-escalation',
};

const TACTICS = [
  ['execution', 'Execution'], ['persistence', 'Persistence'], ['privilege-escalation', 'Privilege escalation'],
  ['defense-evasion', 'Defense evasion'], ['discovery', 'Discovery'], ['lateral-movement', 'Lateral movement'],
  ['collection', 'Collection'], ['command-and-control', 'C2'], ['exfiltration', 'Exfiltration'],
];

const ETATS = {
  queued: 'collection.pm_queued',
  parsing: 'collection.pm_parsing',
  done: 'collection.pm_done',
  skipped: 'collection.pm_skipped',
  error: 'collection.pm_error',
};

const CLASSE_LIGNE = { parsing: 'fl-pm-lg fl-pm-cours', error: 'fl-pm-lg fl-pm-rate' };
const FINIS = new Set(['done', 'skipped', 'error']);
const FENETRE_DEBIT = 15000;

export default function ParsingMonitor({ fileName, parsers, states, live, caseId, plateforme, masques, raison, octetsDistincts }) {
  const { t, i18n } = useTranslation();
  const langue = i18n.language;
  const nombre = (v) => Number(v || 0).toLocaleString(langue);

  const [hist, setHist] = useState([]);
  useEffect(() => {
    if (!caseId || !live) return;
    let vivant = true;
    let enVol = false;
    const sonder = () => {
      if (enVol) return;
      enVol = true;
      collectionAPI.timelineHistogram(caseId, 48)
        .then(r => { if (vivant) setHist(r.data?.buckets || []); })
        .catch(() => {})
        .finally(() => { enVol = false; });
    };
    sonder();
    const iv = setInterval(sonder, 10000);
    return () => { vivant = false; clearInterval(iv); };
  }, [caseId, live]);
  const histMax = Math.max(1, ...hist);

  const totalRecords = useMemo(() => lignesIndexees(states), [states]);
  const pas = useMemo(() => avancement(states), [states]);

  const debutRef = useRef(Date.now());
  const releveRef = useRef(Date.now());
  const echantillonsRef = useRef([]);
  const [debit, setDebit] = useState(0);
  const [ecoule, setEcoule] = useState(0);

  useEffect(() => {
    const maintenant = Date.now();
    releveRef.current = maintenant;
    echantillonsRef.current.push({ t: maintenant, lignes: totalRecords });
    echantillonsRef.current = echantillonsRef.current.filter(e => maintenant - e.t < FENETRE_DEBIT);
    const e = echantillonsRef.current;
    if (e.length >= 2) {
      const dt = (e[e.length - 1].t - e[0].t) / 1000;
      if (dt > 0.5) setDebit(Math.max(0, (e[e.length - 1].lignes - e[0].lignes) / dt));
    }
    setEcoule(maintenant - debutRef.current);
  }, [totalRecords, pas.termines]);

  useEffect(() => {
    if (!live) return undefined;
    const iv = setInterval(() => setEcoule(Date.now() - debutRef.current), 1000);
    return () => clearInterval(iv);
  }, [live]);

  const couvertes = useMemo(() => {
    const vu = new Set();
    for (const p of parsers || []) {
      if (states?.[p.key]?.status === 'done' && PARSER_TACTIC[p.key]) vu.add(PARSER_TACTIC[p.key]);
    }
    return vu;
  }, [parsers, states]);

  const ordonnes = useMemo(() => parseursOrdonnes(parsers, states), [parsers, states]);
  const groupes = useMemo(() => masquesParPlateforme(masques), [masques]);
  const [devoiler, setDevoiler] = useState(false);

  const principal = useMemo(() => parseurPrincipal(states), [states]);
  const enCours = principal
    ? ordonnes.find(p => p.key === principal.cle) || { key: principal.cle }
    : ordonnes.find(p => states?.[p.key]?.status === 'parsing');
  const enOctets = pas.mesure === 'octets';
  const aideOctets = !enOctets ? undefined : Number.isInteger(octetsDistincts)
    ? t('collection.pm_bytes_read_hint', { total: fmtOctets(pas.octetsTotal), distincts: fmtOctets(octetsDistincts) })
    : t('collection.pm_bytes_read_hint_short');
  const heureReleve = new Date(releveRef.current).toLocaleTimeString(langue);

  if (!parsers || parsers.length === 0) return null;

  return (
    <div className="fl-pm">
      <div className="fl-pm-tete">
        <span className="fl-pm-titre">{t('collection.parsing_monitor')}</span>
        {fileName && <span className="fl-pm-fic" title={fileName}>{fileName}</span>}
        {plateforme && <span className="fl-pm-relev">{plateforme}</span>}
        <span className="fl-pm-relev">{t('collection.pm_last_reading', { heure: heureReleve })}</span>
      </div>

      <div className="fl-pm-compteurs">
        <span className="fl-pm-compteur">
          <b>{nombre(totalRecords)}</b><em>{t('collection.pm_rows_indexed')}</em>
        </span>
        {debit > 0 && (
          <span className="fl-pm-compteur">
            <b>{nombre(Math.round(debit))}</b><em>{t('collection.pm_rows_per_sec')}</em>
          </span>
        )}
        {dureeLisible(ecoule) && (
          <span className="fl-pm-compteur">
            <b>{dureeLisible(ecoule)}</b><em>{t('collection.pm_elapsed')}</em>
          </span>
        )}
      </div>

      <div className="fl-pm-avance">
        <span title={aideOctets}>
          {enOctets
            ? t('collection.pm_bytes_read', { lus: fmtOctets(pas.octetsLus), total: fmtOctets(pas.octetsTotal) })
            : t('collection.pm_parsers_done', { n: pas.termines, total: pas.total })}
        </span>
        <span className="fl-pm-piste"><i style={{ width: `${pas.pct}%` }} /></span>
      </div>

      <div className="fl-pm-encours">
        {enCours
          ? <>{t('collection.pm_running')} <b>{enCours.name || enCours.key}</b></>
          : raison === 'aucun-artefact-detecte'
            ? t('collection.pm_no_artifact')
            : t('collection.pm_none_running')}
        {principal && (
          <span className="fl-pm-part">
            {' '}{t('collection.pm_running_share', { taille: fmtOctets(principal.octets), part: principal.part })}
            {principal.autres > 0 && t('collection.pm_running_others', { count: principal.autres })}
          </span>
        )}
        {enOctets && (
          <><span className="fl-pm-pt">·</span>{t('collection.pm_parsers_done', { n: pas.termines, total: pas.total })}</>
        )}
      </div>

      <div className="fl-pm-questions">
        <span className="fl-pm-quoi">{t('collection.pm_questions')}</span>
        {TACTICS.map(([cle, libelle], idx) => (
          <span key={cle}>
            {idx > 0 && <span className="fl-pm-pt">·</span>}
            <span className={couvertes.has(cle) ? 'fl-pm-q' : 'fl-pm-q-dort'}>{libelle}</span>
          </span>
        ))}
      </div>

      <div className="fl-pm-liste">
        {ordonnes.map(p => {
          const etat = states?.[p.key]?.status || 'queued';
          const lignes = states?.[p.key]?.records;
          return (
            <div key={p.key} className={CLASSE_LIGNE[etat] || (FINIS.has(etat) ? 'fl-pm-lg' : 'fl-pm-lg fl-pm-file')}>
              <span className="fl-pm-nom">{p.name || p.key}</span>
              <span className="fl-pm-etat">{t(ETATS[etat] || ETATS.queued)}</span>
              <span className="fl-pm-n">{etat === 'done' && lignes != null ? nombre(lignes) : '—'}</span>
            </div>
          );
        })}
      </div>

      <div className="fl-pm-masques">
        {groupes.length === 0
          ? <span>{plateforme ? t('collection.pm_listed', { n: pas.total }) : t('collection.pm_platform_unknown')}</span>
          : (
            <>
              <span>
                {t('collection.pm_listed', { n: pas.total })}
                {' · '}
                {t('collection.pm_masked', {
                  detail: groupes
                    .map(g => t('collection.pm_masked_group', {
                      n: g.n,
                      plateforme: g.plateforme || t('collection.pm_masked_unknown'),
                    }))
                    .join(' · '),
                })}
              </span>
              <button style={controlStyle(false)} {...controlHover(false)} onClick={() => setDevoiler(v => !v)}>
                {devoiler ? t('collection.pm_hide') : t('collection.pm_show_anyway')}
              </button>
              {devoiler && (
                <ul>{masques.map(m => <li key={m.cle}>{m.cle}</li>)}</ul>
              )}
            </>
          )}
      </div>

      {hist.some(v => v > 0) && (
        <div className="fl-pm-histo">
          <div className="fl-pm-histo-barres">
            {hist.map((v, i) => {
              const h = v > 0 ? Math.max(8, (Math.log(v + 1) / Math.log(histMax + 1)) * 100) : 0;
              return (
                <i key={i}
                  title={t('collection.pm_events', { n: nombre(v) })}
                  style={{ height: `${h}%`, minHeight: v > 0 ? 3 : 0, background: v > 0 ? undefined : 'transparent' }} />
              );
            })}
          </div>
          <div className="fl-pm-histo-mot">{t('collection.pm_histogram')}</div>
        </div>
      )}
    </div>
  );
}
