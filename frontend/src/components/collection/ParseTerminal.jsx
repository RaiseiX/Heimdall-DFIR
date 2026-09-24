import { useState, useEffect, useLayoutEffect, useRef, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { collectionAPI } from '../../utils/api';
import { useSocketEvent } from '../../hooks/useSocket';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { cleDeLigne, fusionner, pourLesPreuves, filtrer, heure, texteExport, nomExport, ligneTexte } from './journalVue';

const NIVEAUX_SIGNALES = new Set(['warn', 'error']);
const MARGE_BAS = 8;

function Surligne({ texte, requete }) {
  const q = requete.trim().toLowerCase();
  if (!q) return texte;
  const morceaux = [];
  const bas = texte.toLowerCase();
  let i = 0;
  for (let j = bas.indexOf(q); j >= 0; j = bas.indexOf(q, i)) {
    if (j > i) morceaux.push(texte.slice(i, j));
    morceaux.push(<mark key={j}>{texte.slice(j, j + q.length)}</mark>);
    i = j + q.length;
  }
  if (i < texte.length) morceaux.push(texte.slice(i));
  return morceaux;
}

export default function ParseTerminal({ caseId, socket, preuves = null, lignesNavigateur = [], provenance = [], titre, requete, onRequete }) {
  const { t, i18n } = useTranslation();
  const [serveur, setServeur] = useState([]);
  const [requeteInterne, setRequeteInterne] = useState('');
  const [suivi, setSuivi] = useState(true);
  const [copie, setCopie] = useState(null);
  const corpsRef = useRef(null);
  const q = requete ?? requeteInterne;
  const changerRequete = onRequete ?? setRequeteInterne;
  const clePreuves = preuves ? preuves.join('\n') : null;

  const charger = useCallback(() => {
    if (!caseId) return;
    collectionAPI.parseLog(caseId)
      .then(r => setServeur(s => fusionner(s, Array.isArray(r.data?.lignes) ? r.data.lignes : [])))
      .catch(() => {});
  }, [caseId]);

  useEffect(() => { setServeur([]); charger(); }, [charger]);
  useSocketEvent(socket, 'collection:log', ligne => {
    if (ligne && ligne.caseId === caseId) setServeur(s => fusionner(s, [ligne]));
  });
  useSocketEvent(socket, 'connect', charger);

  const toutes = useMemo(
    () => fusionner(pourLesPreuves(serveur, clePreuves === null ? null : clePreuves.split('\n').filter(Boolean)), lignesNavigateur),
    [serveur, clePreuves, lignesNavigateur],
  );
  const visibles = useMemo(() => filtrer(toutes, q), [toutes, q]);

  useLayoutEffect(() => {
    const el = corpsRef.current;
    if (suivi && el) el.scrollTop = el.scrollHeight;
  }, [visibles, suivi]);

  useEffect(() => {
    if (!copie) return undefined;
    const minuteur = setTimeout(() => setCopie(null), 1400);
    return () => clearTimeout(minuteur);
  }, [copie]);

  if (toutes.length === 0) return null;

  const surDefilement = () => {
    const el = corpsRef.current;
    if (!el) return;
    const enBas = el.scrollHeight - el.scrollTop - el.clientHeight < MARGE_BAS;
    if (enBas !== suivi) setSuivi(enBas);
  };
  const reprendre = () => {
    setSuivi(true);
    const el = corpsRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  };
  const copier = async () => {
    try { await navigator.clipboard.writeText(toutes.map(ligneTexte).join('\n')); setCopie('ok'); } catch { setCopie('refus'); }
  };
  const exporter = () => {
    const maintenant = new Date();
    const blob = new Blob([texteExport(toutes, { provenance, maintenant })], { type: 'text/plain;charset=utf-8' });
    const lien = document.createElement('a');
    lien.href = URL.createObjectURL(blob);
    lien.download = nomExport(provenance[0]?.nom, maintenant);
    document.body.appendChild(lien);
    lien.click();
    lien.remove();
    setTimeout(() => URL.revokeObjectURL(lien.href), 1000);
  };

  const compte = q.trim()
    ? t('collection.import.journal.lignes_filtrees', { n: visibles.length, total: toutes.length })
    : t('collection.import.journal.lignes', { count: toutes.length });

  return (
    <details className="fl-term-details" open>
      <summary>{t('collection.import.journal.summary')}</summary>
      <div className="fl-term">
        <div className="fl-term-tete">
          <span className="fl-term-titre">{titre}</span>
          <span className="fl-term-n">{compte}</span>
          <span className="fl-term-esp" />
          <span className="fl-term-grep">
            <label htmlFor={`fl-term-grep-${caseId}`}>grep</label>
            <input id={`fl-term-grep-${caseId}`} value={q} onChange={e => changerRequete(e.target.value)}
              placeholder={t('collection.import.journal.grep_placeholder')} autoComplete="off" spellCheck={false} />
          </span>
          <button type="button" style={controlStyle(suivi)} {...controlHover(suivi)} aria-pressed={suivi}
            onClick={() => (suivi ? setSuivi(false) : reprendre())}>
            {t('collection.import.journal.suivre')}
          </button>
          <button type="button" style={controlStyle(false)} {...controlHover(false)} onClick={copier}>
            {copie === 'ok' ? t('collection.import.journal.copie') : copie === 'refus' ? t('collection.import.journal.copie_refusee') : t('collection.import.journal.copier')}
          </button>
          <button type="button" style={controlStyle(false)} {...controlHover(false)} onClick={exporter}
            title={t('collection.import.journal.exporter_aide')}>
            {t('collection.import.journal.exporter')}
          </button>
        </div>
        <div ref={corpsRef} className="fl-term-corps" tabIndex={0} onScroll={surDefilement}
          aria-label={t('collection.import.journal.summary')}>
          {visibles.map(l => {
            const signale = NIVEAUX_SIGNALES.has(l.niveau);
            const classe = `fl-term-l${l.source === 'navigateur' ? ' fl-term-nav' : ''}${signale ? ` fl-term-${l.niveau}` : ''}`;
            return (
              <div key={cleDeLigne(l)} className={classe}>
                <span className="fl-term-t">{heure(l.ts, i18n.language)}</span>
                <span className="fl-term-s">{l.source}</span>
                <span className="fl-term-m">
                  {signale && <span className="fl-term-niv">{l.niveau}</span>}
                  <Surligne texte={l.message} requete={q} />
                </span>
              </div>
            );
          })}
          <span className="fl-term-curseur" aria-hidden="true" />
        </div>
        {!suivi && (
          <div className="fl-term-pause">
            <span>{t('collection.import.journal.pause')}</span>
            <button type="button" style={controlStyle(false)} {...controlHover(false)} onClick={reprendre}>
              {t('collection.import.journal.reprendre')}
            </button>
          </div>
        )}
      </div>
    </details>
  );
}
