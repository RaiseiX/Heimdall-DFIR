import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { evidenceAPI } from '../../utils/api';
import { Alert } from '../ui';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { designation, lignesTexte, morceaux, lignesHexa, nomEncodage, octetsDuNom } from './fichiersVue';

const ENCODAGES = ['auto', 'utf-8', 'utf-16le', 'windows-1252', 'hexa'];
const K = 'collection.fichiers';

function Segment({ actif, onClick, children }) {
  return (
    <button type="button" aria-pressed={actif} style={controlStyle(actif)} {...controlHover(actif)} onClick={onClick}>
      {children}
    </button>
  );
}

function Action({ onClick, children, disabled }) {
  return (
    <button type="button" style={controlStyle(false)} {...controlHover(false)} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

export default function LecteurFichier({ evidenceId, fichier }) {
  const { t, i18n } = useTranslation();
  const [encodage, setEncodage] = useState('auto');
  const [offset, setOffset] = useState(0);
  const [coupe, setCoupe] = useState(false);
  const [tranche, setTranche] = useState(null);
  const [erreur, setErreur] = useState('');
  const [saisie, setSaisie] = useState('');
  const [recherche, setRecherche] = useState(null);
  const [aller, setAller] = useState('');
  const [copie, setCopie] = useState('');
  const demande = useRef(0);

  useEffect(() => {
    const n = ++demande.current;
    setErreur('');
    evidenceAPI.fichierContenu(evidenceId, { ...designation(fichier), offset, encodage })
      .then(r => { if (n === demande.current) setTranche(r.data); })
      .catch(e => {
        if (n !== demande.current) return;
        setTranche(null);
        setErreur(e.response?.data?.error || t(`${K}.erreur_lecture`));
      });
    return () => { demande.current++; };
  }, [evidenceId, fichier, offset, encodage]);

  const fmt = n => Number(n).toLocaleString(i18n.language);
  const nom = fichier.chemin.slice(fichier.chemin.lastIndexOf('/') + 1);
  const dossier = fichier.chemin.includes('/') ? `${fichier.chemin.slice(0, fichier.chemin.lastIndexOf('/'))}/` : '';

  const detecte = !tranche ? { nom: '…', precision: '' }
    : tranche.encodage_detecte === 'binaire' ? { nom: t(`${K}.binaire`), precision: '' }
      : tranche.encodage_detecte === 'vide' ? { nom: '—', precision: '' }
        : { nom: nomEncodage(tranche.encodage_detecte), precision: tranche.deduit ? t(`${K}.deduit`) : '' };

  async function chercher(e) {
    e.preventDefault();
    const terme = saisie.trim();
    if (!terme) return;
    try {
      const r = await evidenceAPI.fichierRecherche(evidenceId, { ...designation(fichier), q: terme, encodage });
      setRecherche({ terme, resultats: r.data.resultats, tronque: r.data.tronque, erreur: '' });
    } catch (err) {
      setRecherche({ terme, resultats: [], tronque: false, erreur: err.response?.data?.error || t(`${K}.erreur_recherche`) });
    }
  }

  function allerA(e) {
    e.preventDefault();
    if (/^\d+$/.test(aller)) setOffset(Number(aller));
  }

  function copier() {
    Promise.resolve(navigator.clipboard?.writeText(fichier.chemin))
      .then(() => setCopie('ok'), () => setCopie('refus'));
  }

  const terme = recherche?.terme || '';

  return (
    <div className="fl-fic-l">
      <div className="fl-fic-l-tete">
        <div className="fl-fic-l-haut">
          <span className="fl-fic-l-nom">{nom}</span>
          <Action onClick={copier}>
            {copie === 'ok' ? t(`${K}.copie`) : copie === 'refus' ? t(`${K}.copie_refusee`) : t(`${K}.copier_chemin`)}
          </Action>
        </div>
        {dossier && <div className="fl-fic-l-dir">{dossier}</div>}
        <div className="fl-fic-l-meta">
          <span>{t(`${K}.octets`, { n: fmt(fichier.taille ?? tranche?.taille ?? 0) })}</span>
          {fichier.mtime && <span>{t(`${K}.modifie`, { date: fichier.mtime.replace('T', ' ').slice(0, 19) })}</span>}
          <span>{fichier.lu ? t(`${K}.lu_par`, { type: fichier.lu }) : t(`${K}.lu_par_aucun`)}</span>
        </div>
        {fichier.octets && <div className="fl-fic-l-octets">{t(`${K}.nom_non_utf8`, { octets: octetsDuNom(fichier.octets) })}</div>}
      </div>

      <div className="fl-fic-reglages">
        <div className="fl-fic-grp" role="group" aria-label={t(`${K}.encodage`)}>
          <span className="fl-fic-lbl">{t(`${K}.encodage`)}</span>
          {ENCODAGES.map(code => (
            <Segment key={code} actif={encodage === code} onClick={() => { setEncodage(code); setOffset(0); }}>
              {code === 'auto' ? t(`${K}.auto`, detecte) : nomEncodage(code)}
            </Segment>
          ))}
        </div>
        <div className="fl-fic-grp" role="group" aria-label={t(`${K}.lignes`)}>
          <span className="fl-fic-lbl">{t(`${K}.lignes`)}</span>
          <Segment actif={!coupe} onClick={() => setCoupe(false)}>{t(`${K}.entieres`)}</Segment>
          <Segment actif={coupe} onClick={() => setCoupe(true)}>{t(`${K}.coupees`)}</Segment>
        </div>
        <form className="fl-fic-chercher" role="search" onSubmit={chercher}>
          <input className="fl-fic-champ" type="search" value={saisie} onChange={e => setSaisie(e.target.value)}
            placeholder={t(`${K}.chercher_placeholder`)} aria-label={t(`${K}.chercher_placeholder`)} spellCheck={false} />
          <button type="submit" style={controlStyle(false)} {...controlHover(false)}>{t(`${K}.chercher`)}</button>
        </form>
      </div>

      {recherche && (
        <div className="fl-fic-resultats">
          {recherche.erreur ? <span>{recherche.erreur}</span>
            : recherche.resultats.length ? (
              <>
                <span>{t(`${K}.resultats`, { n: fmt(recherche.resultats.length), q: recherche.terme })}</span>
                {recherche.resultats.map(r => (
                  <Action key={r.offset} onClick={() => setOffset(r.offset)}>{t(`${K}.ligne_n`, { n: fmt(r.ligne) })}</Action>
                ))}
                {recherche.tronque && <span>{t(`${K}.resultats_tronques`)}</span>}
              </>
            ) : <span>{t(`${K}.aucun_resultat`, { q: recherche.terme })}</span>}
          <span className="fl-fic-esp" />
          <Action onClick={() => { setRecherche(null); setSaisie(''); }}>{t(`${K}.effacer`)}</Action>
        </div>
      )}

      <div className={`fl-fic-corps${coupe ? ' fl-fic-coupe' : ''}`} tabIndex={0} aria-label={nom}>
        {erreur && <Alert variant="danger" message={erreur} />}
        {!erreur && !tranche && <div className="fl-fic-muet">{t(`${K}.lecture`)}</div>}
        {!erreur && tranche?.encodage === 'vide' && <div className="fl-fic-muet">{t(`${K}.vide`)}</div>}
        {!erreur && tranche?.hexa !== undefined && (
          <table className="fl-fic-hexa">
            <tbody>
              {lignesHexa(tranche.hexa, tranche.offset).map(l => (
                <tr key={l.offset}><td className="fl-fic-no">{l.offset}</td><td className="fl-fic-hx">{l.hexa}</td><td>{l.ascii}</td></tr>
              ))}
            </tbody>
          </table>
        )}
        {!erreur && tranche?.texte !== undefined && tranche.encodage !== 'vide' && (
          <table className="fl-fic-texte">
            <tbody>
              {lignesTexte(tranche.texte, tranche.premiere_ligne).map((l, i) => (
                <tr key={i}>
                  <td className="fl-fic-no">{l.no ?? ''}</td>
                  <td className="fl-fic-co">
                    {morceaux(l.texte, terme).map((m, j) => (m.marque ? <mark key={j}>{m.texte}</mark> : <span key={j}>{m.texte}</span>))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="fl-fic-pied">
        {tranche && tranche.longueur > 0 && (
          <span>{t(`${K}.plage`, { de: fmt(tranche.offset), a: fmt(tranche.offset + tranche.longueur - 1), taille: fmt(tranche.taille) })}</span>
        )}
        {tranche?.offset > 0 && <Action onClick={() => setOffset(0)}>{t(`${K}.debut`)}</Action>}
        {tranche?.suivant != null && <Action onClick={() => setOffset(tranche.suivant)}>{t(`${K}.suite`)}</Action>}
        {tranche && tranche.taille > 0 && (
          <form className="fl-fic-aller" onSubmit={allerA}>
            <label htmlFor="fl-fic-aller">{t(`${K}.aller`)}</label>
            <input id="fl-fic-aller" className="fl-fic-champ" inputMode="numeric" value={aller} onChange={e => setAller(e.target.value)} placeholder="0" />
          </form>
        )}
        <span className="fl-fic-journal">{t(`${K}.journal`)}</span>
      </div>
    </div>
  );
}
