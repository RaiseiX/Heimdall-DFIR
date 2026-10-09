import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, CornerDownRight, BookOpen, Link2 } from 'lucide-react';
import { notebookAPI } from '../../utils/api';
import { extraireSources } from '../../utils/notebookSource';
import { Button, Spinner, Alert, EmptyState, Select } from '../ui';
import { decouperEntrees, insererDansSection, SECTIONS_RAPPORT } from './reportWriting';

function Entree({ entree, doc, etat, k }) {
  const [cible, setCible] = useState(SECTIONS_RAPPORT[1]);
  const [insere, setInsere] = useState(null);
  const [echec, setEchec] = useState(false);
  const sources = useMemo(() => extraireSources(entree.texte), [entree.texte]);
  const titre = entree.titre || k('entree_sans_titre');
  const pret = Boolean(doc) && etat === 'synchro';
  const inserer = () => {
    if (insererDansSection(doc, cible, entree.texte)) {
      setInsere(cible);
      setEchec(false);
    } else {
      setInsere(null);
      setEchec(true);
    }
  };
  return (
    <div className="fl-redac-entree" data-entree={entree.id}>
      <div className="fl-redac-entete">
        <span className="fl-redac-entete-titre">{titre}</span>
        {sources.length > 0 && <span className="fl-redac-source"><Link2 size={11} aria-hidden="true" />{k('source_presente')}</span>}
      </div>
      <pre className="fl-redac-corps">{entree.texte}</pre>
      <div className="fl-redac-actions">
        <Select
          className="fl-select-sm"
          value={cible}
          onChange={(e) => { setCible(e.target.value); setInsere(null); setEchec(false); }}
          aria-label={k('section_destination', { titre })}
        >
          {SECTIONS_RAPPORT.map((cle) => <option key={cle} value={cle}>{k(`section_${cle}`)}</option>)}
        </Select>
        <Button size="sm" icon={CornerDownRight} onClick={inserer} disabled={!pret} ariaLabel={k('inserer_titre', { titre })}>{k('inserer')}</Button>
      </div>
      {insere && <span className="fl-redac-confirme" role="status">{k('insere', { section: k(`section_${insere}`) })}</span>}
      {echec && <span className="fl-redac-echec" role="status">{k('insertion_impossible')}</span>}
    </div>
  );
}

export default function NotebookSourcePane({ caseId, doc, etat }) {
  const { t } = useTranslation();
  const k = (cle, o) => t(`casedetail.redaction.${cle}`, o);
  const [contenu, setContenu] = useState(null);
  const [chargement, setChargement] = useState(false);
  const [erreur, setErreur] = useState(null);

  const charger = useCallback(async () => {
    if (!caseId) return;
    setChargement(true);
    setErreur(null);
    try {
      const r = await notebookAPI.get(caseId);
      setContenu(r.data?.content || '');
    } catch (e) {
      setErreur(e?.response?.data?.error || e?.message || String(e));
    } finally {
      setChargement(false);
    }
  }, [caseId]);

  useEffect(() => { charger(); }, [charger]);

  const entrees = useMemo(() => decouperEntrees(contenu), [contenu]);

  return (
    <section className="fl-redac-carnet" aria-label={k('carnet_titre')}>
      <div className="fl-redac-barre">
        <h4 className="fl-redac-titre"><BookOpen size={12} color="var(--fl-accent)" aria-hidden="true" />{k('carnet_titre')}</h4>
        <span className="fl-redac-espace" />
        <Button size="sm" variant="ghost" icon={RefreshCw} loading={chargement} onClick={charger}>{k('carnet_rafraichir')}</Button>
      </div>
      {erreur && <Alert message={k('carnet_erreur', { detail: erreur })} />}
      {chargement && contenu === null && <Spinner text={k('carnet_chargement')} />}
      {contenu !== null && entrees.length === 0 && <EmptyState icon={BookOpen} title={k('carnet_vide')} />}
      {entrees.length > 0 && (
        <div className="fl-redac-liste">
          {entrees.map((e) => <Entree key={`${e.id}:${e.texte.length}`} entree={e} doc={doc} etat={etat} k={k} />)}
        </div>
      )}
    </section>
  );
}
