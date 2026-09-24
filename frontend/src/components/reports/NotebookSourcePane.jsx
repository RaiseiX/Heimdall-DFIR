import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, CornerDownRight, BookOpen, Link2 } from 'lucide-react';
import { notebookAPI } from '../../utils/api';
import { extraireSources } from '../../utils/notebookSource';
import { Button, Spinner, Alert, EmptyState } from '../ui';
import { decouperEntrees, insererDansSection, SECTIONS_RAPPORT } from './reportWriting';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  racine: { display: 'flex', flexDirection: 'column', gap: 8, minHeight: 0 },
  barre: { display: 'flex', alignItems: 'center', gap: 8 },
  titre: { display: 'flex', alignItems: 'center', gap: 6, margin: 0, fontFamily: MONO, fontSize: 11, fontWeight: 700, color: 'var(--fl-text)' },
  liste: { display: 'grid', gap: 8, overflowY: 'auto', maxHeight: 520, paddingRight: 4 },
  entree: { border: '1px solid var(--fl-border)', borderRadius: 4, padding: '8px 10px', background: 'var(--fl-bg)', display: 'grid', gap: 6 },
  entete: { display: 'flex', alignItems: 'center', gap: 6, fontFamily: MONO, fontSize: 11, fontWeight: 600, color: 'var(--fl-text)' },
  source: { display: 'inline-flex', alignItems: 'center', gap: 3, fontFamily: MONO, fontSize: 9.5, color: 'var(--fl-accent)' },
  corps: { margin: 0, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-dim)', whiteSpace: 'pre-wrap', maxHeight: 96, overflow: 'hidden' },
  actions: { display: 'flex', alignItems: 'center', gap: 6 },
  choix: { flex: 1, minWidth: 0, background: 'var(--fl-panel)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 4, padding: '3px 6px', fontFamily: MONO, fontSize: 10.5 },
  confirme: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-ok)' },
};

function Entree({ entree, doc, k }) {
  const [cible, setCible] = useState(SECTIONS_RAPPORT[1]);
  const [insere, setInsere] = useState(null);
  const sources = useMemo(() => extraireSources(entree.texte), [entree.texte]);
  const inserer = () => {
    if (insererDansSection(doc, cible, entree.texte)) setInsere(cible);
  };
  return (
    <div style={S.entree} data-entree={entree.id}>
      <div style={S.entete}>
        <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entree.titre || k('entree_sans_titre')}</span>
        {sources.length > 0 && <span style={S.source}><Link2 size={10} aria-hidden="true" />{k('source_presente')}</span>}
      </div>
      <pre style={S.corps}>{entree.texte}</pre>
      <div style={S.actions}>
        <select value={cible} onChange={(e) => { setCible(e.target.value); setInsere(null); }} style={S.choix} aria-label={k('inserer_dans')}>
          {SECTIONS_RAPPORT.map((cle) => <option key={cle} value={cle}>{k(`section_${cle}`)}</option>)}
        </select>
        <Button size="sm" icon={CornerDownRight} onClick={inserer} disabled={!doc}>{k('inserer')}</Button>
      </div>
      {insere && <span style={S.confirme} role="status">{k('insere', { section: k(`section_${insere}`) })}</span>}
    </div>
  );
}

export default function NotebookSourcePane({ caseId, doc }) {
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
    <section style={S.racine} aria-label={k('carnet_titre')}>
      <div style={S.barre}>
        <h4 style={S.titre}><BookOpen size={12} color="var(--fl-accent)" aria-hidden="true" />{k('carnet_titre')}</h4>
        <span style={{ flex: 1 }} />
        <Button size="sm" variant="ghost" icon={RefreshCw} loading={chargement} onClick={charger}>{k('carnet_rafraichir')}</Button>
      </div>
      {erreur && <Alert message={erreur} />}
      {chargement && contenu === null && <Spinner text={k('carnet_chargement')} />}
      {contenu !== null && entrees.length === 0 && <EmptyState icon={BookOpen} title={k('carnet_vide')} />}
      {entrees.length > 0 && (
        <div style={S.liste}>
          {entrees.map((e) => <Entree key={`${e.id}:${e.texte.length}`} entree={e} doc={doc} k={k} />)}
        </div>
      )}
    </section>
  );
}
