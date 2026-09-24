import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { lignesDuDepliant, compteDesStatuts } from './parsingView';
import { fmtOctets } from './octets';

const ORDRE = ['parsing', 'error', 'done', 'skipped', 'queued'];
const CLASSE_COMPTE = {
  parsing: 'fl-dep-c-cours', error: 'fl-dep-c-rate', done: 'fl-dep-c-fait', skipped: 'fl-dep-c-att', queued: 'fl-dep-c-att',
};
const ETATS = {
  queued: 'collection.pm_queued', parsing: 'collection.pm_parsing', done: 'collection.pm_done',
  skipped: 'collection.pm_skipped', error: 'collection.pm_error',
};

export default function ParseursDepliant({ parseurs, etats, fichiers, onChoisir }) {
  const { t, i18n } = useTranslation();
  const [ouvert, setOuvert] = useState(false);
  if (!parseurs || parseurs.length === 0) return null;

  const compte = compteDesStatuts(etats);
  const nombre = v => (v == null ? '—' : Number(v).toLocaleString(i18n.language));
  const presents = ORDRE.filter(s => compte[s]);

  return (
    <div className="fl-dep">
      <button type="button" style={controlStyle(false)} {...controlHover(false)}
        aria-expanded={ouvert} aria-controls="fl-dep-liste" onClick={() => setOuvert(o => !o)}>
        <span className="fl-dep-chev" aria-hidden="true">›</span>
        {presents.map((s, i) => (
          <span key={s}>
            {i > 0 && <span className="fl-dep-pt">·</span>}
            <span className={CLASSE_COMPTE[s]}>{t(`collection.import.depliant.${s}`, { count: compte[s] })}</span>
          </span>
        ))}
      </button>
      {ouvert && (
        <div className="fl-dep-liste" id="fl-dep-liste" role="table" aria-label={t('collection.import.depliant.titre')}>
          <div className="fl-dep-lg fl-dep-tete" role="row">
            <span role="columnheader">{t('collection.import.depliant.col_parseur')}</span>
            <span role="columnheader">{t('collection.import.depliant.col_etat')}</span>
            <span role="columnheader" className="fl-dep-n fl-dep-fich">{t('collection.import.depliant.col_fichiers')}</span>
            <span role="columnheader" className="fl-dep-n fl-dep-vol">{t('collection.import.depliant.col_volume')}</span>
            <span role="columnheader" className="fl-dep-n">{t('collection.import.depliant.col_lignes')}</span>
          </div>
          {lignesDuDepliant(parseurs, etats, fichiers).map(l => (
            <div key={l.cle} role="row" className={`fl-dep-lg fl-dep-${l.statut}`}>
              <span role="cell" className="fl-dep-cell">
                <button type="button" className="fl-dep-nom" onClick={() => onChoisir?.(l.cle)}
                  aria-describedby="fl-dep-aide">
                  {l.nom}<small>{l.cle}</small>
                </button>
              </span>
              <span role="cell" className="fl-dep-etat">{t(ETATS[l.statut] || ETATS.queued)}</span>
              <span role="cell" className="fl-dep-n fl-dep-fich">{nombre(l.fichiers)}</span>
              <span role="cell" className="fl-dep-n fl-dep-vol">{l.octets == null ? '—' : fmtOctets(l.octets)}</span>
              <span role="cell" className="fl-dep-n fl-dep-lignes">{nombre(l.lignes)}</span>
            </div>
          ))}
          <span id="fl-dep-aide" hidden>{t('collection.import.depliant.aide_nom')}</span>
        </div>
      )}
    </div>
  );
}
