import { useTranslation } from 'react-i18next';
import { Sparkles } from 'lucide-react';
import { Button, Alert, Spinner } from '../ui';
import NotebookSourcePane from './NotebookSourcePane';
import ReportSectionsEditor from './ReportSectionsEditor';

export default function ReportWritingPane({
  caseId, doc, etat = 'connexion', aiRaison = null, aiLoading, aiError, onPrefill, conflits = [], onRemplacer, onIgnorer,
}) {
  const { t } = useTranslation();
  const k = (cle, o) => t(`casedetail.redaction.${cle}`, o);
  const synchro = etat === 'synchro';
  return (
    <div className="fl-redac">
      <div className="fl-redac-grille">
        <div className="fl-redac-colonne">
          <NotebookSourcePane caseId={caseId} doc={doc} etat={etat} />
        </div>
        <div className="fl-redac-colonne">
          <div className="fl-redac-barre fl-redac-barre-editeur">
            <h4 className="fl-redac-titre">{k('titre')}</h4>
            {etat === 'synchro' && <span className="fl-redac-aide">{k('aide')}</span>}
            <span className="fl-redac-espace" />
            {aiRaison && <span className="fl-redac-raison">{k(`raison_ia_${aiRaison}`)}</span>}
            <Button
              size="sm"
              variant="ghost"
              icon={Sparkles}
              loading={aiLoading}
              onClick={onPrefill}
              disabled={Boolean(aiRaison) || !synchro}
            >
              {k('prefill_ia')}
            </Button>
          </div>
          {etat === 'connexion' && (
            <div className="fl-redac-attente"><Spinner text={k('connexion_brouillon')} /></div>
          )}
          {etat === 'hors_ligne' && <div className="fl-redac-alerte"><Alert variant="warn" message={k('hors_ligne')} /></div>}
          {aiError && <div className="fl-redac-alerte"><Alert message={aiError} /></div>}
          {conflits.length > 0 && (
            <div className="fl-redac-alerte">
              <Alert
                variant="warn"
                message={(
                  <>
                    {k('prefill_conflit', { count: conflits.length, sections: conflits.map((c) => k(`section_${c}`)).join(', ') })}
                    {' '}
                    <Button size="sm" variant="ghost" onClick={onRemplacer} disabled={!synchro}>{k('prefill_remplacer')}</Button>
                    <Button size="sm" variant="ghost" onClick={onIgnorer} disabled={!synchro}>{k('prefill_garder')}</Button>
                  </>
                )}
              />
            </div>
          )}
          <ReportSectionsEditor doc={doc} etat={etat} />
        </div>
      </div>
    </div>
  );
}
