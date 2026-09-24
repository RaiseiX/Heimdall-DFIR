import { useTranslation } from 'react-i18next';
import { Sparkles } from 'lucide-react';
import { Button, Alert } from '../ui';
import NotebookSourcePane from './NotebookSourcePane';
import ReportSectionsEditor from './ReportSectionsEditor';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  racine: { display: 'grid', gap: 10 },
  grille: { display: 'grid', gridTemplateColumns: 'minmax(260px, 2fr) minmax(0, 3fr)', gap: 14, alignItems: 'start' },
  colonne: { minWidth: 0 },
  barre: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
  titre: { margin: 0, fontFamily: MONO, fontSize: 11, fontWeight: 700, color: 'var(--fl-text)' },
  aide: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-subtle)' },
};

export default function ReportWritingPane({
  caseId, doc, aiEnabled, aiLoading, aiError, onPrefill, conflits = [], onRemplacer, onIgnorer,
}) {
  const { t } = useTranslation();
  const k = (cle, o) => t(`casedetail.redaction.${cle}`, o);
  return (
    <div style={S.racine}>
      <div style={S.grille}>
        <div style={S.colonne}>
          <NotebookSourcePane caseId={caseId} doc={doc} />
        </div>
        <div style={S.colonne}>
          <div style={{ ...S.barre, marginBottom: 8 }}>
            <h4 style={S.titre}>{k('titre')}</h4>
            <span style={S.aide}>{k('aide')}</span>
            <span style={{ flex: 1 }} />
            {aiEnabled && (
              <Button size="sm" variant="ghost" icon={Sparkles} loading={aiLoading} onClick={onPrefill}>{k('prefill_ia')}</Button>
            )}
          </div>
          {aiError && <Alert message={aiError} style={{ marginBottom: 8 }} />}
          {conflits.length > 0 && (
            <Alert
              variant="warn"
              style={{ marginBottom: 8 }}
              message={(
                <>
                  {k('prefill_conflit', { count: conflits.length, sections: conflits.map((c) => k(`section_${c}`)).join(', ') })}
                  {' '}
                  <Button size="sm" variant="ghost" onClick={onRemplacer}>{k('prefill_remplacer')}</Button>
                  <Button size="sm" variant="ghost" onClick={onIgnorer}>{k('prefill_garder')}</Button>
                </>
              )}
            />
          )}
          <ReportSectionsEditor doc={doc} />
        </div>
      </div>
    </div>
  );
}
