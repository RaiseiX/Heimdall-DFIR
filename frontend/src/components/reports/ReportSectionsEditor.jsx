import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Textarea } from '../ui';
import { bindTextareaToYText } from './collab/textareaBinding';
import { SECTIONS_RAPPORT, NOTE_ANALYSTE } from './reportWriting';

function Section({ doc, actif, cle, libelle, placeholder }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!doc || !ref.current) return undefined;
    return bindTextareaToYText(doc.getText(cle), ref.current);
  }, [doc, cle]);
  return (
    <label className="fl-redac-bloc">
      <span className="fl-redac-libelle">{libelle}</span>
      <Textarea ref={ref} data-section={cle} spellCheck={false} rows={4} placeholder={actif ? placeholder : undefined} disabled={!actif} />
    </label>
  );
}

export default function ReportSectionsEditor({ doc, etat }) {
  const { t } = useTranslation();
  const k = (cle) => t(`casedetail.redaction.${cle}`);
  const actif = Boolean(doc) && etat === 'synchro';
  return (
    <div className="fl-redac-liste-sections">
      {SECTIONS_RAPPORT.map((cle) => (
        <Section key={cle} doc={doc} actif={actif} cle={cle} libelle={k(`section_${cle}`)} placeholder={k('section_vide')} />
      ))}
      <Section doc={doc} actif={actif} cle={NOTE_ANALYSTE} libelle={k('note_analyste')} placeholder={k('note_analyste_ph')} />
    </div>
  );
}
