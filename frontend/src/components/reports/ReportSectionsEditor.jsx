import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { bindTextareaToYText } from './collab/textareaBinding';
import { SECTIONS_RAPPORT, NOTE_ANALYSTE } from './reportWriting';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  liste: { display: 'grid', gap: 12 },
  bloc: { display: 'grid', gap: 4 },
  libelle: { fontFamily: MONO, fontSize: 10, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--fl-dim)' },
  zone: {
    width: '100%', boxSizing: 'border-box', resize: 'vertical', minHeight: 72,
    background: 'var(--fl-bg)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 4,
    padding: '8px 10px', fontFamily: MONO, fontSize: 11.5, lineHeight: 1.6, outline: 'none',
  },
};

function Section({ doc, cle, libelle, placeholder }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!doc || !ref.current) return undefined;
    return bindTextareaToYText(doc.getText(cle), ref.current);
  }, [doc, cle]);
  return (
    <label style={S.bloc}>
      <span style={S.libelle}>{libelle}</span>
      <textarea ref={ref} data-section={cle} spellCheck={false} rows={4} placeholder={placeholder} style={S.zone} disabled={!doc} />
    </label>
  );
}

export default function ReportSectionsEditor({ doc }) {
  const { t } = useTranslation();
  const k = (cle) => t(`casedetail.redaction.${cle}`);
  return (
    <div style={S.liste}>
      {SECTIONS_RAPPORT.map((cle) => (
        <Section key={cle} doc={doc} cle={cle} libelle={k(`section_${cle}`)} placeholder={k('section_vide')} />
      ))}
      <Section doc={doc} cle={NOTE_ANALYSTE} libelle={k('note_analyste')} placeholder={k('note_analyste_ph')} />
    </div>
  );
}
