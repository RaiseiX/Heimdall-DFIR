import { useState, useEffect, useRef } from 'react';
import * as Y from 'yjs';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff, BookOpen } from 'lucide-react';
import { createCollabProvider } from '../reports/collab/reportCollabProvider';
import { bindTextareaToYText } from '../reports/collab/textareaBinding';
import { mdToHtml } from './notebookMarkdown';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, sans-serif)';

const TON = {
  connexion: 'var(--fl-muted)',
  synchro: 'var(--fl-ok)',
  hors_ligne: 'var(--fl-warn)',
  refuse: 'var(--fl-danger)',
  erreur: 'var(--fl-danger)',
};

export default function NotebookPanel({ caseId, socket }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [contenu, setContenu] = useState('');
  const [preview, setPreview] = useState(false);
  const [etat, setEtat] = useState('connexion');
  const [synchronise, setSynchronise] = useState(false);
  const texteRef = useRef(null);
  const zoneRef = useRef(null);

  useEffect(() => {
    if (!socket || !caseId) return undefined;
    const doc = new Y.Doc();
    const texte = doc.getText('carnet');
    texteRef.current = texte;
    setContenu('');
    setSynchronise(false);
    setEtat(socket.connected === false ? 'hors_ligne' : 'connexion');
    const surChangement = () => setContenu(texte.toString());
    texte.observe(surChangement);
    const provider = createCollabProvider(socket, caseId, doc, 'notebook', {
      onState: () => { setSynchronise(true); setEtat('synchro'); },
    });
    const surDeconnexion = () => setEtat('hors_ligne');
    const surRefus = (m) => { if (m?.caseId === caseId) setEtat('refuse'); };
    const surErreur = (m) => { if (m?.caseId === caseId) setEtat('erreur'); };
    socket.on('disconnect', surDeconnexion);
    socket.on('notebook:denied', surRefus);
    socket.on('notebook:error', surErreur);
    return () => {
      socket.off('disconnect', surDeconnexion);
      socket.off('notebook:denied', surRefus);
      socket.off('notebook:error', surErreur);
      provider.destroy();
      texte.unobserve(surChangement);
      doc.destroy();
      texteRef.current = null;
    };
  }, [socket, caseId]);

  useEffect(() => {
    const el = zoneRef.current;
    const texte = texteRef.current;
    if (preview || !synchronise || !el || !texte) return undefined;
    return bindTextareaToYText(texte, el);
  }, [preview, synchronise]);

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 12 }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <BookOpen size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
        <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-dim)', fontWeight: 700 }}>
          {t('notebook.title')}
        </span>
        <span style={{ flex: 1 }} />
        <span role="status" data-etat={etat} style={{ fontSize: 10, fontFamily: MONO, color: TON[etat] }}>
          {t(`notebook.sync_${etat}`)}
        </span>
        <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-subtle)' }}>{contenu.length.toLocaleString()} {t('notebook.chars')}</span>
        <button onClick={() => setPreview(v => !v)}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: preview ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent', border: `1px solid ${preview ? 'color-mix(in srgb, var(--fl-accent) 35%, transparent)' : 'var(--fl-border)'}`, borderRadius: 5, cursor: 'pointer', padding: '4px 9px', color: preview ? 'var(--fl-accent)' : 'var(--fl-muted)', fontSize: 10, fontFamily: MONO }}>
          {preview ? <EyeOff size={11} /> : <Eye size={11} />}
          {preview ? t('notebook.edit') : t('notebook.preview')}
        </button>
      </div>

      {!contenu && !preview && (
        <p style={{ fontSize: 11, fontFamily: UI, color: 'var(--fl-subtle)', margin: 0 }}>
          {t('notebook.hint')}
        </p>
      )}

      {preview ? (
        <div
          onClick={(e) => {
            const lien = e.target.closest?.('a[data-source]');
            if (!lien) return;
            e.preventDefault();
            navigate(lien.getAttribute('href'));
          }}
          style={{ minHeight: 400, padding: '14px 16px', border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-bg)', fontSize: 12.5, fontFamily: UI, color: 'var(--fl-text)', lineHeight: 1.65, overflowY: 'auto' }}
          dangerouslySetInnerHTML={{ __html: '<p style="margin:.5em 0">' + mdToHtml(contenu) + '</p>' }}
        />
      ) : (
        <textarea
          ref={zoneRef}
          readOnly={!synchronise}
          spellCheck={false}
          aria-label={t('notebook.title')}
          placeholder={t('notebook.placeholder')}
          style={{
            minHeight: 420, resize: 'vertical', width: '100%', boxSizing: 'border-box',
            padding: '14px 16px', border: '1px solid var(--fl-border)', borderRadius: 8,
            background: 'var(--fl-bg)', color: 'var(--fl-text)',
            fontFamily: MONO, fontSize: 12, lineHeight: 1.7,
            outline: 'none', caretColor: 'var(--fl-accent)',
            opacity: synchronise ? 1 : 0.6,
          }}
        />
      )}
    </div>
  );
}
