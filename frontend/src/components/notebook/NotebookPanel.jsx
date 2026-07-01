import { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Save, Eye, EyeOff, BookOpen } from 'lucide-react';
import { notebookAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, sans-serif)';

// Lightweight markdown-to-html for preview (no external dep).
function mdToHtml(md) {
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // headings
    .replace(/^### (.+)$/gm, '<h3 style="margin:.8em 0 .3em;font-size:13px;color:var(--fl-text)">$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2 style="margin:.9em 0 .3em;font-size:14px;color:var(--fl-text)">$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1 style="margin:1em 0 .4em;font-size:16px;color:var(--fl-text)">$1</h1>')
    // bold / italic
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    // inline code
    .replace(/`([^`]+)`/g, '<code style="background:var(--fl-card);padding:1px 5px;border-radius:3px;font-family:'+MONO+';font-size:10.5px">$1</code>')
    // MITRE technique links (T1234 / T1234.001)
    .replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<a href="https://attack.mitre.org/techniques/$1" target="_blank" rel="noreferrer" style="color:var(--fl-accent);text-decoration:none;font-family:'+MONO+';font-size:10.5px">$1</a>')
    // bullet lists
    .replace(/^[-*] (.+)$/gm, '<li style="margin:.15em 0">$1</li>')
    .replace(/(<li[\s\S]*?<\/li>\n?)+/g, m => '<ul style="margin:.4em 0 .4em 1.2em;padding:0">'+m+'</ul>')
    // paragraphs (blank-line separated)
    .replace(/\n{2,}/g, '</p><p style="margin:.5em 0">')
    .replace(/^(.+)$/gm, s => s.startsWith('<') ? s : s);
}

export default function NotebookPanel({ caseId }) {
  const { t } = useTranslation();
  const [content, setContent]   = useState('');
  const [preview, setPreview]   = useState(false);
  const [saving, setSaving]     = useState(false);
  const [savedAt, setSavedAt]   = useState(null);
  const [updatedBy, setUpdatedBy] = useState(null);
  const [dirty, setDirty]       = useState(false);
  const timerRef = useRef(null);

  useEffect(() => {
    if (!caseId) return;
    notebookAPI.get(caseId)
      .then(r => {
        setContent(r.data?.content || '');
        setSavedAt(r.data?.updated_at || null);
        setUpdatedBy(r.data?.updated_by_name || null);
      })
      .catch(() => {});
  }, [caseId]);

  const save = useCallback(async (c) => {
    if (!caseId) return;
    setSaving(true);
    try {
      const r = await notebookAPI.save(caseId, c ?? content);
      setSavedAt(r.data?.updated_at || new Date().toISOString());
      setDirty(false);
    } catch (_e) {}
    finally { setSaving(false); }
  }, [caseId, content]);

  function handleChange(v) {
    setContent(v);
    setDirty(true);
    // Debounced auto-save after 3 s of inactivity.
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => save(v), 3000);
  }

  useEffect(() => () => clearTimeout(timerRef.current), []);

  const charCount = content.length;

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 12 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <BookOpen size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
        <span style={{ fontSize: 11, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)', fontWeight: 700 }}>
          {t('notebook.title')}
        </span>
        <span style={{ flex: 1 }} />
        {savedAt && (
          <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            {dirty ? t('notebook.unsaved') : t('notebook.saved_at', { time: new Date(savedAt).toLocaleTimeString() })}
            {updatedBy && !dirty && ` · ${updatedBy}`}
          </span>
        )}
        <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-subtle)' }}>{charCount.toLocaleString()} {t('notebook.chars')}</span>
        <button onClick={() => setPreview(v => !v)}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: preview ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent', border: `1px solid ${preview ? 'color-mix(in srgb, var(--fl-accent) 35%, transparent)' : 'var(--fl-border)'}`, borderRadius: 5, cursor: 'pointer', padding: '4px 9px', color: preview ? 'var(--fl-accent)' : 'var(--fl-muted)', fontSize: 10, fontFamily: MONO }}>
          {preview ? <EyeOff size={11} /> : <Eye size={11} />}
          {preview ? t('notebook.edit') : t('notebook.preview')}
        </button>
        <button onClick={() => save()} disabled={saving || !dirty}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: dirty ? 'color-mix(in srgb, var(--fl-ok) 10%, transparent)' : 'transparent', border: `1px solid ${dirty ? 'color-mix(in srgb, var(--fl-ok) 35%, transparent)' : 'var(--fl-border)'}`, borderRadius: 5, cursor: dirty ? 'pointer' : 'default', padding: '4px 9px', color: dirty ? 'var(--fl-ok)' : 'var(--fl-subtle)', fontSize: 10, fontFamily: MONO, opacity: saving ? 0.6 : 1 }}>
          <Save size={11} />
          {saving ? t('notebook.saving') : t('notebook.save')}
        </button>
      </div>

      {/* Hint */}
      {!content && !preview && (
        <p style={{ fontSize: 11, fontFamily: UI, color: 'var(--fl-subtle)', margin: 0 }}>
          {t('notebook.hint')}
        </p>
      )}

      {/* Editor / Preview */}
      {preview ? (
        <div
          style={{ minHeight: 400, padding: '14px 16px', border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-bg)', fontSize: 12.5, fontFamily: UI, color: 'var(--fl-text)', lineHeight: 1.65, overflowY: 'auto' }}
          dangerouslySetInnerHTML={{ __html: '<p style="margin:.5em 0">' + mdToHtml(content) + '</p>' }}
        />
      ) : (
        <textarea
          value={content}
          onChange={e => handleChange(e.target.value)}
          spellCheck={false}
          placeholder={t('notebook.placeholder')}
          style={{
            minHeight: 420, resize: 'vertical', width: '100%', boxSizing: 'border-box',
            padding: '14px 16px', border: '1px solid var(--fl-border)', borderRadius: 8,
            background: 'var(--fl-bg)', color: 'var(--fl-text)',
            fontFamily: MONO, fontSize: 12, lineHeight: 1.7,
            outline: 'none', caretColor: 'var(--fl-accent)',
          }}
        />
      )}
    </div>
  );
}
