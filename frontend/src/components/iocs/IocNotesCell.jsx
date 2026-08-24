import { useState, useRef } from 'react';

// ─── Inline analyst-notes editor for an IOC row ──────────────────────────────
// Click the dashed cell to edit; Ctrl/Cmd+Enter or blur saves, Escape cancels.
export default function IocNotesCell({ value, onSave, onClose, width }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value || '');
  const [saving, setSaving] = useState(false);
  const cancelRef = useRef(false);

  const start = () => {
    setDraft(value || '');
    cancelRef.current = false;
    setEditing(true);
  };

  const save = async () => {
    if (cancelRef.current) { cancelRef.current = false; onClose?.(); return; }
    setEditing(false);
    const next = draft.trim();
    if (next === (value || '').trim()) { onClose?.(); return; }
    setSaving(true);
    try {
      await onSave(next);
    } finally {
      setSaving(false);
    }
  };

  if (editing) {
    return (
      <textarea
        autoFocus
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={save}
        onKeyDown={e => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) save();
          else if (e.key === 'Escape') { cancelRef.current = true; setEditing(false); onClose?.(); }
        }}
        rows={2}
        style={{ width: '100%', minHeight: 44, boxSizing: 'border-box', background: 'var(--fl-raised)', color: 'var(--fl-text)', border: '1px solid var(--fl-accent)', borderRadius: 6, padding: '5px 7px', fontFamily: 'var(--f-mono, monospace)', fontSize: 11, lineHeight: 1.4, resize: 'vertical', outline: 'none' }}
      />
    );
  }

  return (
    <button
      onClick={start}
      disabled={saving}
      title={value ? value : 'Cliquer pour ajouter une note'}
      style={{ display: 'block', width: width || '100%', textAlign: 'left', background: 'none', border: value ? '1px solid var(--fl-border)' : '1px dashed var(--fl-border2)', borderRadius: 6, padding: '5px 7px', cursor: 'pointer', minHeight: 32, color: value ? 'var(--fl-dim)' : 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, monospace)', lineHeight: 1.4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
    >
      {value || (saving ? '…' : '✎ ' + 'Ajouter une note')}
    </button>
  );
}
