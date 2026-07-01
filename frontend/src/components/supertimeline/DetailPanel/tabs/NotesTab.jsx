import { useState, useEffect, useRef } from 'react';
import { Send, Pencil, Trash2 } from 'lucide-react';
import { artifactsAPI } from '../../../../utils/api';
import { fmtLocal } from '../../../../utils/formatters';
import { computeRef } from '../../utils/timelineUtils';
import { useTimelineStore } from '../../store/useTimelineStore';

export default function NotesTab({ record: r }) {
  const { caseId, setNotedRef } = useTimelineStore();
  const [notes, setNotes]       = useState([]);
  const [noteText, setNoteText] = useState('');
  const [saving, setSaving]     = useState(false);
  const [editId, setEditId]     = useState(null);
  const [editText, setEditText] = useState('');
  const inputRef = useRef(null);

  const ref = r ? computeRef(r) : null;

  useEffect(() => {
    if (!caseId || !ref) return;
    artifactsAPI.getNotes(caseId, ref)
      .then(res => setNotes(res.data?.notes ?? []))
      .catch(() => setNotes([]));
  }, [caseId, ref]);

  async function submit() {
    if (!noteText.trim() || !ref || !caseId) return;
    setSaving(true);
    try {
      await artifactsAPI.createNote(caseId, ref, noteText.trim());
      setNoteText('');
      const res = await artifactsAPI.getNotes(caseId, ref);
      const loaded = res.data?.notes ?? [];
      setNotes(loaded);
      setNotedRef(ref, loaded.length > 0); // C6: update grid indicator
    } catch {} finally { setSaving(false); }
  }

  async function saveEdit(noteId) {
    if (!editText.trim() || !ref || !caseId) return;
    try {
      await artifactsAPI.updateNote(caseId, ref, noteId, editText.trim());
      setEditId(null);
      const res = await artifactsAPI.getNotes(caseId, ref);
      setNotes(res.data?.notes ?? []);
    } catch {}
  }

  async function deleteNote(noteId) {
    if (!ref || !caseId) return;
    try {
      await artifactsAPI.deleteNote(caseId, ref, noteId);
      const res = await artifactsAPI.getNotes(caseId, ref);
      const loaded = res.data?.notes ?? [];
      setNotes(loaded);
      setNotedRef(ref, loaded.length > 0); // C6: update grid indicator
    } catch {}
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
        {notes.length === 0 ? (
          <div style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, textAlign: 'center', marginTop: 24 }}>
            No notes yet — add one below
          </div>
        ) : notes.map(n => (
          <div key={n.id} style={{ borderRadius: 6, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', padding: '8px 10px' }}>
            {editId === n.id ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <textarea value={editText} onChange={e => setEditText(e.target.value)}
                  style={{ width: '100%', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: '6px 8px', resize: 'vertical', minHeight: 60, outline: 'none', boxSizing: 'border-box' }} />
                <div style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => saveEdit(n.id)} style={{ padding: '3px 10px', borderRadius: 4, background: 'rgba(77,130,192,0.12)', border: '1px solid rgba(77,130,192,0.3)', color: 'var(--fl-accent)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}>Save</button>
                  <button onClick={() => setEditId(null)} style={{ padding: '3px 10px', borderRadius: 4, background: 'none', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}>Cancel</button>
                </div>
              </div>
            ) : (
              <>
                <div style={{ fontSize: 11, color: 'var(--fl-text)', lineHeight: 1.5, wordBreak: 'break-word', marginBottom: 6 }}>{n.note}</div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    {n.author_name || n.author_username} · {fmtLocal(n.created_at)}
                    {n.updated_at !== n.created_at && ' (edited)'}
                  </span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button onClick={() => { setEditId(n.id); setEditText(n.note); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', display: 'flex' }}><Pencil size={10} /></button>
                    <button onClick={() => deleteNote(n.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-danger)', display: 'flex' }}><Trash2 size={10} /></button>
                  </div>
                </div>
              </>
            )}
          </div>
        ))}
      </div>
      <div style={{ flexShrink: 0, padding: '8px 12px', borderTop: '1px solid var(--fl-border)', display: 'flex', gap: 8 }}>
        <textarea ref={inputRef} value={noteText} onChange={e => setNoteText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) submit(); }}
          placeholder="Add a note… (Ctrl+Enter to send)"
          style={{ flex: 1, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: '6px 8px', resize: 'none', height: 52, outline: 'none' }} />
        <button onClick={submit} disabled={saving || !noteText.trim()} style={{
          padding: '0 12px', borderRadius: 4,
          background: noteText.trim() ? 'rgba(77,130,192,0.12)' : 'var(--fl-bg)',
          border: `1px solid ${noteText.trim() ? 'rgba(77,130,192,0.3)' : 'var(--fl-border)'}`,
          color: noteText.trim() ? 'var(--fl-accent)' : 'var(--fl-muted)',
          cursor: noteText.trim() ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        }}>
          <Send size={11} /> Send
        </button>
      </div>
    </div>
  );
}
