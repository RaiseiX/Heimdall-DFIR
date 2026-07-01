import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Pencil, Trash2, Crosshair, X, RefreshCw, FileText, Sparkles, ClipboardCopy, Check, ArrowRight } from 'lucide-react';
import { bookmarksAPI, reportsAPI } from '../../utils/api';
import { fmtLocal } from '../../utils/formatters';
import StructuredNoteEditor from './StructuredNoteEditor';

const TACTIC_COLOR = {
  'Reconnaissance': 'var(--fl-dim)', 'Resource Development': 'var(--fl-dim)',
  'Initial Access': 'var(--fl-warn)', 'Execution': 'var(--fl-danger)',
  'Persistence': 'var(--fl-pink)', 'Privilege Escalation': 'var(--fl-purple)',
  'Defense Evasion': 'var(--fl-accent)', 'Credential Access': 'var(--fl-danger)',
  'Discovery': 'var(--fl-gold)', 'Lateral Movement': 'var(--fl-warn)',
  'Collection': 'var(--fl-ok)', 'Command and Control': 'var(--fl-danger)',
  'Exfiltration': 'var(--fl-danger)', 'Impact': 'var(--fl-danger)',
};

const CONF_COLOR = { high: 'var(--fl-ok)', medium: 'var(--fl-gold)', low: 'var(--fl-subtle)' };

export default function FindingsPanel({ caseId, onChange }) {
  const { t } = useTranslation();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading]   = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId]     = useState(null);
  const [narrative, setNarrative]   = useState(null);
  const [narLoading, setNarLoading] = useState(false);
  const [narCopied, setNarCopied]   = useState(false);

  const load = useCallback(() => {
    if (!caseId) return;
    setLoading(true);
    bookmarksAPI.list(caseId)
      .then(res => setFindings((res.data || []).filter(b => b.source !== 'mitre')))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const titleById = new Map(findings.map(f => [f.id, f.title]));

  async function handleCreate(form) {
    await bookmarksAPI.create(caseId, form);
    setShowForm(false); load(); onChange?.();
  }
  async function handleUpdate(form) {
    await bookmarksAPI.update(caseId, editId, form);
    setEditId(null); load(); onChange?.();
  }
  async function remove(id) {
    try { await bookmarksAPI.remove(caseId, id); load(); onChange?.(); } catch { /* noop */ }
  }

  async function generateNarrative() {
    if (narLoading || !findings.length) return;
    setNarLoading(true); setNarrative(null);
    try {
      const r = await reportsAPI.bookmarkNarrative(caseId);
      setNarrative(r.data?.narrative || '');
    } catch (e) {
      setNarrative('Erreur : ' + (e.response?.data?.error || e.message));
    } finally { setNarLoading(false); }
  }

  function copyNarrative() {
    if (!narrative) return;
    navigator.clipboard.writeText(narrative).then(() => {
      setNarCopied(true); setTimeout(() => setNarCopied(false), 2000);
    });
  }

  function exportCSV() {
    const cols = ['Timestamp', 'Title', 'Fact', 'Significance', 'Confidence', 'Tactic', 'Technique', 'Author'];
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = findings.map(b => [
      b.event_timestamp ? fmtLocal(b.event_timestamp) : '', b.title, b.description,
      b.significance, b.confidence, b.mitre_tactic, b.mitre_technique, b.author_name || b.username,
    ].map(esc).join(','));
    const csv = '﻿' + cols.map(esc).join(',') + '\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `findings_${caseId}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click(); URL.revokeObjectURL(url);
  }

  const btn = {
    display: 'flex', alignItems: 'center', gap: 4, background: 'none',
    border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer',
    padding: '3px 8px', color: 'var(--fl-subtle)', fontSize: 10,
    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Crosshair size={13} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {t('investigation.findings_title')} ({findings.length})
          </span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button onClick={load} style={{ ...btn, padding: '5px 9px' }}><RefreshCw size={11} /></button>
          {findings.length > 0 && <button onClick={exportCSV} style={btn}><FileText size={10} /> CSV</button>}
          {findings.length > 0 && (
            <button onClick={generateNarrative} disabled={narLoading} style={{ ...btn, color: 'var(--fl-purple)', borderColor: 'color-mix(in srgb, var(--fl-purple) 35%, transparent)', opacity: narLoading ? 0.6 : 1 }}>
              <Sparkles size={10} style={{ animation: narLoading ? 'fl-spin 1.2s linear infinite' : 'none' }} />
              {narLoading ? t('bookmark.narrative_generating') : t('bookmark.narrative_btn')}
            </button>
          )}
          <button onClick={() => { setShowForm(v => !v); setEditId(null); }} style={{ ...btn, color: 'var(--fl-accent)', borderColor: '#2a4a6a' }}>
            {showForm ? <X size={11} /> : <Plus size={11} />} {showForm ? t('common.cancel') : t('bookmark.new')}
          </button>
        </div>
      </div>

      {showForm && (
        <StructuredNoteEditor findings={findings} onSave={handleCreate} onCancel={() => setShowForm(false)} />
      )}

      {narrative !== null && (
        <div style={{ border: '1px solid color-mix(in srgb, var(--fl-purple) 25%, transparent)', borderRadius: 8, background: 'color-mix(in srgb, var(--fl-purple) 5%, var(--fl-bg))', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-purple)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              <Sparkles size={9} style={{ marginRight: 4, verticalAlign: 'middle' }} />{t('bookmark.narrative_title')}
            </span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button onClick={copyNarrative} style={{ ...btn, color: narCopied ? 'var(--fl-ok)' : 'var(--fl-subtle)' }}>
                {narCopied ? <Check size={10} /> : <ClipboardCopy size={10} />} {narCopied ? t('common.copied') : t('common.copy')}
              </button>
              <button onClick={() => setNarrative(null)} style={{ ...btn, padding: '3px 7px' }}><X size={10} /></button>
            </div>
          </div>
          <pre style={{ margin: 0, fontSize: 11, lineHeight: 1.6, color: 'var(--fl-text)', fontFamily: 'var(--f-ui, sans-serif)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{narrative}</pre>
        </div>
      )}

      {loading && <div style={{ textAlign: 'center', color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: 16 }}>{t('common.loading')}</div>}

      {!loading && findings.length === 0 && !showForm && (
        <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: '24px 16px', border: '1px dashed var(--fl-sep)', borderRadius: 8 }}>
          {t('bookmark.empty')}
        </div>
      )}

      {findings.map(b => {
        const tc = TACTIC_COLOR[b.mitre_tactic] || 'var(--fl-dim)';
        if (editId === b.id) {
          return <StructuredNoteEditor key={b.id} initial={b} findings={findings} onSave={handleUpdate} onCancel={() => setEditId(null)} />;
        }
        return (
          <div key={b.id} style={{
            borderRadius: 8, border: `1px solid color-mix(in srgb, ${b.color || 'var(--fl-sep)'} 19%, transparent)`,
            borderLeft: `3px solid ${b.color || 'var(--fl-accent)'}`, background: 'var(--fl-bg)', padding: '10px 12px',
            display: 'flex', flexDirection: 'column', gap: 6,
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fl-on-dark)', lineHeight: 1.4, flex: 1 }}>{b.title}</span>
              <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                <button onClick={() => { setEditId(b.id); setShowForm(false); }} style={{ background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer', color: 'var(--fl-subtle)', padding: '4px 7px' }}><Pencil size={10} /></button>
                <button onClick={() => remove(b.id)} style={{ background: 'none', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', borderRadius: 4, cursor: 'pointer', color: 'var(--fl-danger)', padding: '4px 7px' }}><Trash2 size={10} /></button>
              </div>
            </div>

            {b.description && <div style={{ fontSize: 11, color: 'var(--fl-dim)', lineHeight: 1.4 }}>{b.description}</div>}
            {b.significance && (
              <div style={{ fontSize: 11, color: 'var(--fl-subtle)', lineHeight: 1.4, fontStyle: 'italic', borderLeft: '2px solid var(--fl-sep)', paddingLeft: 8 }}>
                {b.significance}
              </div>
            )}

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
              {b.mitre_tactic && <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 9, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${tc} 9%, transparent)`, color: tc, border: `1px solid color-mix(in srgb, ${tc} 19%, transparent)` }}>{b.mitre_tactic}</span>}
              {b.mitre_technique && <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'var(--fl-sep)', color: 'var(--fl-dim)', border: '1px solid #2a3045' }}>{b.mitre_technique}</span>}
              {b.confidence && <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 9, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: CONF_COLOR[b.confidence] || 'var(--fl-subtle)', border: `1px solid color-mix(in srgb, ${CONF_COLOR[b.confidence] || 'var(--fl-subtle)'} 30%, transparent)` }}>{t('investigation.conf_' + b.confidence)}</span>}
              {b.links_to && titleById.get(b.links_to) && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)' }}>
                  <ArrowRight size={9} /> {titleById.get(b.links_to)}
                </span>
              )}
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', marginLeft: 'auto' }}>
                {b.author_name || b.username}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
