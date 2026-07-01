import { useState } from 'react';
import { useTranslation } from 'react-i18next';

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const TACTIC_COLOR = {
  'Reconnaissance': 'var(--fl-dim)', 'Resource Development': 'var(--fl-dim)',
  'Initial Access': 'var(--fl-warn)', 'Execution': 'var(--fl-danger)',
  'Persistence': 'var(--fl-pink)', 'Privilege Escalation': 'var(--fl-purple)',
  'Defense Evasion': 'var(--fl-accent)', 'Credential Access': 'var(--fl-danger)',
  'Discovery': 'var(--fl-gold)', 'Lateral Movement': 'var(--fl-warn)',
  'Collection': 'var(--fl-ok)', 'Command and Control': 'var(--fl-danger)',
  'Exfiltration': 'var(--fl-danger)', 'Impact': 'var(--fl-danger)',
};

// Hex literals (not CSS vars): the chosen color is persisted to the DB and
// later drawn by the PDF report renderer, which cannot resolve var(--fl-*).
const PALETTE = ['#4d82c0', '#D7263D', '#E8730C', '#C99A06', '#2E9E5B', '#6E56CF', '#D6336C'];

const EMPTY = {
  title: '', mitre_tactic: '', mitre_technique: '', description: '',
  significance: '', confidence: '', links_to: '', color: '#4d82c0',
};

const field = {
  background: '#050c18', border: '1px solid var(--fl-card)', borderRadius: 4,
  color: 'var(--fl-on-dark)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
  padding: '5px 8px', outline: 'none', width: '100%', boxSizing: 'border-box',
};

const lbl = { fontSize: 9, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.05em' };

/**
 * Reusable structured forensic note editor.
 * Props:
 *  - initial: finding object (or null for new)
 *  - findings: list of other findings (for the links_to selector)
 *  - onSave(form), onCancel()
 */
export default function StructuredNoteEditor({ initial, findings = [], onSave, onCancel }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ ...EMPTY, ...(initial || {}) });
  const [saving, setSaving] = useState(false);

  function set(k, v) { setForm(p => ({ ...p, [k]: v })); }

  async function submit(e) {
    e.preventDefault();
    if (!form.title.trim()) return;
    setSaving(true);
    try { await onSave(form); } finally { setSaving(false); }
  }

  const linkOptions = findings.filter(f => f.id && f.id !== initial?.id);

  return (
    <form onSubmit={submit} style={{
      padding: '12px 14px', background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <input autoFocus placeholder={t('bookmark.title_ph')} value={form.title}
        onChange={e => set('title', e.target.value)} style={field} />

      <div style={{ display: 'flex', gap: 8 }}>
        <select value={form.mitre_tactic} onChange={e => set('mitre_tactic', e.target.value)}
          style={{ ...field, color: form.mitre_tactic ? (TACTIC_COLOR[form.mitre_tactic] || 'var(--fl-on-dark)') : 'var(--fl-subtle)' }}>
          <option value="">{t('bookmark.tactic_ph')}</option>
          {MITRE_TACTICS.map(tc => <option key={tc} value={tc}>{tc}</option>)}
        </select>
        <input placeholder={t('bookmark.technique_ph')} value={form.mitre_technique}
          onChange={e => set('mitre_technique', e.target.value)} style={field} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <span style={lbl}>{t('investigation.fact')}</span>
        <textarea placeholder={t('investigation.fact_ph')} value={form.description} rows={2}
          onChange={e => set('description', e.target.value)} style={{ ...field, resize: 'vertical' }} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <span style={lbl}>{t('investigation.significance')}</span>
        <textarea placeholder={t('investigation.significance_ph')} value={form.significance} rows={2}
          onChange={e => set('significance', e.target.value)} style={{ ...field, resize: 'vertical' }} />
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
          <span style={lbl}>{t('investigation.confidence')}</span>
          <select value={form.confidence} onChange={e => set('confidence', e.target.value)} style={field}>
            <option value="">—</option>
            <option value="low">{t('investigation.conf_low')}</option>
            <option value="medium">{t('investigation.conf_medium')}</option>
            <option value="high">{t('investigation.conf_high')}</option>
          </select>
        </div>
        <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
          <span style={lbl}>{t('investigation.leads_to')}</span>
          <select value={form.links_to || ''} onChange={e => set('links_to', e.target.value)} style={field}>
            <option value="">{t('investigation.leads_to_none')}</option>
            {linkOptions.map(f => <option key={f.id} value={f.id}>{f.title}</option>)}
          </select>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={lbl}>{t('bookmark.col_color') || 'Color'}</span>
        {PALETTE.map(c => (
          <button key={c} type="button" onClick={() => set('color', c)} style={{
            width: 18, height: 18, borderRadius: '50%', background: c, border: 'none', cursor: 'pointer',
            outline: form.color === c ? `2px solid ${c}` : 'none', outlineOffset: 2,
          }} />
        ))}
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        <button type="submit" disabled={saving || !form.title.trim()} style={{
          flex: 1, padding: '5px 10px', borderRadius: 4,
          background: form.title.trim() ? '#1a1f2c' : '#0a1020',
          border: `1px solid ${form.title.trim() ? '#2a5080' : '#0e1828'}`,
          color: form.title.trim() ? 'var(--fl-accent)' : 'var(--fl-card)',
          fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: form.title.trim() ? 'pointer' : 'default',
        }}>
          {saving ? t('bookmark.creating') : t('common.save')}
        </button>
        <button type="button" onClick={onCancel} style={{
          padding: '5px 10px', borderRadius: 4, background: 'none',
          border: '1px solid var(--fl-card)', color: 'var(--fl-subtle)',
          fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
        }}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  );
}
