import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X, Plus, Trash2, ListChecks } from 'lucide-react';
import { dfiqAPI } from '../../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

export default function DfiqCustomModal({ onClose, onCreated }) {
  const { t } = useTranslation();
  const [title, setTitle]             = useState('');
  const [description, setDescription] = useState('');
  const [questions, setQuestions]     = useState([{ text: '', facet_name: '' }]);
  const [saving, setSaving]           = useState(false);
  const [error, setError]             = useState('');

  const addQuestionRow = () => setQuestions(prev => [...prev, { text: '', facet_name: '' }]);
  const removeQuestionRow = (idx) => setQuestions(prev => prev.filter((_, i) => i !== idx));
  const updateQuestionRow = (idx, field, value) =>
    setQuestions(prev => prev.map((q, i) => (i === idx ? { ...q, [field]: value } : q)));

  const handleCreate = async () => {
    if (!title.trim()) { setError(t('dfiq.custom_error_title_required')); return; }
    setSaving(true);
    setError('');
    try {
      const { data: scenario } = await dfiqAPI.createScenario({ title: title.trim(), description: description.trim() || null });
      const validQuestions = questions.filter(q => q.text.trim());
      for (const q of validQuestions) {
        await dfiqAPI.addQuestion(scenario.id, { text: q.text.trim(), facet_name: q.facet_name.trim() || null });
      }
      onCreated?.(scenario);
    } catch (e) {
      setError(e.response?.data?.error || 'Error');
    } finally {
      setSaving(false);
    }
  };

  const inputSt = {
    width: '100%', boxSizing: 'border-box',
    background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)', borderRadius: 6,
    color: 'var(--fl-on-dark)', fontSize: 11, fontFamily: MONO,
    padding: '5px 9px', outline: 'none',
  };
  const labelSt = {
    fontSize: 10, color: 'var(--fl-dim)', fontFamily: MONO, display: 'block', marginBottom: 4,
  };
  const btnGhost = {
    padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: MONO,
    cursor: 'pointer', background: 'transparent', border: '1px solid var(--fl-sep)', color: 'var(--fl-dim)',
  };
  const btnPrimary = {
    display: 'flex', alignItems: 'center', gap: 5,
    padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: MONO,
    cursor: 'pointer', background: 'var(--fl-accent)', border: 'none', color: '#fff', fontWeight: 600,
    opacity: saving ? 0.6 : 1,
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={t('dfiq.custom_new')}
      style={{
        position: 'fixed', inset: 0, zIndex: 2000,
        background: 'rgba(0,0,0,0.65)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        width: 520, maxHeight: '90vh',
        background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)',
        borderRadius: 12, boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--fl-sep)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <ListChecks size={14} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: MONO, fontWeight: 700, color: 'var(--fl-dim)', fontSize: 13, flex: 1 }}>
            {t('dfiq.custom_new')}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 2 }}>
            <X size={14} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <label style={labelSt}>{t('dfiq.custom_scenario_title')} *</label>
            <input
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder={t('dfiq.custom_scenario_title_ph')}
              style={inputSt}
            />
          </div>

          <div>
            <label style={labelSt}>{t('dfiq.custom_scenario_description')}</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder={t('dfiq.custom_scenario_description_ph')}
              rows={2}
              style={{ ...inputSt, resize: 'vertical', fontFamily: 'inherit' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <label style={{ ...labelSt, marginBottom: 0 }}>{t('dfiq.custom_question_add')}</label>
              <button onClick={addQuestionRow} style={{ ...btnGhost, display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px' }}>
                <Plus size={10} /> {t('dfiq.custom_question_add')}
              </button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {questions.map((q, idx) => (
                <div key={idx} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input
                    value={q.text}
                    onChange={e => updateQuestionRow(idx, 'text', e.target.value)}
                    placeholder={t('dfiq.custom_question_text_ph')}
                    style={{ ...inputSt, flex: 2 }}
                  />
                  <input
                    value={q.facet_name}
                    onChange={e => updateQuestionRow(idx, 'facet_name', e.target.value)}
                    placeholder={t('dfiq.custom_question_facet_ph')}
                    style={{ ...inputSt, flex: 1 }}
                  />
                  {questions.length > 1 && (
                    <button onClick={() => removeQuestionRow(idx)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-danger)', padding: 2, flexShrink: 0 }}>
                      <Trash2 size={12} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {error && (
            <div style={{ fontSize: 11, color: 'var(--fl-danger)', fontFamily: MONO }}>{error}</div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4 }}>
            <button onClick={onClose} style={btnGhost}>{t('dfiq.custom_cancel')}</button>
            <button onClick={handleCreate} disabled={saving} style={btnPrimary}>
              {saving ? t('dfiq.custom_creating') : t('dfiq.custom_create')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
