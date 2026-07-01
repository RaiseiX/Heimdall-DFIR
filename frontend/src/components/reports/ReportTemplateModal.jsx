
import { useState, useEffect } from 'react';
import { X, Plus, Trash2, Save, FileText } from 'lucide-react';
import { reportsAPI } from '../../utils/api';

const ALL_SECTIONS = [
  { id: 'summary',      label: 'Case summary' },
  { id: 'evidence',     label: 'Evidence' },
  { id: 'timeline',     label: 'Timeline' },
  { id: 'iocs',         label: 'IOCs' },
  { id: 'mitre',        label: 'MITRE ATT&CK' },
  { id: 'triage',       label: 'Triage scores' },
  { id: 'yara',         label: 'YARA results' },
  { id: 'threat_intel', label: 'Threat Intelligence' },
  { id: 'bookmarks',    label: 'Bookmarks' },
  { id: 'hayabusa',     label: 'Hayabusa detections' },
  { id: 'sigma',        label: 'Sigma threat hunting' },
  { id: 'custody',      label: 'Chain of custody' },
];

const CLASSIFICATIONS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP SECRET'];

const EMPTY_TPL = {
  name: '',
  description: '',
  config: {
    organization: '',
    classification: 'CONFIDENTIAL',
    intro_text: '',
    footer_text: '',
    color_accent: '#00d4ff',
    use_ai: true,
    sections: ALL_SECTIONS.map(s => s.id),
  },
};

function deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}

export default function ReportTemplateModal({ onClose, onSelect }) {
  const [templates, setTemplates] = useState([]);
  const [editing, setEditing]     = useState(null);
  const [saving, setSaving]       = useState(false);
  const [error, setError]         = useState('');

  useEffect(() => {
    reportsAPI.listTemplates()
      .then(r => setTemplates(r.data))
      .catch(() => setTemplates([]));
  }, []);

  const startNew = () => {
    setEditing(deepCopy(EMPTY_TPL));
    setError('');
  };

  const startEdit = (tpl) => {

    const cfg = {
      organization: '',
      classification: 'CONFIDENTIAL',
      intro_text: '',
      footer_text: '',
      color_accent: '#00d4ff',
      use_ai: true,
      sections: ALL_SECTIONS.map(s => s.id),
      ...tpl.config,
    };
    setEditing({ ...tpl, config: cfg });
    setError('');
  };

  const handleSave = async () => {
    if (!editing.name.trim()) { setError('Name is required.'); return; }
    setSaving(true);
    setError('');
    try {
      if (editing.id) {
        const { data } = await reportsAPI.updateTemplate(editing.id, editing);
        setTemplates(prev => prev.map(t => t.id === editing.id ? data : t));
      } else {
        const { data } = await reportsAPI.createTemplate(editing);
        setTemplates(prev => [data, ...prev]);
      }
      setEditing(null);
    } catch {
      setError('Save error.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this template?')) return;
    try {
      await reportsAPI.deleteTemplate(id);
      setTemplates(prev => prev.filter(t => t.id !== id));
      if (editing?.id === id) setEditing(null);
    } catch (_e) {}
  };

  const toggleSection = (sectionId) => {
    setEditing(prev => {
      const secs = prev.config.sections || [];
      const next = secs.includes(sectionId)
        ? secs.filter(s => s !== sectionId)
        : [...secs, sectionId];
      return { ...prev, config: { ...prev.config, sections: next } };
    });
  };

  const setConfigField = (field, value) =>
    setEditing(prev => ({ ...prev, config: { ...prev.config, [field]: value } }));

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 2000,
      background: 'rgba(0,0,0,0.65)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        width: editing ? 780 : 460, maxHeight: '90vh',
        background: 'var(--fl-bg)', border: '1px solid var(--fl-card)',
        borderRadius: 12, boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>

        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--fl-card)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <FileText size={14} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: 'var(--fl-dim)', fontSize: 13, flex: 1 }}>
            {editing ? (editing.id ? 'Edit template' : 'New template') : 'Report templates'}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 2 }}>
            <X size={14} />
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', display: 'flex', minHeight: 0 }}>

          <div style={{
            width: editing ? 220 : '100%', flexShrink: 0,
            borderRight: editing ? '1px solid var(--fl-card)' : 'none',
            padding: 12, display: 'flex', flexDirection: 'column', gap: 6,
          }}>
            <button
              onClick={startNew}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '7px 12px', borderRadius: 7, fontSize: 11,
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 21%, transparent)', color: 'var(--fl-accent)',
              }}
            >
              <Plus size={11} /> New template
            </button>

            {templates.length === 0 && (
              <div style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textAlign: 'center', padding: '16px 0' }}>
                No templates - create one.
              </div>
            )}

            {templates.map(tpl => (
              <div
                key={tpl.id}
                style={{
                  padding: '8px 10px', borderRadius: 7, cursor: 'pointer',
                  background: editing?.id === tpl.id ? 'color-mix(in srgb, var(--fl-accent) 9%, transparent)' : 'var(--fl-bg)',
                  border: `1px solid ${editing?.id === tpl.id ? 'color-mix(in srgb, var(--fl-accent) 21%, transparent)' : 'var(--fl-card)'}`,
                  transition: 'background 0.1s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ flex: 1, minWidth: 0 }} onClick={() => startEdit(tpl)}>
                    <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {tpl.name}
                    </div>
                    {tpl.description && (
                      <div style={{ fontSize: 10, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                        {tpl.description}
                      </div>
                    )}
                  </div>
                  {onSelect && (
                    <button
                      onClick={() => onSelect(tpl)}
                      title="Use this template"
                      style={{
                        padding: '2px 7px', borderRadius: 4, fontSize: 10,
                        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                        background: 'color-mix(in srgb, var(--fl-ok) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 21%, transparent)', color: 'var(--fl-ok)',
                      }}
                    >
                      ✓
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(tpl.id)}
                    title="Delete"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 2, flexShrink: 0 }}
                  >
                    <Trash2 size={11} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {editing && (
            <div style={{ flex: 1, padding: 16, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'block', marginBottom: 4 }}>Name *</label>
                  <input
                    value={editing.name}
                    onChange={e => setEditing(p => ({ ...p, name: e.target.value }))}
                    placeholder="Template name"
                    style={inputSt}
                  />
                </div>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'block', marginBottom: 4 }}>Description</label>
                  <input
                    value={editing.description || ''}
                    onChange={e => setEditing(p => ({ ...p, description: e.target.value }))}
                    placeholder="Short description"
                    style={inputSt}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10 }}>
                <div>
                  <label style={labelSt}>Organization</label>
                  <input
                    value={editing.config.organization || ''}
                    onChange={e => setConfigField('organization', e.target.value)}
                    placeholder="e.g. ACME Security"
                    style={inputSt}
                  />
                </div>
                <div>
                  <label style={labelSt}>Classification</label>
                  <select value={editing.config.classification || 'CONFIDENTIAL'} onChange={e => setConfigField('classification', e.target.value)} style={inputSt}>
                    {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <label style={labelSt}>Color</label>
                  <input type="color" value={editing.config.color_accent || '#00d4ff'} onChange={e => setConfigField('color_accent', e.target.value)}
                    style={{ width: 48, height: 32, border: '1px solid var(--fl-card)', borderRadius: 6, cursor: 'pointer', background: 'none' }} />
                </div>
              </div>

              <div>
                <label style={labelSt}>Texte d'introduction (optionnel)</label>
                <textarea
                  value={editing.config.intro_text || ''}
                  onChange={e => setConfigField('intro_text', e.target.value)}
                  placeholder="Text shown at the top of the report before the sections..."
                  rows={3}
                  style={{ ...inputSt, resize: 'vertical', fontFamily: 'inherit' }}
                />
              </div>
              <div>
                <label style={labelSt}>Texte de pied de page (optionnel)</label>
                <input
                  value={editing.config.footer_text || ''}
                  onChange={e => setConfigField('footer_text', e.target.value)}
                  placeholder="e.g. Restricted distribution document"
                  style={inputSt}
                />
              </div>

              
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="checkbox"
                  id="use-ai"
                  checked={editing.config.use_ai !== false}
                  onChange={e => setConfigField('use_ai', e.target.checked)}
                  style={{ cursor: 'pointer', accentColor: 'var(--fl-accent)' }}
                />
                <label htmlFor="use-ai" style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', cursor: 'pointer' }}>
                  Enrich with AI (automatic narrative summary)
                </label>
              </div>

              <div>
                <label style={labelSt}>Sections to include</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, marginTop: 6 }}>
                  {ALL_SECTIONS.map(sec => {
                    const active = (editing.config.sections || []).includes(sec.id);
                    return (
                      <label
                        key={sec.id}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer',
                          padding: '5px 8px', borderRadius: 5,
                          background: active ? 'color-mix(in srgb, var(--fl-accent) 6%, transparent)' : 'transparent',
                          border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'var(--fl-card)'}`,
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() => toggleSection(sec.id)}
                          style={{ accentColor: 'var(--fl-accent)', cursor: 'pointer' }}
                        />
                        <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: active ? 'var(--fl-dim)' : 'var(--fl-dim)' }}>
                          {sec.label}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {error && (
                <div style={{ fontSize: 11, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{error}</div>
              )}

              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4 }}>
                <button onClick={() => { setEditing(null); setError(''); }} style={btnGhost}>Cancel</button>
                <button onClick={handleSave} disabled={saving} style={btnPrimary}>
                  <Save size={11} /> {saving ? 'Saving…' : (editing.id ? 'Update' : 'Create')}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const inputSt = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 6,
  color: 'var(--fl-dim)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  padding: '5px 9px', outline: 'none',
};
const labelSt = {
  fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'block', marginBottom: 4,
};
const btnGhost = {
  padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  cursor: 'pointer', background: 'transparent', border: '1px solid var(--fl-card)', color: 'var(--fl-dim)',
};
const btnPrimary = {
  display: 'flex', alignItems: 'center', gap: 5,
  padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  cursor: 'pointer', background: 'var(--fl-accent)', border: 'none', color: '#fff', fontWeight: 600,
};
