
import { useState, useEffect } from 'react';
import { X, Plus, Trash2, Save, FileText } from 'lucide-react';
import { reportsAPI } from '../../utils/api';

const ALL_SECTIONS = [
  { id: 'summary',      label: 'Résumé du cas' },
  { id: 'evidence',     label: 'Preuves' },
  { id: 'timeline',     label: 'Chronologie' },
  { id: 'iocs',         label: 'IOCs' },
  { id: 'mitre',        label: 'MITRE ATT&CK' },
  { id: 'triage',       label: 'Scores de triage' },
  { id: 'yara',         label: 'Résultats YARA' },
  { id: 'threat_intel', label: 'Threat Intelligence' },
  { id: 'bookmarks',    label: 'Bookmarks' },
  { id: 'hayabusa',     label: 'Détections Hayabusa' },
  { id: 'sigma',        label: 'Sigma Threat Hunting' },
  { id: 'custody',      label: 'Chaîne de custody' },
];

const CLASSIFICATIONS = ['PUBLIC', 'INTERNE', 'CONFIDENTIEL', 'SECRET', 'TRÈS SECRET'];

const EMPTY_TPL = {
  name: '',
  description: '',
  config: {
    organization: '',
    classification: 'CONFIDENTIEL',
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
      classification: 'CONFIDENTIEL',
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
    if (!editing.name.trim()) { setError('Le nom est requis.'); return; }
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
      setError('Erreur lors de la sauvegarde.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Supprimer ce template ?')) return;
    try {
      await reportsAPI.deleteTemplate(id);
      setTemplates(prev => prev.filter(t => t.id !== id));
      if (editing?.id === id) setEditing(null);
    } catch  }
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
        background: '#0d1117', border: '1px solid #1e2a3a',
        borderRadius: 12, boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>

        <div style={{
          padding: '12px 16px', borderBottom: '1px solid #1e2a3a',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <FileText size={14} style={{ color: '#4d82c0' }} />
          <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#c9d1d9', fontSize: 13, flex: 1 }}>
            {editing ? (editing.id ? 'Modifier le template' : 'Nouveau template') : 'Templates de rapport'}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#7d8590', padding: 2 }}>
            <X size={14} />
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', display: 'flex', minHeight: 0 }}>

          <div style={{
            width: editing ? 220 : '100%', flexShrink: 0,
            borderRight: editing ? '1px solid #1e2a3a' : 'none',
            padding: 12, display: 'flex', flexDirection: 'column', gap: 6,
          }}>
            <button
              onClick={startNew}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '7px 12px', borderRadius: 7, fontSize: 11,
                fontFamily: 'monospace', cursor: 'pointer',
                background: '#4d82c015', border: '1px solid #4d82c035', color: '#4d82c0',
              }}
            >
              <Plus size={11} /> Nouveau template
            </button>

            {templates.length === 0 && (
              <div style={{ fontSize: 11, color: '#484f58', fontFamily: 'monospace', textAlign: 'center', padding: '16px 0' }}>
                Aucun template — créez-en un !
              </div>
            )}

            {templates.map(tpl => (
              <div
                key={tpl.id}
                style={{
                  padding: '8px 10px', borderRadius: 7, cursor: 'pointer',
                  background: editing?.id === tpl.id ? '#4d82c018' : '#0d1117',
                  border: `1px solid ${editing?.id === tpl.id ? '#4d82c035' : '#1e2a3a'}`,
                  transition: 'background 0.1s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ flex: 1, minWidth: 0 }} onClick={() => startEdit(tpl)}>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#c9d1d9', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {tpl.name}
                    </div>
                    {tpl.description && (
                      <div style={{ fontSize: 10, color: '#7d8590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                        {tpl.description}
                      </div>
                    )}
                  </div>
                  {onSelect && (
                    <button
                      onClick={() => onSelect(tpl)}
                      title="Utiliser ce template"
                      style={{
                        padding: '2px 7px', borderRadius: 4, fontSize: 10,
                        fontFamily: 'monospace', cursor: 'pointer',
                        background: '#22c55e14', border: '1px solid #22c55e35', color: '#22c55e',
                      }}
                    >
                      ✓
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(tpl.id)}
                    title="Supprimer"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4d5460', padding: 2, flexShrink: 0 }}
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
                  <label style={{ fontSize: 10, color: '#7d8590', fontFamily: 'monospace', display: 'block', marginBottom: 4 }}>Nom *</label>
                  <input
                    value={editing.name}
                    onChange={e => setEditing(p => ({ ...p, name: e.target.value }))}
                    placeholder="Nom du template"
                    style={inputSt}
                  />
                </div>
                <div>
                  <label style={{ fontSize: 10, color: '#7d8590', fontFamily: 'monospace', display: 'block', marginBottom: 4 }}>Description</label>
                  <input
                    value={editing.description || ''}
                    onChange={e => setEditing(p => ({ ...p, description: e.target.value }))}
                    placeholder="Description courte"
                    style={inputSt}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10 }}>
                <div>
                  <label style={labelSt}>Organisation</label>
                  <input
                    value={editing.config.organization || ''}
                    onChange={e => setConfigField('organization', e.target.value)}
                    placeholder="Ex: ACME Security"
                    style={inputSt}
                  />
                </div>
                <div>
                  <label style={labelSt}>Classification</label>
                  <select value={editing.config.classification || 'CONFIDENTIEL'} onChange={e => setConfigField('classification', e.target.value)} style={inputSt}>
                    {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <label style={labelSt}>Couleur</label>
                  <input type="color" value={editing.config.color_accent || '#00d4ff'} onChange={e => setConfigField('color_accent', e.target.value)}
                    style={{ width: 48, height: 32, border: '1px solid #1e2a3a', borderRadius: 6, cursor: 'pointer', background: 'none' }} />
                </div>
              </div>

              <div>
                <label style={labelSt}>Texte d'introduction (optionnel)</label>
                <textarea
                  value={editing.config.intro_text || ''}
                  onChange={e => setConfigField('intro_text', e.target.value)}
                  placeholder="Texte affiché en tête de rapport avant les sections..."
                  rows={3}
                  style={{ ...inputSt, resize: 'vertical', fontFamily: 'inherit' }}
                />
              </div>
              <div>
                <label style={labelSt}>Texte de pied de page (optionnel)</label>
                <input
                  value={editing.config.footer_text || ''}
                  onChange={e => setConfigField('footer_text', e.target.value)}
                  placeholder="Ex: Document à diffusion restreinte"
                  style={inputSt}
                />
              </div>

              
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="checkbox"
                  id="use-ai"
                  checked={editing.config.use_ai !== false}
                  onChange={e => setConfigField('use_ai', e.target.checked)}
                  style={{ cursor: 'pointer', accentColor: '#8b5cf6' }}
                />
                <label htmlFor="use-ai" style={{ fontSize: 11, fontFamily: 'monospace', color: '#c9d1d9', cursor: 'pointer' }}>
                  Enrichir avec l'IA (synthèse narrative automatique)
                </label>
              </div>

              <div>
                <label style={labelSt}>Sections à inclure</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, marginTop: 6 }}>
                  {ALL_SECTIONS.map(sec => {
                    const active = (editing.config.sections || []).includes(sec.id);
                    return (
                      <label
                        key={sec.id}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer',
                          padding: '5px 8px', borderRadius: 5,
                          background: active ? '#4d82c010' : 'transparent',
                          border: `1px solid ${active ? '#4d82c030' : '#1e2a3a'}`,
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() => toggleSection(sec.id)}
                          style={{ accentColor: '#4d82c0', cursor: 'pointer' }}
                        />
                        <span style={{ fontSize: 11, fontFamily: 'monospace', color: active ? '#c9d1d9' : '#7d8590' }}>
                          {sec.label}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {error && (
                <div style={{ fontSize: 11, color: '#da3633', fontFamily: 'monospace' }}>{error}</div>
              )}

              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4 }}>
                <button onClick={() => { setEditing(null); setError(''); }} style={btnGhost}>Annuler</button>
                <button onClick={handleSave} disabled={saving} style={btnPrimary}>
                  <Save size={11} /> {saving ? 'Sauvegarde…' : (editing.id ? 'Mettre à jour' : 'Créer')}
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
  background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 6,
  color: '#c9d1d9', fontSize: 11, fontFamily: 'monospace',
  padding: '5px 9px', outline: 'none',
};
const labelSt = {
  fontSize: 10, color: '#7d8590', fontFamily: 'monospace', display: 'block', marginBottom: 4,
};
const btnGhost = {
  padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
  cursor: 'pointer', background: 'transparent', border: '1px solid #1e2a3a', color: '#7d8590',
};
const btnPrimary = {
  display: 'flex', alignItems: 'center', gap: 5,
  padding: '6px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
  cursor: 'pointer', background: '#4d82c0', border: 'none', color: '#fff', fontWeight: 600,
};
