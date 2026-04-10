
import { useState, useEffect, useCallback } from 'react';
import {
  X, Plus, Trash2, ChevronUp, ChevronDown, Edit3,
  Download, Upload, ToggleLeft, ToggleRight, GripVertical,
  Check, AlertCircle,
} from 'lucide-react';
import { collectionAPI } from '../../utils/api';
import {
  sortRules, conditionToString, RULE_FIELDS, RULE_OPS, RULE_COLORS,
} from '../../utils/colorRulesEngine';
import axios from 'axios';

const API_BASE = (typeof import.meta !== 'undefined' ? import.meta.env?.VITE_API_URL : '') || '/api';

async function fetchRules(caseId) {
  const res = await axios.get(`${API_BASE}/timeline-rules`, {
    params: { case_id: caseId },
    headers: { Authorization: `Bearer ${localStorage.getItem('heimdall_token') || localStorage.getItem('forensiclab_token')}` },
  });
  return res.data.rules || [];
}

async function saveRule(rule) {
  const token = localStorage.getItem('heimdall_token') || localStorage.getItem('forensiclab_token');
  const headers = { Authorization: `Bearer ${token}` };
  if (rule.id && !rule._new) {
    const res = await axios.put(`${API_BASE}/timeline-rules/${rule.id}`, rule, { headers });
    return res.data.rule;
  }
  const { id: _id, _new, ...body } = rule;
  const res = await axios.post(`${API_BASE}/timeline-rules`, body, { headers });
  return res.data.rule;
}

async function deleteRule(id) {
  const token = localStorage.getItem('heimdall_token') || localStorage.getItem('forensiclab_token');
  await axios.delete(`${API_BASE}/timeline-rules/${id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function reorderRules(updates) {
  const token = localStorage.getItem('heimdall_token') || localStorage.getItem('forensiclab_token');
  await axios.patch(`${API_BASE}/timeline-rules/reorder`, { updates }, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

function ConditionRow({ cond, onChange, onDelete, isOnly }) {
  const needsValue = !['is_null', 'is_not_null', 'off_hours'].includes(cond.op);
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4 }}>
      <select value={cond.field} onChange={e => onChange({ ...cond, field: e.target.value })}
        style={{ flex: 1.2, padding: '3px 6px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 4, color: '#c0cce0', fontSize: 10, fontFamily: 'monospace' }}>
        {RULE_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select value={cond.op} onChange={e => onChange({ ...cond, op: e.target.value })}
        style={{ flex: 1, padding: '3px 6px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 4, color: '#c0cce0', fontSize: 10, fontFamily: 'monospace' }}>
        {RULE_OPS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      {needsValue && (
        <input value={cond.value || ''} onChange={e => onChange({ ...cond, value: e.target.value })}
          placeholder="valeur"
          style={{ flex: 1.5, padding: '3px 6px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 4, color: '#e6edf3', fontSize: 10, fontFamily: 'monospace' }} />
      )}
      {!isOnly && (
        <button onClick={onDelete} style={{ padding: '2px 4px', background: 'none', border: 'none', cursor: 'pointer', color: '#484f58' }}>
          <X size={10} />
        </button>
      )}
    </div>
  );
}

function RuleEditor({ rule, caseId, onSave, onCancel }) {
  const [form, setForm] = useState({
    name:       rule?.name || '',
    color:      rule?.color || '#EF4444',
    icon:       rule?.icon || '',
    scope:      rule?.scope || 'case',
    priority:   rule?.priority ?? 10,
    is_active:  rule?.is_active ?? true,
    case_id:    rule?.case_id || caseId || null,
    conditions: rule?.conditions || { operator: 'AND', rules: [{ field: 'description', op: 'contains', value: '' }] },
    id:         rule?.id,
    _new:       !rule?.id,
  });
  const [saving, setSaving] = useState(false);
  const [error,  setError]  = useState('');

  function addCondition() {
    setForm(f => ({ ...f, conditions: { ...f.conditions, rules: [...f.conditions.rules, { field: 'description', op: 'contains', value: '' }] } }));
  }
  function updateCondition(i, cond) {
    setForm(f => {
      const rules = [...f.conditions.rules];
      rules[i] = cond;
      return { ...f, conditions: { ...f.conditions, rules } };
    });
  }
  function removeCondition(i) {
    setForm(f => ({ ...f, conditions: { ...f.conditions, rules: f.conditions.rules.filter((_, idx) => idx !== i) } }));
  }

  async function handleSave() {
    if (!form.name.trim()) { setError('Le nom est requis'); return; }
    if (!form.conditions.rules.length) { setError('Au moins une condition est requise'); return; }
    setSaving(true); setError('');
    try {
      const saved = await saveRule(form);
      onSave(saved);
    } catch (e) {
      setError(e.response?.data?.error || 'Erreur lors de la sauvegarde');
    } finally { setSaving(false); }
  }

  return (
    <div style={{ padding: 12, background: '#0d1525', border: '1px solid #30363d', borderRadius: 8, marginBottom: 8 }}>
      
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
          placeholder="Nom de la règle"
          style={{ flex: 1, padding: '5px 8px', background: '#161b22', border: '1px solid #30363d', borderRadius: 5, color: '#e6edf3', fontSize: 11, fontFamily: 'monospace' }} />
        <input type="number" value={form.priority} onChange={e => setForm(f => ({ ...f, priority: parseInt(e.target.value) || 0 }))}
          title="Priorité (+ bas = évalué en premier)"
          style={{ width: 54, padding: '5px 8px', background: '#161b22', border: '1px solid #30363d', borderRadius: 5, color: '#e6edf3', fontSize: 11, textAlign: 'center' }} />
      </div>

      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>COULEUR</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
          {RULE_COLORS.map(c => (
            <button key={c} onClick={() => setForm(f => ({ ...f, color: c }))}
              style={{
                width: 20, height: 20, borderRadius: 4, background: c, border: 'none', cursor: 'pointer',
                outline: form.color === c ? `2px solid ${c}` : 'none',
                outlineOffset: 2,
                transform: form.color === c ? 'scale(1.2)' : 'scale(1)',
              }} />
          ))}
          <input type="color" value={form.color} onChange={e => setForm(f => ({ ...f, color: e.target.value }))}
            style={{ width: 24, height: 24, border: 'none', cursor: 'pointer', background: 'none', padding: 0 }} />
          <span style={{ fontFamily: 'monospace', fontSize: 10, color: form.color }}>{form.color}</span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em' }}>PORTÉE</span>
        <button onClick={() => setForm(f => ({ ...f, scope: f.scope === 'global' ? 'case' : 'global', case_id: f.scope === 'global' ? (caseId || null) : null }))}
          style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
            background: form.scope === 'global' ? '#f59e0b18' : '#4d82c018',
            color: form.scope === 'global' ? '#f59e0b' : '#4d82c0',
            border: `1px solid ${form.scope === 'global' ? '#f59e0b40' : '#4d82c040'}` }}>
          {form.scope === 'global' ? '🌐 Globale (tous les cas)' : '📁 Ce cas uniquement'}
        </button>
      </div>

      <div style={{ marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em' }}>CONDITIONS</span>
          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            <select value={form.conditions.operator} onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, operator: e.target.value } }))}
              style={{ padding: '2px 5px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 3, color: '#7d8590', fontSize: 9 }}>
              <option value="AND">ET (toutes les conditions)</option>
              <option value="OR">OU (au moins une)</option>
            </select>
          </div>
        </div>
        {form.conditions.rules.map((cond, i) => (
          <ConditionRow key={i} cond={cond}
            onChange={c => updateCondition(i, c)}
            onDelete={() => removeCondition(i)}
            isOnly={form.conditions.rules.length === 1} />
        ))}
        <button onClick={addCondition} style={{ marginTop: 4, padding: '3px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', background: '#161b22', border: '1px solid #30363d', color: '#7d8590', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Plus size={10} /> Ajouter une condition
        </button>
      </div>

      {error && <div style={{ padding: '4px 8px', borderRadius: 4, background: '#2d1515', border: '1px solid #dc2626', color: '#f87171', fontSize: 10, fontFamily: 'monospace', marginBottom: 6 }}>{error}</div>}

      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
        <button onClick={onCancel} style={{ padding: '4px 12px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', background: '#161b22', border: '1px solid #30363d', color: '#7d8590' }}>
          Annuler
        </button>
        <button onClick={handleSave} disabled={saving} style={{ padding: '4px 14px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace', cursor: 'pointer', background: '#4d82c0', border: 'none', color: '#fff', fontWeight: 700 }}>
          {saving ? '...' : 'Sauvegarder'}
        </button>
      </div>
    </div>
  );
}

export default function ColorRulesManager({ open, onClose, caseId, onRulesChange }) {
  const [rules,    setRules]    = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [editRule, setEditRule] = useState(null);
  const [dragOver, setDragOver] = useState(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchRules(caseId);
      const sorted = sortRules(data);
      setRules(sorted);
      onRulesChange?.(sorted);
    } catch  }
    setLoading(false);
  }, [caseId, onRulesChange]);

  useEffect(() => { if (open) loadRules(); }, [open, loadRules]);

  async function handleSave(saved) {
    setEditRule(null);
    await loadRules();
  }

  async function handleDelete(id) {
    if (!confirm('Supprimer cette règle ?')) return;
    await deleteRule(id);
    await loadRules();
  }

  async function toggleActive(rule) {
    await saveRule({ ...rule, is_active: !rule.is_active });
    await loadRules();
  }

  async function movePriority(rule, direction) {
    const idx = rules.findIndex(r => r.id === rule.id);
    if (direction === 'up'   && idx === 0) return;
    if (direction === 'down' && idx === rules.length - 1) return;
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    const updates = [
      { id: rule.id,          priority: rules[swapIdx].priority },
      { id: rules[swapIdx].id, priority: rule.priority },
    ];
    await reorderRules(updates);
    await loadRules();
  }

  function exportRules() {
    const data = JSON.stringify(rules.map(({ id: _id, author_id: _a, created_at: _c, updated_at: _u, ...r }) => r), null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a'); a.href = url; a.download = 'color-rules.json'; a.click();
    URL.revokeObjectURL(url);
  }

  function importRules() {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = '.json';
    inp.onchange = async e => {
      const file = e.target.files[0]; if (!file) return;
      const text = await file.text();
      try {
        const imported = JSON.parse(text);
        if (!Array.isArray(imported)) return;
        for (const r of imported) {
          await saveRule({ ...r, _new: true, id: undefined });
        }
        await loadRules();
      } catch { alert('Fichier JSON invalide'); }
    };
    inp.click();
  }

  if (!open) return null;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 500,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'flex-end',
      pointerEvents: 'none',
    }}>
      
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', pointerEvents: 'auto' }} />

      <div style={{
        position: 'relative', width: 460, height: '100vh', background: '#0d1117',
        borderLeft: '1px solid #30363d', display: 'flex', flexDirection: 'column',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.6)', pointerEvents: 'auto', overflow: 'hidden',
      }}>
        
        <div style={{ padding: '14px 16px', borderBottom: '1px solid #30363d', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#e6edf3' }}>
              🎨 Règles de colorisation
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#484f58', marginTop: 2 }}>
              {rules.filter(r => r.is_active).length} règles actives · évaluées en priorité croissante
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button onClick={exportRules} title="Exporter les règles en JSON"
              style={{ padding: '4px 8px', background: '#161b22', border: '1px solid #30363d', borderRadius: 5, cursor: 'pointer', color: '#7d8590' }}>
              <Download size={12} />
            </button>
            <button onClick={importRules} title="Importer des règles depuis JSON"
              style={{ padding: '4px 8px', background: '#161b22', border: '1px solid #30363d', borderRadius: 5, cursor: 'pointer', color: '#7d8590' }}>
              <Upload size={12} />
            </button>
            <button onClick={onClose} style={{ padding: '4px 8px', background: '#161b22', border: '1px solid #30363d', borderRadius: 5, cursor: 'pointer', color: '#7d8590' }}>
              <X size={12} />
            </button>
          </div>
        </div>

        <div style={{ padding: '8px 14px', borderBottom: '1px solid #1a2035', flexShrink: 0 }}>
          <button onClick={() => setEditRule('new')}
            style={{ width: '100%', padding: '7px 0', borderRadius: 6, fontSize: 11, fontFamily: 'monospace', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, background: '#4d82c012', border: '1px dashed #4d82c040', color: '#4d82c0' }}>
            <Plus size={12} /> Nouvelle règle
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 14px' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#484f58', fontFamily: 'monospace', fontSize: 11 }}>Chargement...</div>
          ) : (
            <>
              {editRule === 'new' && (
                <RuleEditor rule={null} caseId={caseId} onSave={handleSave} onCancel={() => setEditRule(null)} />
              )}
              {rules.length === 0 && editRule !== 'new' && (
                <div style={{ textAlign: 'center', padding: 40, color: '#484f58', fontFamily: 'monospace', fontSize: 11 }}>
                  Aucune règle. Cliquez sur "Nouvelle règle" pour commencer.
                </div>
              )}
              {rules.map((rule, idx) => {
                const isEditing = editRule?.id === rule.id;
                return (
                  <div key={rule.id}>
                    {isEditing ? (
                      <RuleEditor rule={rule} caseId={caseId} onSave={handleSave} onCancel={() => setEditRule(null)} />
                    ) : (
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 6, padding: '7px 10px',
                        background: '#111827', border: `1px solid ${rule.is_active ? '#1a2035' : '#30363d'}`,
                        borderLeft: `3px solid ${rule.is_active ? rule.color : '#30363d'}`,
                        borderRadius: 6, marginBottom: 4, opacity: rule.is_active ? 1 : 0.5,
                      }}>
                        
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 1, flexShrink: 0 }}>
                          <button onClick={() => movePriority(rule, 'up')} disabled={idx === 0}
                            style={{ padding: 1, background: 'none', border: 'none', cursor: idx === 0 ? 'default' : 'pointer', color: idx === 0 ? '#30363d' : '#484f58' }}>
                            <ChevronUp size={10} />
                          </button>
                          <span style={{ fontFamily: 'monospace', fontSize: 8, color: '#484f58', textAlign: 'center', lineHeight: 1 }}>{rule.priority}</span>
                          <button onClick={() => movePriority(rule, 'down')} disabled={idx === rules.length - 1}
                            style={{ padding: 1, background: 'none', border: 'none', cursor: idx === rules.length - 1 ? 'default' : 'pointer', color: idx === rules.length - 1 ? '#30363d' : '#484f58' }}>
                            <ChevronDown size={10} />
                          </button>
                        </div>

                        <div style={{ width: 14, height: 14, borderRadius: 3, background: rule.color, flexShrink: 0 }} />

                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: rule.is_active ? '#e6edf3' : '#484f58', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {rule.name}
                          </div>
                          <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#484f58', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {rule.conditions?.operator} : {rule.conditions?.rules?.map(c => conditionToString(c)).join(` ${rule.conditions?.operator === 'OR' ? '| ' : '& '}`)}
                          </div>
                        </div>

                        {rule.scope === 'global' && (
                          <span style={{ flexShrink: 0, padding: '1px 5px', borderRadius: 3, fontSize: 8, fontFamily: 'monospace', background: '#f59e0b14', color: '#f59e0b', border: '1px solid #f59e0b30' }}>global</span>
                        )}

                        <button onClick={() => toggleActive(rule)} title={rule.is_active ? 'Désactiver' : 'Activer'}
                          style={{ padding: 3, background: 'none', border: 'none', cursor: 'pointer', color: rule.is_active ? '#22c55e' : '#484f58', flexShrink: 0 }}>
                          {rule.is_active ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
                        </button>
                        <button onClick={() => setEditRule(rule)} title="Modifier"
                          style={{ padding: 3, background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', flexShrink: 0 }}>
                          <Edit3 size={11} />
                        </button>
                        <button onClick={() => handleDelete(rule.id)} title="Supprimer"
                          style={{ padding: 3, background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', flexShrink: 0 }}
                          onMouseEnter={e => e.currentTarget.style.color = '#ef4444'}
                          onMouseLeave={e => e.currentTarget.style.color = '#484f58'}>
                          <Trash2 size={11} />
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )}
        </div>

        <div style={{ padding: '8px 14px', borderTop: '1px solid #1a2035', flexShrink: 0, fontFamily: 'monospace', fontSize: 9, color: '#3d5070' }}>
          Les règles sont évaluées en ordre croissant de priorité · première correspondance gagne · évaluation 100% locale (zéro requête réseau)
        </div>
      </div>
    </div>
  );
}
