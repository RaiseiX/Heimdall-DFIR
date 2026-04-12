import { useState, useEffect, useMemo } from 'react';
import { Shield, Plus, X, Search, ChevronDown, ChevronRight, Trash2, Edit2, Check } from 'lucide-react';
import { TACTICS, TACTIC_MAP, TECHNIQUES } from '../../data/mitreData';
import { mitreAPI } from '../../utils/api';

const CONFIDENCE = [
  { key: 'confirmed', label: 'Confirmé',  color: '#ef4444' },
  { key: 'high',      label: 'Élevée',    color: '#d97c20' },
  { key: 'medium',    label: 'Moyenne',   color: '#c89d1d' },
  { key: 'low',       label: 'Faible',    color: '#22c55e' },
];
const CONF_MAP = Object.fromEntries(CONFIDENCE.map(c => [c.key, c]));

const TECH_BY_TACTIC = TECHNIQUES.reduce((acc, t) => {
  if (!acc[t.tactic]) acc[t.tactic] = [];
  acc[t.tactic].push(t);
  return acc;
}, {});

function ConfBadge({ level }) {
  const c = CONF_MAP[level];
  if (!c) return null;
  return (
    <span style={{ padding: '1px 7px', borderRadius: 8, fontSize: 10, fontFamily: 'monospace',
      fontWeight: 700, background: `${c.color}20`, color: c.color, border: `1px solid ${c.color}35` }}>
      {c.label}
    </span>
  );
}

function TechniqueModal({ onAdd, onClose, alreadyMapped }) {
  const [search, setSearch]   = useState('');
  const [tactic, setTactic]   = useState(null);
  const [selected, setSelected] = useState(null);
  const [confidence, setConf] = useState('medium');
  const [notes, setNotes]     = useState('');
  const [adding, setAdding]   = useState(false);
  const [error, setError]     = useState('');

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return TECHNIQUES.filter(t => {
      const matchSearch = !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
      const matchTactic = !tactic || t.tactic === tactic;
      const notMapped   = !alreadyMapped.has(t.id);
      return matchSearch && matchTactic && notMapped;
    });
  }, [search, tactic, alreadyMapped]);

  async function handleAdd() {
    if (!selected) return;
    setAdding(true);
    setError('');
    try {
      await onAdd({ ...selected, confidence, notes });
      onClose();
    } catch (e) {
      setError(e.message || 'Erreur lors de l\'ajout');
      setAdding(false);
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 200, background: '#00000088',
      display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ width: 780, maxHeight: '85vh', background: '#111827',
        border: '1px solid #30363d', borderRadius: 12, display: 'flex', flexDirection: 'column',
        boxShadow: '0 20px 60px #000' }}>

        <div style={{ padding: '14px 18px', borderBottom: '1px solid #30363d',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} style={{ color: '#4d82c0' }} />
            <span style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#e6edf3' }}>
              Sélectionner une technique MITRE ATT&CK
            </span>
          </div>
          <button onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#334155' }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
          
          <div style={{ width: 200, borderRight: '1px solid #30363d', overflowY: 'auto',
            padding: 8, flexShrink: 0 }}>
            <button onClick={() => setTactic(null)}
              style={{ width: '100%', padding: '5px 8px', borderRadius: 5, textAlign: 'left',
                fontFamily: 'monospace', fontSize: 11, cursor: 'pointer',
                background: !tactic ? '#4d82c015' : 'transparent',
                color: !tactic ? '#4d82c0' : '#7d8590',
                border: `1px solid ${!tactic ? '#4d82c030' : 'transparent'}` }}>
              Toutes ({TECHNIQUES.filter(t => !alreadyMapped.has(t.id)).length})
            </button>
            {TACTICS.map(ta => {
              const count = (TECH_BY_TACTIC[ta.id] || []).filter(t => !alreadyMapped.has(t.id)).length;
              if (!count) return null;
              const active = tactic === ta.id;
              return (
                <button key={ta.id} onClick={() => setTactic(active ? null : ta.id)}
                  style={{ width: '100%', padding: '5px 8px', borderRadius: 5, textAlign: 'left',
                    fontFamily: 'monospace', fontSize: 10, cursor: 'pointer', marginTop: 2,
                    background: active ? `${ta.color}18` : 'transparent',
                    color: active ? ta.color : '#7d8590',
                    border: `1px solid ${active ? ta.color + '30' : 'transparent'}` }}>
                  <span style={{ display: 'block', fontWeight: active ? 700 : 400 }}>{ta.name}</span>
                  <span style={{ opacity: 0.6 }}>{count} techniques</span>
                </button>
              );
            })}
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
            <div style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', position: 'relative' }}>
              <Search size={12} style={{ position: 'absolute', left: 22, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Rechercher par ID ou nom…"
                style={{ width: '100%', paddingLeft: 28, paddingRight: 8, paddingTop: 5, paddingBottom: 5,
                  borderRadius: 6, fontFamily: 'monospace', fontSize: 11,
                  background: '#0d1117', border: '1px solid #30363d', color: '#e6edf3', outline: 'none' }} />
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
              {filtered.length === 0 && (
                <div style={{ textAlign: 'center', padding: 24, fontFamily: 'monospace', fontSize: 11, color: '#334155' }}>
                  Aucune technique disponible
                </div>
              )}
              {filtered.map(t => {
                const ta    = TACTIC_MAP[t.tactic];
                const isSel = selected?.id === t.id;
                return (
                  <div key={t.id} onClick={() => setSelected(isSel ? null : t)}
                    style={{ padding: '6px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 3,
                      background: isSel ? '#142030' : 'transparent',
                      border: `1px solid ${isSel ? '#4d82c040' : '#30363d'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
                        color: '#4a9ebb', minWidth: 80 }}>
                        {t.id}
                      </span>
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#d0daf0', flex: 1 }}>
                        {t.name}
                      </span>
                      {ta && (
                        <span style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9,
                          fontFamily: 'monospace', background: `${ta.color}18`,
                          color: ta.color, border: `1px solid ${ta.color}25`, flexShrink: 0 }}>
                          {ta.name}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {selected && (
          <div style={{ padding: '12px 18px', borderTop: '1px solid #30363d', background: '#0d1525' }}>
            <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#4d82c0', marginBottom: 10,
              display: 'flex', alignItems: 'center', gap: 6 }}>
              <Check size={12} /> {selected.id} — {selected.name}
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              
              <div>
                <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#3d5070',
                  marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                  Niveau de confiance
                </div>
                <div style={{ display: 'flex', gap: 5 }}>
                  {CONFIDENCE.map(c => (
                    <button key={c.key} onClick={() => setConf(c.key)}
                      style={{ padding: '3px 10px', borderRadius: 6, fontSize: 10, fontFamily: 'monospace',
                        cursor: 'pointer', fontWeight: 600,
                        background: confidence === c.key ? `${c.color}20` : 'transparent',
                        color: confidence === c.key ? c.color : '#334155',
                        border: `1px solid ${confidence === c.key ? c.color + '50' : '#30363d'}` }}>
                      {c.label}
                    </button>
                  ))}
                </div>
              </div>
              
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#3d5070',
                  marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                  Notes / Preuve
                </div>
                <input value={notes} onChange={e => setNotes(e.target.value)}
                  placeholder="Référence à une preuve, événement, log…"
                  style={{ width: '100%', padding: '5px 8px', borderRadius: 6, fontFamily: 'monospace', fontSize: 11,
                    background: '#0d1117', border: '1px solid #30363d', color: '#e6edf3', outline: 'none' }} />
              </div>
              
              <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: 4 }}>
                <div style={{ height: 20 }} />
                <button onClick={handleAdd} disabled={adding} className="fl-btn fl-btn-primary fl-btn-sm">
                  {adding ? '…' : '+ Ajouter'}
                </button>
              </div>
            </div>
            {error && (
              <div style={{ marginTop: 6, fontFamily: 'monospace', fontSize: 11, color: '#ef4444' }}>
                {error}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function TechRow({ tech, onDelete, onUpdate }) {
  const [editing, setEditing] = useState(false);
  const [notes, setNotes]     = useState(tech.notes || '');
  const [conf, setConf]       = useState(tech.confidence || 'medium');
  const [saving, setSaving]   = useState(false);
  const ta = TACTIC_MAP[tech.tactic];

  async function save() {
    setSaving(true);
    await onUpdate(tech.id, { confidence: conf, notes });
    setEditing(false);
    setSaving(false);
  }

  return (
    <div style={{ borderRadius: 7, border: '1px solid #30363d', marginBottom: 5,
      background: '#0d1525', overflow: 'hidden' }}>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
        borderLeft: `3px solid ${ta?.color || '#334155'}` }}>
        <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: '#4a9ebb', minWidth: 80 }}>
          {tech.technique_id}
        </span>
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#d0daf0', flex: 1 }}>
          {tech.technique_name}
        </span>
        {ta && (
          <span style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9, fontFamily: 'monospace',
            background: `${ta.color}15`, color: ta.color, border: `1px solid ${ta.color}25` }}>
            {ta.name}
          </span>
        )}
        <ConfBadge level={tech.confidence} />
        <button onClick={() => setEditing(v => !v)}
          style={{ background: 'none', border: 'none', cursor: 'pointer',
            color: editing ? '#4d82c0' : '#334155' }}>
          <Edit2 size={12} />
        </button>
        <button onClick={() => onDelete(tech.id)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#334155' }}>
          <Trash2 size={12} />
        </button>
      </div>

      {!editing && tech.notes && (
        <div style={{ padding: '3px 10px 5px 13px', fontFamily: 'monospace', fontSize: 10,
          color: '#4a6080', borderTop: '1px solid #1c2333' }}>
          {tech.notes}
        </div>
      )}

      {editing && (
        <div style={{ padding: '8px 12px', borderTop: '1px solid #30363d', background: '#0d1117' }}>
          <div style={{ display: 'flex', gap: 4, marginBottom: 6 }}>
            {CONFIDENCE.map(c => (
              <button key={c.key} onClick={() => setConf(c.key)}
                style={{ padding: '2px 8px', borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
                  cursor: 'pointer', fontWeight: 600,
                  background: conf === c.key ? `${c.color}20` : 'transparent',
                  color: conf === c.key ? c.color : '#334155',
                  border: `1px solid ${conf === c.key ? c.color + '50' : '#30363d'}` }}>
                {c.label}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <input value={notes} onChange={e => setNotes(e.target.value)}
              placeholder="Notes / référence preuve…"
              style={{ flex: 1, padding: '4px 8px', borderRadius: 5, fontFamily: 'monospace', fontSize: 10,
                background: '#111827', border: '1px solid #30363d', color: '#e6edf3', outline: 'none' }} />
            <button onClick={save} disabled={saving}
              style={{ padding: '4px 12px', borderRadius: 5, fontFamily: 'monospace', fontSize: 10,
                background: '#4d82c018', border: '1px solid #4d82c030', color: '#4d82c0', cursor: 'pointer' }}>
              {saving ? '…' : 'OK'}
            </button>
            <button onClick={() => setEditing(false)}
              style={{ padding: '4px 8px', borderRadius: 5, fontFamily: 'monospace', fontSize: 10,
                background: 'transparent', border: '1px solid #30363d', color: '#334155', cursor: 'pointer' }}>
              <X size={10} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function MitreAttackTab({ caseId }) {
  const [techniques, setTechniques] = useState([]);
  const [loading, setLoading]       = useState(true);
  const [showModal, setShowModal]   = useState(false);
  const [tacticFilter, setTacticFilter] = useState(null);
  const [collapsed, setCollapsed]   = useState({});

  useEffect(() => {
    load();
  }, [caseId]);

  async function load() {
    setLoading(true);
    try {
      const { data } = await mitreAPI.list(caseId);
      setTechniques(Array.isArray(data) ? data : []);
    } catch {
      setTechniques([]);
    }
    setLoading(false);
  }

  async function handleAdd(tech) {
    const { data } = await mitreAPI.add(caseId, {
      technique_id:      tech.id,
      tactic:            TACTIC_MAP[tech.tactic]?.name || tech.tactic,
      technique_name:    tech.name,
      sub_technique_name: null,
      confidence:        tech.confidence,
      notes:             tech.notes,
    });
    setTechniques(prev => [...prev, data]);
  }

  async function handleDelete(id) {
    await mitreAPI.remove(caseId, id);
    setTechniques(prev => prev.filter(t => t.id !== id));
  }

  async function handleUpdate(id, patch) {
    const { data } = await mitreAPI.update(caseId, id, patch);
    setTechniques(prev => prev.map(t => t.id === id ? data : t));
  }

  const grouped = useMemo(() => {
    const g = {};
    for (const t of techniques) {
      if (!g[t.tactic]) g[t.tactic] = [];
      g[t.tactic].push(t);
    }
    return g;
  }, [techniques]);

  const alreadyMapped = useMemo(() => new Set(techniques.map(t => t.technique_id)), [techniques]);

  const stats = useMemo(() => {
    const s = {};
    for (const t of techniques) s[t.confidence] = (s[t.confidence] || 0) + 1;
    return s;
  }, [techniques]);

  const tacticOrder = TACTICS.map(ta => ta.id).filter(id => grouped[id]);

  return (
    <div style={{ padding: '0 0 24px' }}>

      {showModal && (
        <TechniqueModal
          onAdd={handleAdd}
          onClose={() => setShowModal(false)}
          alreadyMapped={alreadyMapped}
        />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={16} style={{ color: '#4d82c0' }} />
          <span style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#e6edf3' }}>
            Cartographie MITRE ATT&amp;CK
          </span>
          {techniques.length > 0 && (
            <span style={{ fontFamily: 'monospace', fontSize: 11, padding: '2px 8px', borderRadius: 4,
              background: '#4d82c012', color: '#4d82c0', border: '1px solid #4d82c025' }}>
              {techniques.length} technique{techniques.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <button onClick={() => setShowModal(true)} className="fl-btn fl-btn-primary fl-btn-sm">
          <Plus size={13} /> Ajouter une technique
        </button>
      </div>

      {techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
          {CONFIDENCE.map(c => {
            const n = stats[c.key] || 0;
            if (!n) return null;
            return (
              <div key={c.key} style={{ padding: '6px 12px', borderRadius: 7,
                background: `${c.color}12`, border: `1px solid ${c.color}25`,
                display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 18, fontWeight: 700, color: c.color }}>{n}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 9, color: c.color, opacity: 0.8 }}>{c.label}</span>
              </div>
            );
          })}
          <div style={{ padding: '6px 12px', borderRadius: 7, background: '#111827',
            border: '1px solid #30363d', display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
            <span style={{ fontFamily: 'monospace', fontSize: 18, fontWeight: 700, color: '#7d8590' }}>
              {Object.keys(grouped).length}
            </span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#334155' }}>Tactiques</span>
          </div>
        </div>
      )}

      {techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 14 }}>
          <button onClick={() => setTacticFilter(null)}
            style={{ padding: '2px 10px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
              cursor: 'pointer', background: !tacticFilter ? '#4d82c018' : 'transparent',
              color: !tacticFilter ? '#4d82c0' : '#7d8590',
              border: `1px solid ${!tacticFilter ? '#4d82c030' : '#30363d'}` }}>
            Toutes
          </button>
          {tacticOrder.map(tacId => {
            const ta = TACTIC_MAP[tacId];
            const active = tacticFilter === tacId;
            return (
              <button key={tacId} onClick={() => setTacticFilter(active ? null : tacId)}
                style={{ padding: '2px 10px', borderRadius: 10, fontSize: 10, fontFamily: 'monospace',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                  background: active ? `${ta.color}18` : 'transparent',
                  color: active ? ta.color : '#7d8590',
                  border: `1px solid ${active ? ta.color + '30' : '#30363d'}` }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: ta.color, display: 'inline-block' }} />
                {ta.name}
                <span style={{ opacity: 0.6 }}>({grouped[tacId]?.length})</span>
              </button>
            );
          })}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, fontFamily: 'monospace', fontSize: 12, color: '#334155' }}>
          Chargement…
        </div>
      ) : techniques.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 48, borderRadius: 10,
          border: '1px dashed #30363d', background: '#0d1525' }}>
          <Shield size={40} style={{ color: '#30363d', margin: '0 auto 12px', display: 'block' }} />
          <p style={{ fontFamily: 'monospace', fontSize: 13, color: '#e6edf3', marginBottom: 6 }}>
            Aucune technique mappée
          </p>
          <p style={{ fontFamily: 'monospace', fontSize: 11, color: '#334155', marginBottom: 20 }}>
            Associez des techniques MITRE ATT&amp;CK aux artefacts observés dans ce cas.
          </p>
          <button onClick={() => setShowModal(true)} className="fl-btn fl-btn-primary fl-btn-sm">
            + Ajouter une première technique
          </button>
        </div>
      ) : (
        <div>
          {tacticOrder
            .filter(tid => !tacticFilter || tid === tacticFilter)
            .map(tacId => {
              const ta    = TACTIC_MAP[tacId];
              const techs = grouped[tacId] || [];
              const isColl = collapsed[tacId];
              return (
                <div key={tacId} style={{ marginBottom: 10, borderRadius: 8,
                  border: `1px solid ${ta.color}25`, overflow: 'hidden' }}>
                  
                  <button onClick={() => setCollapsed(prev => ({ ...prev, [tacId]: !prev[tacId] }))}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 12px', cursor: 'pointer', background: `${ta.color}12`,
                      border: 'none', borderBottom: isColl ? 'none' : `1px solid ${ta.color}20` }}>
                    {isColl ? <ChevronRight size={13} style={{ color: ta.color }} /> : <ChevronDown size={13} style={{ color: ta.color }} />}
                    <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: ta.color }}>
                      {ta.name}
                    </span>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: ta.color, opacity: 0.6 }}>
                      {techs.length} technique{techs.length > 1 ? 's' : ''}
                    </span>
                  </button>
                  
                  {!isColl && (
                    <div style={{ padding: 8, background: '#0d1117' }}>
                      {techs.map(t => (
                        <TechRow key={t.id} tech={t} onDelete={handleDelete} onUpdate={handleUpdate} />
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}
