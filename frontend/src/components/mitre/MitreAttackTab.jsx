import { useState, useEffect, useMemo } from 'react';
import { Shield, Plus, X, Search, ChevronDown, ChevronRight, Trash2, Edit2, Check } from 'lucide-react';
import { TACTICS, TACTIC_MAP, TECHNIQUES } from '../../data/mitreData';
import { mitreAPI } from '../../utils/api';

const CONFIDENCE = [
  { key: 'confirmed', label: 'Confirmed', color: 'var(--fl-danger)' },
  { key: 'high',      label: 'High',      color: 'var(--fl-warn)' },
  { key: 'medium',    label: 'Medium',    color: 'var(--fl-gold)' },
  { key: 'low',       label: 'Low',       color: 'var(--fl-ok)' },
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
    <span style={{ padding: '1px 7px', borderRadius: 8, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      fontWeight: 700, background: `color-mix(in srgb, ${c.color} 13%, transparent)`, color: c.color, border: `1px solid color-mix(in srgb, ${c.color} 21%, transparent)` }}>
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
      setError(e.message || 'Error while adding');
      setAdding(false);
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 200, background: '#00000088',
      display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ width: 780, maxHeight: '85vh', background: 'var(--fl-bg)',
        border: '1px solid var(--fl-border)', borderRadius: 12, display: 'flex', flexDirection: 'column',
        boxShadow: '0 20px 60px #000' }}>

        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--fl-border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} style={{ color: 'var(--fl-accent)' }} />
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, fontWeight: 700, color: 'var(--fl-text)' }}>
              Select a MITRE ATT&CK technique
            </span>
          </div>
          <button onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)' }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
          
          <div style={{ width: 200, borderRight: '1px solid var(--fl-border)', overflowY: 'auto',
            padding: 8, flexShrink: 0 }}>
            <button onClick={() => setTactic(null)}
              style={{ width: '100%', padding: '5px 8px', borderRadius: 5, textAlign: 'left',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, cursor: 'pointer',
                background: !tactic ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
                color: !tactic ? 'var(--fl-accent)' : 'var(--fl-dim)',
                border: `1px solid ${!tactic ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'transparent'}` }}>
              All ({TECHNIQUES.filter(t => !alreadyMapped.has(t.id)).length})
            </button>
            {TACTICS.map(ta => {
              const count = (TECH_BY_TACTIC[ta.id] || []).filter(t => !alreadyMapped.has(t.id)).length;
              if (!count) return null;
              const active = tactic === ta.id;
              return (
                <button key={ta.id} onClick={() => setTactic(active ? null : ta.id)}
                  style={{ width: '100%', padding: '5px 8px', borderRadius: 5, textAlign: 'left',
                    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, cursor: 'pointer', marginTop: 2,
                    background: active ? `color-mix(in srgb, ${ta.color} 9%, transparent)` : 'transparent',
                    color: active ? ta.color : 'var(--fl-dim)',
                    border: `1px solid ${active ? ta.color + '30' : 'transparent'}` }}>
                  <span style={{ display: 'block', fontWeight: active ? 700 : 400 }}>{ta.name}</span>
                  <span style={{ opacity: 0.6 }}>{count} techniques</span>
                </button>
              );
            })}
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
            <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--fl-border)', position: 'relative' }}>
              <Search size={12} style={{ position: 'absolute', left: 22, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search by ID or name…"
                style={{ width: '100%', paddingLeft: 28, paddingRight: 8, paddingTop: 5, paddingBottom: 5,
                  borderRadius: 6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                  background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', outline: 'none' }} />
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
              {filtered.length === 0 && (
                <div style={{ textAlign: 'center', padding: 24, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)' }}>
                  No techniques available
                </div>
              )}
              {filtered.map(t => {
                const ta    = TACTIC_MAP[t.tactic];
                const isSel = selected?.id === t.id;
                return (
                  <div key={t.id} onClick={() => setSelected(isSel ? null : t)}
                    style={{ padding: '6px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 3,
                      background: isSel ? '#142030' : 'transparent',
                      border: `1px solid ${isSel ? 'color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'var(--fl-border)'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, fontWeight: 700,
                        color: '#4a9ebb', minWidth: 80 }}>
                        {t.id}
                      </span>
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: '#d0daf0', flex: 1 }}>
                        {t.name}
                      </span>
                      {ta && (
                        <span style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9,
                          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${ta.color} 9%, transparent)`,
                          color: ta.color, border: `1px solid color-mix(in srgb, ${ta.color} 15%, transparent)`, flexShrink: 0 }}>
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
          <div style={{ padding: '12px 18px', borderTop: '1px solid var(--fl-border)', background: 'var(--fl-bg)' }}>
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-accent)', marginBottom: 10,
              display: 'flex', alignItems: 'center', gap: 6 }}>
              <Check size={12} /> {selected.id} — {selected.name}
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              
              <div>
                <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-subtle)',
                  marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                  Confidence level
                </div>
                <div style={{ display: 'flex', gap: 5 }}>
                  {CONFIDENCE.map(c => (
                    <button key={c.key} onClick={() => setConf(c.key)}
                      style={{ padding: '3px 10px', borderRadius: 6, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        cursor: 'pointer', fontWeight: 600,
                        background: confidence === c.key ? `color-mix(in srgb, ${c.color} 13%, transparent)` : 'transparent',
                        color: confidence === c.key ? c.color : 'var(--fl-card)',
                        border: `1px solid ${confidence === c.key ? c.color + '50' : 'var(--fl-border)'}` }}>
                      {c.label}
                    </button>
                  ))}
                </div>
              </div>
              
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-subtle)',
                  marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                  Notes / Evidence
                </div>
                <input value={notes} onChange={e => setNotes(e.target.value)}
                  placeholder="Reference to evidence, event, log…"
                  style={{ width: '100%', padding: '5px 8px', borderRadius: 6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                    background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', outline: 'none' }} />
              </div>
              
              <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: 4 }}>
                <div style={{ height: 20 }} />
                <button onClick={handleAdd} disabled={adding} className="fl-btn fl-btn-primary fl-btn-sm">
                  {adding ? '…' : '+ Add'}
                </button>
              </div>
            </div>
            {error && (
              <div style={{ marginTop: 6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-danger)' }}>
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
  const [sig, setSig]         = useState(tech.significance || '');
  const [saving, setSaving]   = useState(false);
  const ta = TACTIC_MAP[tech.tactic];

  async function save() {
    setSaving(true);
    await onUpdate(tech.id, { confidence: conf, notes, significance: sig });
    setEditing(false);
    setSaving(false);
  }

  return (
    <div style={{ borderRadius: 7, border: '1px solid var(--fl-border)', marginBottom: 5,
      background: 'var(--fl-bg)', overflow: 'hidden' }}>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
        borderLeft: `3px solid ${ta?.color || 'var(--fl-card)'}` }}>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, fontWeight: 700, color: '#4a9ebb', minWidth: 80 }}>
          {tech.technique_id}
        </span>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: '#d0daf0', flex: 1 }}>
          {tech.technique_name}
        </span>
        {ta && (
          <span style={{ padding: '1px 6px', borderRadius: 8, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            background: `color-mix(in srgb, ${ta.color} 8%, transparent)`, color: ta.color, border: `1px solid color-mix(in srgb, ${ta.color} 15%, transparent)` }}>
            {ta.name}
          </span>
        )}
        <ConfBadge level={tech.confidence} />
        <button onClick={() => setEditing(v => !v)}
          style={{ background: 'none', border: 'none', cursor: 'pointer',
            color: editing ? 'var(--fl-accent)' : 'var(--fl-card)' }}>
          <Edit2 size={12} />
        </button>
        <button onClick={() => onDelete(tech.id)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)' }}>
          <Trash2 size={12} />
        </button>
      </div>

      {!editing && (tech.notes || tech.significance) && (
        <div style={{ padding: '3px 10px 5px 13px', borderTop: '1px solid #1c2333', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {tech.notes && (
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: '#4a6080' }}>{tech.notes}</div>
          )}
          {tech.significance && (
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-subtle)', fontStyle: 'italic' }}>
              → {tech.significance}
            </div>
          )}
        </div>
      )}

      {editing && (
        <div style={{ padding: '8px 12px', borderTop: '1px solid var(--fl-border)', background: 'var(--fl-bg)' }}>
          <div style={{ display: 'flex', gap: 4, marginBottom: 6 }}>
            {CONFIDENCE.map(c => (
              <button key={c.key} onClick={() => setConf(c.key)}
                style={{ padding: '2px 8px', borderRadius: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  cursor: 'pointer', fontWeight: 600,
                  background: conf === c.key ? `color-mix(in srgb, ${c.color} 13%, transparent)` : 'transparent',
                  color: conf === c.key ? c.color : 'var(--fl-card)',
                  border: `1px solid ${conf === c.key ? c.color + '50' : 'var(--fl-border)'}` }}>
                {c.label}
              </button>
            ))}
          </div>
          <input value={sig} onChange={e => setSig(e.target.value)}
            placeholder="Analytical significance (so what?)…"
            style={{ width: '100%', boxSizing: 'border-box', marginBottom: 6, padding: '4px 8px', borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
              background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', outline: 'none' }} />
          <div style={{ display: 'flex', gap: 6 }}>
            <input value={notes} onChange={e => setNotes(e.target.value)}
              placeholder="Notes / evidence reference…"
              style={{ flex: 1, padding: '4px 8px', borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', outline: 'none' }} />
            <button onClick={save} disabled={saving}
              style={{ padding: '4px 12px', borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)', color: 'var(--fl-accent)', cursor: 'pointer' }}>
              {saving ? '…' : 'OK'}
            </button>
            <button onClick={() => setEditing(false)}
              style={{ padding: '4px 8px', borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                background: 'transparent', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer' }}>
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
          <Shield size={16} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, fontWeight: 700, color: 'var(--fl-text)' }}>
            Cartographie MITRE ATT&amp;CK
          </span>
          {techniques.length > 0 && (
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: '2px 8px', borderRadius: 4,
              background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>
              {techniques.length} technique{techniques.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <button onClick={() => setShowModal(true)} className="fl-btn fl-btn-primary fl-btn-sm">
          <Plus size={13} /> Add a technique
        </button>
      </div>

      {techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
          {CONFIDENCE.map(c => {
            const n = stats[c.key] || 0;
            if (!n) return null;
            return (
              <div key={c.key} style={{ padding: '6px 12px', borderRadius: 7,
                background: `color-mix(in srgb, ${c.color} 7%, transparent)`, border: `1px solid color-mix(in srgb, ${c.color} 15%, transparent)`,
                display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 18, fontWeight: 700, color: c.color }}>{n}</span>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: c.color, opacity: 0.8 }}>{c.label}</span>
              </div>
            );
          })}
          <div style={{ padding: '6px 12px', borderRadius: 7, background: 'var(--fl-bg)',
            border: '1px solid var(--fl-border)', display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 18, fontWeight: 700, color: 'var(--fl-dim)' }}>
              {Object.keys(grouped).length}
            </span>
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-muted)' }}>Tactiques</span>
          </div>
        </div>
      )}

      {techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 14 }}>
          <button onClick={() => setTacticFilter(null)}
            style={{ padding: '2px 10px', borderRadius: 10, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              cursor: 'pointer', background: !tacticFilter ? 'color-mix(in srgb, var(--fl-accent) 9%, transparent)' : 'transparent',
              color: !tacticFilter ? 'var(--fl-accent)' : 'var(--fl-dim)',
              border: `1px solid ${!tacticFilter ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'var(--fl-border)'}` }}>
            All
          </button>
          {tacticOrder.map(tacId => {
            const ta = TACTIC_MAP[tacId];
            const active = tacticFilter === tacId;
            return (
              <button key={tacId} onClick={() => setTacticFilter(active ? null : tacId)}
                style={{ padding: '2px 10px', borderRadius: 10, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                  background: active ? `color-mix(in srgb, ${ta.color} 9%, transparent)` : 'transparent',
                  color: active ? ta.color : 'var(--fl-dim)',
                  border: `1px solid ${active ? ta.color + '30' : 'var(--fl-border)'}` }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: ta.color, display: 'inline-block' }} />
                {ta.name}
                <span style={{ opacity: 0.6 }}>({grouped[tacId]?.length})</span>
              </button>
            );
          })}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: 'var(--fl-muted)' }}>
          Loading…
        </div>
      ) : techniques.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 48, borderRadius: 10,
          border: '1px dashed var(--fl-border)', background: 'var(--fl-bg)' }}>
          <Shield size={40} style={{ color: 'var(--fl-border)', margin: '0 auto 12px', display: 'block' }} />
          <p style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: 'var(--fl-text)', marginBottom: 6 }}>
            No mapped techniques
          </p>
          <p style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)', marginBottom: 20 }}>
            Map MITRE ATT&amp;CK techniques to artifacts observed in this case.
          </p>
          <button onClick={() => setShowModal(true)} className="fl-btn fl-btn-primary fl-btn-sm">
            + Add the first technique
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
                  border: `1px solid color-mix(in srgb, ${ta.color} 15%, transparent)`, overflow: 'hidden' }}>
                  
                  <button onClick={() => setCollapsed(prev => ({ ...prev, [tacId]: !prev[tacId] }))}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 12px', cursor: 'pointer', background: `color-mix(in srgb, ${ta.color} 7%, transparent)`,
                      border: 'none', borderBottom: isColl ? 'none' : `1px solid color-mix(in srgb, ${ta.color} 13%, transparent)` }}>
                    {isColl ? <ChevronRight size={13} style={{ color: ta.color }} /> : <ChevronDown size={13} style={{ color: ta.color }} />}
                    <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: ta.color }}>
                      {ta.name}
                    </span>
                    <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: ta.color, opacity: 0.6 }}>
                      {techs.length} technique{techs.length > 1 ? 's' : ''}
                    </span>
                  </button>
                  
                  {!isColl && (
                    <div style={{ padding: 8, background: 'var(--fl-bg)' }}>
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
