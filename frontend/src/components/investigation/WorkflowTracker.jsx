import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2, RefreshCw, ListChecks, Link2 as LinkIcon } from 'lucide-react';
import { investigationAPI } from '../../utils/api';

const PHASE_ORDER = ['acquisition', 'examination', 'analysis', 'reporting'];
const STATUS_CYCLE = ['todo', 'doing', 'done', 'blocked'];
const STATUS_COLOR = { todo: 'var(--fl-subtle)', doing: 'var(--fl-gold)', done: 'var(--fl-ok)', blocked: 'var(--fl-danger)' };

export default function WorkflowTracker({ caseId }) {
  const { t } = useTranslation();
  const [steps, setSteps]   = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [addingTo, setAddingTo] = useState(null);   // phase id we're adding a task to
  const [draft, setDraft]   = useState('');
  const [err, setErr]       = useState('');

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      let res = await investigationAPI.get(caseId);
      if (!res.data?.steps?.length) {
        await investigationAPI.seed(caseId).catch(() => {});
        res = await investigationAPI.get(caseId);
      }
      setSteps(res.data?.steps || []);
      setFindings(res.data?.findings || []);
    } catch { setSteps([]); setFindings([]); }
    finally { setLoading(false); }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  async function linkFinding(step, findingRef) {
    const ref = findingRef || null;
    setSteps(s => s.map(x => x.id === step.id ? { ...x, finding_ref: ref } : x));
    try { await investigationAPI.updateStep(caseId, step.id, { finding_ref: ref }); } catch { load(); }
  }

  const findingTitle = new Map(findings.map(f => [f.id, f.title]));

  async function cycleStatus(step) {
    const next = STATUS_CYCLE[(STATUS_CYCLE.indexOf(step.status) + 1) % STATUS_CYCLE.length];
    setSteps(s => s.map(x => x.id === step.id ? { ...x, status: next } : x));
    try { await investigationAPI.updateStep(caseId, step.id, { status: next }); } catch { load(); }
  }

  async function addTask(phase) {
    if (!draft.trim()) { setAddingTo(null); setErr(''); return; }
    const pos = steps.filter(s => s.phase === phase).length;
    try {
      await investigationAPI.addStep(caseId, { phase, title: draft.trim(), position: pos });
      setDraft(''); setAddingTo(null); setErr('');
      await load();
    } catch (e) {
      // Keep the input open + preserve the draft so nothing is lost; surface why.
      const status = e?.response?.status;
      setErr(status === 404
        ? 'API investigation introuvable (404) — backend à reconstruire ?'
        : (e?.response?.data?.error || e.message || 'Échec de la création'));
    }
  }

  async function removeStep(id) {
    setSteps(s => s.filter(x => x.id !== id));
    try { await investigationAPI.removeStep(caseId, id); } catch { load(); }
  }

  const done = steps.filter(s => s.status === 'done').length;
  const pct = steps.length ? Math.round((done / steps.length) * 100) : 0;
  const phases = [...new Set([...PHASE_ORDER, ...steps.map(s => s.phase)])];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ListChecks size={13} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {t('investigation.workflow_title')}
          </span>
          {steps.length > 0 && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>· {done}/{steps.length} · {pct}%</span>}
        </div>
        <button onClick={load} style={{ background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer', padding: '3px 7px', color: 'var(--fl-subtle)' }}><RefreshCw size={11} /></button>
      </div>

      {steps.length > 0 && (
        <div style={{ height: 4, background: 'var(--fl-bg)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ height: '100%', borderRadius: 2, width: `${pct}%`, background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-ok))', transition: 'width 0.4s' }} />
        </div>
      )}

      {loading && <div style={{ textAlign: 'center', color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: 12 }}>{t('common.loading')}</div>}

      <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 6, alignItems: 'flex-start' }}>
        {phases.map(phase => {
          const items = steps.filter(s => s.phase === phase);
          return (
            <div key={phase} style={{ minWidth: 200, flex: '0 0 200px', border: '1px solid var(--fl-sep)', borderRadius: 8, background: 'var(--fl-bg)', padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {t('investigation.phase_' + phase, phase)}
                </span>
                <button onClick={() => { setAddingTo(phase); setDraft(''); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0 }}><Plus size={12} /></button>
              </div>

              {items.map(s => (
                <div key={s.id} style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: '5px 7px', borderRadius: 5, border: '1px solid var(--fl-sep)', background: '#0a1625' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <button onClick={() => cycleStatus(s)} title={t('investigation.status_' + s.status)} style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0, border: 'none', cursor: 'pointer', background: STATUS_COLOR[s.status] || 'var(--fl-subtle)' }} />
                    <span style={{ flex: 1, fontSize: 10, color: s.status === 'done' ? 'var(--fl-muted)' : 'var(--fl-on-dark)', textDecoration: s.status === 'done' ? 'line-through' : 'none', lineHeight: 1.3 }}>{s.title}</span>
                    <button onClick={() => removeStep(s.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 0, flexShrink: 0 }}><Trash2 size={10} /></button>
                  </div>
                  {findings.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, paddingLeft: 16 }}>
                      <LinkIcon size={9} style={{ color: s.finding_ref ? 'var(--fl-accent)' : 'var(--fl-muted)', flexShrink: 0 }} />
                      <select value={s.finding_ref || ''} onChange={e => linkFinding(s, e.target.value)}
                        title={s.finding_ref ? findingTitle.get(s.finding_ref) : ''}
                        style={{ flex: 1, minWidth: 0, background: 'transparent', border: 'none', outline: 'none', cursor: 'pointer',
                          color: s.finding_ref ? 'var(--fl-accent)' : 'var(--fl-muted)', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                        <option value="">{t('investigation.leads_to_none')}</option>
                        {findings.map(f => <option key={f.id} value={f.id}>{f.title}</option>)}
                      </select>
                    </div>
                  )}
                </div>
              ))}

              {!items.length && addingTo !== phase && (
                <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('investigation.no_steps')}</div>
              )}

              {addingTo === phase && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                  <input autoFocus value={draft} placeholder={t('investigation.task_ph')}
                    onChange={e => { setDraft(e.target.value); if (err) setErr(''); }}
                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTask(phase); } if (e.key === 'Escape') { setAddingTo(null); setErr(''); } }}
                    onBlur={() => { if (!draft.trim()) { setAddingTo(null); setErr(''); } }}
                    style={{ background: '#050c18', border: `1px solid ${err ? 'var(--fl-danger)' : 'var(--fl-card)'}`, borderRadius: 4, color: 'var(--fl-on-dark)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, padding: '4px 7px', outline: 'none', width: '100%', boxSizing: 'border-box' }} />
                  {err && <span style={{ fontSize: 9, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{err}</span>}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
