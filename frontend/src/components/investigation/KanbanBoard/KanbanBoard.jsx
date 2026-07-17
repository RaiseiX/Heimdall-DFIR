import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Link2 as LinkIcon } from 'lucide-react';
import { investigationAPI } from '../../../utils/api';
import { STATUS_CYCLE, STATUS_COLOR, STATUS_LABEL_KEY, applyDrop } from '../investigationStatus';

export default function KanbanBoard({ caseId }) {
  const { t } = useTranslation();
  const [steps, setSteps]       = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading]   = useState(false);
  const [dragOver, setDragOver] = useState(null); // status column currently hovered during a drag

  // Same load-with-seed-fallback pattern as WorkflowTracker (load-on-mount, no live updates in v1).
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

  const findingTitle = new Map(findings.map(f => [f.id, f.title]));

  async function onDrop(e, targetStatus) {
    e.preventDefault();
    setDragOver(null);
    const draggedId = e.dataTransfer.getData('text/plain');
    if (!draggedId) return; // non-card / empty drop
    const { steps: next, changed } = applyDrop(steps, draggedId, targetStatus);
    if (!changed) return;   // unknown id or same-column drop -> no API call
    const dragged = steps.find(s => String(s.id) === String(changed.id));
    setSteps(next);         // optimistic
    try {
      // The backend PUT /steps/:id does NOT COALESCE finding_ref/assignee_id, so any
      // omitted field is overwritten with NULL. Forward the dragged step's current
      // values to keep its finding link (and assignee) intact across a status move.
      await investigationAPI.updateStep(caseId, changed.id, {
        status: changed.status,
        position: changed.position,
        finding_ref: dragged?.finding_ref ?? null,
        assignee_id: dragged?.assignee_id ?? null,
      });
    } catch {
      load();               // revert to server truth so the board never lies
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {t('investigation.workflow_title')}
        </span>
        <button onClick={load} style={{ background: 'none', border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer', padding: '3px 7px', color: 'var(--fl-subtle)' }}><RefreshCw size={11} /></button>
      </div>

      {loading && <div style={{ textAlign: 'center', color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, padding: 12 }}>{t('common.loading')}</div>}

      <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 6, alignItems: 'flex-start' }}>
        {STATUS_CYCLE.map(status => {
          const items = steps
            .filter(s => s.status === status)
            .sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
          const isOver = dragOver === status;
          return (
            <div
              key={status}
              onDragOver={e => { e.preventDefault(); setDragOver(status); }}
              onDragLeave={() => setDragOver(prev => (prev === status ? null : prev))}
              onDrop={e => onDrop(e, status)}
              style={{
                minWidth: 200, flex: '0 0 200px', borderRadius: 8, background: 'var(--fl-bg)',
                padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 6,
                border: `1px solid ${isOver ? 'var(--fl-accent)' : 'var(--fl-sep)'}`,
                outline: isOver ? '1px dashed color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'none',
                outlineOffset: -2, transition: 'border-color 0.1s',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0, background: STATUS_COLOR[status] || 'var(--fl-subtle)' }} />
                <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {t(STATUS_LABEL_KEY[status])}
                </span>
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>· {items.length}</span>
              </div>

              {items.map(s => (
                <div
                  key={s.id}
                  draggable
                  onDragStart={e => { e.dataTransfer.setData('text/plain', String(s.id)); e.dataTransfer.effectAllowed = 'move'; }}
                  style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: '5px 7px', borderRadius: 5, border: '1px solid var(--fl-sep)', background: '#0a1625', cursor: 'grab', userSelect: 'none' }}
                >
                  <span style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    {t('investigation.phase_' + s.phase, s.phase)}
                  </span>
                  <span style={{ fontSize: 10, color: s.status === 'done' ? 'var(--fl-muted)' : 'var(--fl-on-dark)', textDecoration: s.status === 'done' ? 'line-through' : 'none', lineHeight: 1.3 }}>{s.title}</span>
                  {s.finding_ref && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <LinkIcon size={9} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
                      <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {findingTitle.get(s.finding_ref) || ''}
                      </span>
                    </div>
                  )}
                </div>
              ))}

              {!items.length && (
                <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('investigation.no_steps')}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
