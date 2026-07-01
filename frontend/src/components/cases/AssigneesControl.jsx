import { useState, useEffect, useRef, useCallback } from 'react';
import { UserPlus, X } from 'lucide-react';
import { casesAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const initials = (u) => (u.full_name || u.username || '?').split(/\s+/).map(s => s[0]).slice(0, 2).join('').toUpperCase();

// Case assignment chip-bar. Read-only for analysts; admin / team lead can add/remove.
export default function AssigneesControl({ caseId, user }) {
  const canManage = user?.role === 'admin' || user?.role === 'team_lead';
  const [assignees, setAssignees] = useState([]);
  const [pool, setPool] = useState([]);
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  const load = useCallback(() => {
    casesAPI.assignees(caseId).then(r => setAssignees(r.data.assignees || [])).catch(() => {});
  }, [caseId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!open) return;
    if (canManage && !pool.length) casesAPI.assignableUsers().then(r => setPool(r.data.users || [])).catch(() => {});
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open, canManage, pool.length]);

  const add = async (uid) => { try { await casesAPI.assignUser(caseId, uid); load(); } catch { /* ignore */ } };
  const remove = async (uid) => { try { await casesAPI.unassignUser(caseId, uid); load(); } catch { /* ignore */ } };

  const assignedIds = new Set(assignees.map(a => a.id));

  return (
    <div ref={ref} style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {assignees.slice(0, 4).map((a, i) => (
          <span key={a.id} title={`${a.full_name || a.username}${a.role === 'team_lead' ? ' · team lead' : ''}`}
            style={{ width: 22, height: 22, borderRadius: 5, marginLeft: i ? -6 : 0, background: 'var(--fl-raised)',
              border: '1px solid var(--fl-border)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: MONO, fontSize: 9, fontWeight: 700, color: 'var(--fl-dim)' }}>
            {initials(a)}
          </span>
        ))}
        {assignees.length > 4 && (
          <span style={{ marginLeft: -6, width: 22, height: 22, borderRadius: 5, background: 'var(--fl-card)', border: '1px solid var(--fl-border)',
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontFamily: MONO, fontSize: 9, color: 'var(--fl-muted)' }}>
            +{assignees.length - 4}
          </span>
        )}
      </div>
      {canManage && (
        <button onClick={() => setOpen(v => !v)} title="Manage assigned analysts"
          style={{ width: 22, height: 22, borderRadius: 5, background: open ? 'var(--fl-card)' : 'transparent',
            border: `1px solid ${open ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
            color: open ? 'var(--fl-accent)' : 'var(--fl-muted)', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
          <UserPlus size={12} />
        </button>
      )}
      {open && canManage && (
        <div style={{ position: 'absolute', right: 0, top: '120%', zIndex: 2000, width: 260, maxHeight: 320, overflowY: 'auto',
          background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, boxShadow: 'var(--fl-shadow-lg)', padding: 6 }}>
          <div style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', padding: '4px 6px 8px' }}>
            Assigned analysts
          </div>
          {pool.map(u => {
            const on = assignedIds.has(u.id);
            return (
              <button key={u.id} onClick={() => (on ? remove(u.id) : add(u.id))}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left', padding: '6px 6px', borderRadius: 6,
                  background: on ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent', border: 'none', cursor: 'pointer', marginBottom: 2 }}>
                <span style={{ width: 20, height: 20, borderRadius: 5, background: 'var(--fl-raised)', border: '1px solid var(--fl-border)',
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontFamily: MONO, fontSize: 8.5, fontWeight: 700, color: 'var(--fl-dim)' }}>
                  {initials(u)}
                </span>
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ display: 'block', fontSize: 12, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.full_name || u.username}</span>
                  <span style={{ display: 'block', fontSize: 9.5, fontFamily: MONO, color: 'var(--fl-muted)' }}>{u.role === 'team_lead' ? 'team lead' : u.role}</span>
                </span>
                {on
                  ? <X size={13} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
                  : <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-accent)', flexShrink: 0 }}>+</span>}
              </button>
            );
          })}
          {!pool.length && <div style={{ fontSize: 11, color: 'var(--fl-muted)', padding: 8 }}>Loading…</div>}
        </div>
      )}
    </div>
  );
}
