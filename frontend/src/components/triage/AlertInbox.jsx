import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { UserPlus, X, Trash2, ChevronRight, Inbox as InboxIcon } from 'lucide-react';
import { triageAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, "Inter", sans-serif)';

const SEV = {
  critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)',
  low: 'var(--fl-purple)', info: 'var(--fl-muted)',
};
const STATUSES = ['new', 'in_progress', 'resolved', 'dismissed'];

function age(ts) {
  if (!ts) return '';
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export default function AlertInbox() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const me = (() => { try { return JSON.parse(localStorage.getItem('heimdall_user') || '{}'); } catch { return {}; } })();
  const isAdmin = me.role === 'admin';

  const [status, setStatus]   = useState('new');
  const [severity, setSev]    = useState('');
  const [q, setQ]             = useState('');
  const [data, setData]       = useState({ results: [], total: 0 });
  const [stats, setStats]     = useState({ byStatus: {}, open: 0 });
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy]       = useState('');
  const limit = 50;

  const loadStats = useCallback(() => { triageAPI.alertStats().then(r => setStats(r.data)).catch(() => {}); }, []);
  const load = useCallback(() => {
    setLoading(true);
    triageAPI.alerts({ status, severity: severity || undefined, q: q || undefined, page, limit })
      .then(r => setData(r.data))
      .catch(() => setData({ results: [], total: 0 }))
      .finally(() => setLoading(false));
  }, [status, severity, q, page]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => { const id = setTimeout(load, 350); return () => clearTimeout(id); }, [q]); // debounce search

  const after = () => { load(); loadStats(); };

  const setAlertStatus = async (a, st) => { setBusy(a.id); try { await triageAPI.updateAlert(a.id, { status: st }); after(); } finally { setBusy(''); } };
  const assignMe = async (a) => { setBusy(a.id); try { await triageAPI.updateAlert(a.id, { assignee: me.id }); after(); } finally { setBusy(''); } };
  const dismiss = async (a) => {
    const reason = prompt(t('triage.inbox.dismiss_prompt'));
    if (reason === null) return;
    setBusy(a.id); try { await triageAPI.dismissAlert(a.id, { reason }); after(); } finally { setBusy(''); }
  };
  const remove = async (a) => {
    if (!confirm(t('triage.inbox.delete_confirm'))) return;
    setBusy(a.id); try { await triageAPI.deleteAlert(a.id); after(); } finally { setBusy(''); }
  };

  const totalPages = Math.max(1, Math.ceil(data.total / limit));

  return (
    <div>
      {/* Status tabs */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
        {STATUSES.map(s => {
          const active = status === s;
          const n = stats.byStatus?.[s] ?? 0;
          return (
            <button key={s} onClick={() => { setStatus(s); setPage(1); }}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 7, cursor: 'pointer', fontFamily: MONO, fontSize: 11.5,
                background: active ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
                color: active ? 'var(--fl-text)' : 'var(--fl-muted)',
                border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 45%, transparent)' : 'var(--fl-border)'}` }}>
              {t(`triage.inbox.status.${s}`)}
              <span style={{ fontSize: 10, color: active ? 'var(--fl-accent)' : 'var(--fl-subtle)' }}>{n}</span>
            </button>
          );
        })}
        <span style={{ flex: 1 }} />
        <select value={severity} onChange={e => { setSev(e.target.value); setPage(1); }}
          style={{ padding: '6px 10px', borderRadius: 7, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11.5 }}>
          <option value="">{t('triage.inbox.all_sev')}</option>
          {Object.keys(SEV).map(s => <option key={s} value={s}>{t(`triage.severity.${s}`)}</option>)}
        </select>
        <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }} placeholder={t('triage.inbox.search_ph')}
          style={{ padding: '6px 10px', borderRadius: 7, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11.5, width: 200 }} />
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[0,1,2,3].map(i => <div key={i} className="fl-skeleton" style={{ height: 56, borderRadius: 8, background: 'var(--fl-card)' }} />)}
        </div>
      ) : data.results.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '56px 16px', gap: 10 }}>
          <InboxIcon size={26} strokeWidth={1.6} style={{ color: 'var(--fl-muted)' }} />
          <span style={{ fontSize: 13, fontFamily: MONO, color: 'var(--fl-muted)' }}>{t('triage.inbox.empty')}</span>
        </div>
      ) : (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
          {data.results.map((a, i) => (
            <div key={a.id}
              style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', alignItems: 'center', gap: 12, padding: '11px 14px',
                borderLeft: `3px solid ${SEV[a.severity] || 'var(--fl-muted)'}`,
                borderBottom: i < data.results.length - 1 ? '1px solid var(--fl-border2)' : 'none',
                opacity: busy === a.id ? 0.5 : 1 }}>
              <span style={{ fontSize: 9, fontFamily: MONO, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: SEV[a.severity] || 'var(--fl-muted)', width: 56 }}>{t(`triage.severity.${a.severity}`)}</span>

              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, color: 'var(--fl-text)', fontFamily: UI, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.title}{a.hit_count > 1 && <span style={{ marginLeft: 6, fontSize: 10, fontFamily: MONO, color: 'var(--fl-warn)' }}>×{a.hit_count}</span>}
                </div>
                <div style={{ fontSize: 10.5, color: 'var(--fl-muted)', fontFamily: MONO, marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ color: 'var(--fl-accent)' }}>{a.source}</span>
                  {a.entity_value && <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 260, whiteSpace: 'nowrap' }}>{a.entity_type ? `${a.entity_type}:` : ''}{a.entity_value}</span>}
                  {a.case_number && <span>· {a.case_number}</span>}
                  <span>· {age(a.last_seen || a.created_at)}</span>
                  {a.assignee_name && <span>· 👤 {a.assignee_name}</span>}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
                {!a.assignee && (status === 'new' || status === 'in_progress') && (
                  <button onClick={() => assignMe(a)} title={t('triage.inbox.assign_me')} style={iconBtn}><UserPlus size={13} /></button>
                )}
                {(status === 'new' || status === 'in_progress') && (
                  <select value={a.status} onChange={e => setAlertStatus(a, e.target.value)}
                    style={{ padding: '3px 6px', borderRadius: 5, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 10.5 }}>
                    {STATUSES.map(s => <option key={s} value={s}>{t(`triage.inbox.status.${s}`)}</option>)}
                  </select>
                )}
                {a.status !== 'dismissed' && (
                  <button onClick={() => dismiss(a)} title={t('triage.inbox.dismiss')} style={iconBtn}><X size={13} /></button>
                )}
                {a.case_id && (
                  <button onClick={() => navigate(`/cases/${a.case_id}`)} title={t('triage.action_open_case')} style={{ ...iconBtn, color: 'var(--fl-accent)' }}><ChevronRight size={14} /></button>
                )}
                {isAdmin && (
                  <button onClick={() => remove(a)} title={t('common.delete')} style={{ ...iconBtn, color: 'var(--fl-danger)' }}><Trash2 size={12} /></button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, marginTop: 14, fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-muted)' }}>
          <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} style={pageBtn}>‹</button>
          {page} / {totalPages}
          <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)} style={pageBtn}>›</button>
        </div>
      )}
    </div>
  );
}

const iconBtn = { display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: '4px 6px', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', borderRadius: 5, cursor: 'pointer' };
const pageBtn = { padding: '3px 9px', background: 'transparent', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 5, cursor: 'pointer' };
