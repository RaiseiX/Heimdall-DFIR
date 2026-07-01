import { useState, useEffect } from 'react';
import { X, MessageSquare, RefreshCw } from 'lucide-react';
import { feedbackAPI } from '../utils/api';
import { useTheme } from '../utils/theme';
import { useTranslation } from 'react-i18next';

const STATUS_CONFIG = {
  open:        { key: 'feedback.status_open',        color: 'var(--fl-accent)' },
  in_progress: { key: 'feedback.status_in_progress', color: 'var(--fl-warn)' },
  resolved:    { key: 'feedback.status_resolved',    color: 'var(--fl-ok)' },
  closed:      { key: 'feedback.status_closed',      color: 'var(--fl-dim)' },
};

const TYPE_LABEL_KEYS = { bug: 'feedback.type_bug', suggestion: 'feedback.type_suggestion', autre: 'feedback.type_other' };

export default function FeedbackMyRequests({ onClose }) {
  const T = useTheme();
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const { data } = await feedbackAPI.mine();
      setRows(data || []);
    } catch { setRows([]); }
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9100,
      background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: T.panel, border: `1px solid ${T.border}`, borderRadius: 10,
        width: 640, maxWidth: '95vw', maxHeight: '80vh',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }} onClick={e => e.stopPropagation()}>
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderBottom: `1px solid ${T.border}`, flexShrink: 0,
        }}>
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, fontWeight: 700, color: T.text, display: 'flex', alignItems: 'center', gap: 7 }}>
            <MessageSquare size={14} style={{ color: T.accent }} /> {t('feedback.my_requests')}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={load} disabled={loading} style={{ background: 'none', border: `1px solid ${T.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: T.dim, display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} /> {t('feedback.refresh')}
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: T.muted }}>
              <X size={14} />
            </button>
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
          {loading && !rows.length && (
            <div style={{ textAlign: 'center', padding: '24px 0', color: T.muted, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
              {t('common.loading')}
            </div>
          )}
          {!loading && rows.length === 0 && (
            <div style={{ textAlign: 'center', padding: '24px 0', color: T.muted, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
              {t('feedback.empty_my_requests')}
            </div>
          )}
          {rows.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                  {[t('feedback.col_type'), t('feedback.col_title'), t('feedback.col_status'), t('feedback.col_admin_reply'), t('feedback.col_date')].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '5px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map(r => {
                  const sc = STATUS_CONFIG[r.status] || STATUS_CONFIG.open;
                  return (
                    <tr key={r.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                      <td style={{ padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: T.dim, whiteSpace: 'nowrap' }}>
                        {TYPE_LABEL_KEYS[r.type] ? t(TYPE_LABEL_KEYS[r.type]) : r.type}
                      </td>
                      <td style={{ padding: '6px 8px', color: T.text, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.title || r.description?.slice(0, 50) || '—'}
                      </td>
                      <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                        <span style={{
                          padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                          background: `color-mix(in srgb, ${sc.color} 9%, transparent)`, color: sc.color, border: `1px solid color-mix(in srgb, ${sc.color} 19%, transparent)`,
                        }}>
                          {t(sc.key)}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: T.dim, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.admin_reply || <span style={{ color: T.muted }}>—</span>}
                      </td>
                      <td style={{ padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, whiteSpace: 'nowrap' }}>
                        {new Date(r.created_at).toLocaleDateString(i18n.language)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
