import { useState, useEffect } from 'react';
import { X, MessageSquare, RefreshCw } from 'lucide-react';
import { feedbackAPI } from '../utils/api';
import { useTheme } from '../utils/theme';

const STATUS_CONFIG = {
  open:        { label: 'Ouvert',      color: 'var(--fl-accent)' },
  in_progress: { label: 'En cours',    color: 'var(--fl-warn)' },
  resolved:    { label: 'Résolu',      color: 'var(--fl-ok)' },
  closed:      { label: 'Fermé',       color: 'var(--fl-dim)' },
};

const TYPE_LABELS = { bug: '🐛 Bug', suggestion: '💡 Suggestion', autre: '📝 Autre' };

export default function FeedbackMyRequests({ onClose }) {
  const T = useTheme();
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
          <span style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: T.text, display: 'flex', alignItems: 'center', gap: 7 }}>
            <MessageSquare size={14} style={{ color: T.accent }} /> Mes demandes
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={load} disabled={loading} style={{ background: 'none', border: `1px solid ${T.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: T.dim, display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, fontFamily: 'monospace' }}>
              <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} /> Actualiser
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: T.muted }}>
              <X size={14} />
            </button>
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
          {loading && !rows.length && (
            <div style={{ textAlign: 'center', padding: '24px 0', color: T.muted, fontFamily: 'monospace', fontSize: 12 }}>
              Chargement…
            </div>
          )}
          {!loading && rows.length === 0 && (
            <div style={{ textAlign: 'center', padding: '24px 0', color: T.muted, fontFamily: 'monospace', fontSize: 12 }}>
              Vous n'avez soumis aucune demande pour l'instant.
            </div>
          )}
          {rows.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                  {['Type', 'Titre', 'Statut', 'Réponse admin', 'Date'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '5px 8px', fontFamily: 'monospace', fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map(r => {
                  const sc = STATUS_CONFIG[r.status] || STATUS_CONFIG.open;
                  return (
                    <tr key={r.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: T.dim, whiteSpace: 'nowrap' }}>
                        {TYPE_LABELS[r.type] || r.type}
                      </td>
                      <td style={{ padding: '6px 8px', color: T.text, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.title || r.description?.slice(0, 50) || '—'}
                      </td>
                      <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                        <span style={{
                          padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
                          background: `${sc.color}18`, color: sc.color, border: `1px solid ${sc.color}30`,
                        }}>
                          {sc.label}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: T.dim, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.admin_reply || <span style={{ color: T.muted }}>—</span>}
                      </td>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace', fontSize: 10, color: T.muted, whiteSpace: 'nowrap' }}>
                        {new Date(r.created_at).toLocaleDateString('fr-FR')}
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
