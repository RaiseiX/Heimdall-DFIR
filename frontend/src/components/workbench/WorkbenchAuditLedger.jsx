import { useEffect, useState, useMemo } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw, ChevronRight, ChevronDown, FileSearch } from 'lucide-react';
import { workbenchPinsAPI } from '../../utils/api';

const ACTION_COLORS = {
  pin:    { bg: '#22c55e20', fg: 'var(--fl-ok, #22c55e)' },
  update: { bg: '#1c6ef220', fg: 'var(--fl-accent)' },
  unpin:  { bg: '#ef444420', fg: 'var(--fl-danger)' },
  clear:  { bg: '#ef444430', fg: 'var(--fl-danger)' },
  import: { bg: '#c9689820', fg: 'var(--fl-purple, #c96898)' },
};

function fmtUtc(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
  } catch { return String(ts); }
}

export default function WorkbenchAuditLedger({ caseId }) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [expanded, setExpanded] = useState({});

  const load = async () => {
    setLoading(true); setErr(null);
    try {
      const res = await workbenchPinsAPI.audit(caseId);
      const body = res?.data || res;
      setData(body);
    } catch (e) {
      setErr(e?.response?.data?.error || e?.message || 'Erreur de chargement');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [caseId]);

  const verifyColor = !data ? 'var(--fl-dim)' : data.verified ? 'var(--fl-ok, #22c55e)' : 'var(--fl-danger)';
  const VerifyIcon = data?.verified ? ShieldCheck : ShieldAlert;

  const actorCount = useMemo(() => {
    if (!data?.entries) return 0;
    return new Set(data.entries.map(e => e.actor_id).filter(Boolean)).size;
  }, [data]);

  return (
    <div style={{ fontFamily: 'monospace' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', marginBottom: 10,
        background: 'var(--fl-bg)', border: `1px solid ${verifyColor}60`, borderLeft: `3px solid ${verifyColor}`, borderRadius: 6,
      }}>
        <VerifyIcon size={16} style={{ color: verifyColor }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--fl-on-dark)', marginBottom: 2 }}>
            {loading ? 'Vérification de la chaîne…' : data?.verified ? 'Chaîne de preuve vérifiée' : (err ? 'Erreur de chargement' : 'CHAÎNE ALTÉRÉE')}
          </div>
          <div style={{ fontSize: 10, color: 'var(--fl-dim)' }}>
            {err ? err : data ? (
              data.verified
                ? `${data.count} opération(s) · ${actorCount} analyste(s) · hash chain SHA-256 intact`
                : `Rupture détectée au seq #${data.broken_at} — exportez immédiatement le ledger pour investigation`
            ) : '…'}
          </div>
        </div>
        <button onClick={load} disabled={loading} title="Rafraîchir le ledger"
          style={{
            display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', fontSize: 10,
            background: 'var(--fl-card)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)',
            borderRadius: 4, cursor: loading ? 'wait' : 'pointer', fontFamily: 'monospace', opacity: loading ? 0.6 : 1,
          }}>
          <RefreshCw size={11} style={{ transform: loading ? 'rotate(180deg)' : 'none', transition: 'transform 0.3s' }} /> Vérifier
        </button>
        <button onClick={() => {
            if (!data) return;
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `workbench-audit-${caseId}-${Date.now()}.json`;
            a.click(); URL.revokeObjectURL(url);
          }}
          disabled={!data || loading}
          title="Exporter le ledger complet (JSON)"
          style={{
            display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', fontSize: 10,
            background: 'var(--fl-card)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)',
            borderRadius: 4, cursor: 'pointer', fontFamily: 'monospace',
          }}>
          <FileSearch size={11} /> Exporter
        </button>
      </div>

      {data?.entries?.length === 0 && (
        <div style={{ padding: '32px 20px', textAlign: 'center', color: 'var(--fl-dim)', fontSize: 11, border: '1px dashed var(--fl-sep)', borderRadius: 8 }}>
          Aucune opération enregistrée. Chaque pin / modification sera horodatée et liée par hash ici.
        </div>
      )}

      {data?.entries && data.entries.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {[...data.entries].reverse().map(e => {
            const ac = ACTION_COLORS[e.action] || { bg: 'var(--fl-card)', fg: 'var(--fl-dim)' };
            const isBroken = data.broken_at != null && e.seq >= data.broken_at;
            const isOpen = expanded[e.seq];
            return (
              <div key={e.seq} style={{
                background: 'var(--fl-bg)', border: `1px solid ${isBroken ? 'var(--fl-danger)' : 'var(--fl-card)'}`,
                borderLeft: `2px solid ${ac.fg}`, borderRadius: 4,
              }}>
                <div onClick={() => setExpanded(prev => ({ ...prev, [e.seq]: !prev[e.seq] }))}
                  style={{ padding: '5px 10px', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 10 }}>
                  {isOpen ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                  <span style={{ color: 'var(--fl-dim)', width: 40 }}>#{e.seq}</span>
                  <span style={{
                    padding: '1px 7px', borderRadius: 3, background: ac.bg, color: ac.fg,
                    fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', fontSize: 9,
                  }}>
                    {e.action}
                  </span>
                  <span style={{ color: 'var(--fl-on-dark)' }}>{e.actor_name || `user ${e.actor_id || '?'}`}</span>
                  <span style={{ marginLeft: 'auto', color: 'var(--fl-dim)' }}>{fmtUtc(e.created_at)}</span>
                  <span title={e.content_hash} style={{
                    fontFamily: 'monospace', color: isBroken ? 'var(--fl-danger)' : 'var(--fl-gold)',
                    fontSize: 9,
                  }}>
                    {String(e.content_hash || '').slice(0, 12)}…
                  </span>
                </div>
                {isOpen && (
                  <div style={{ padding: '8px 12px 10px 32px', borderTop: '1px solid var(--fl-card)', fontSize: 10, color: 'var(--fl-on-dark)' }}>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ color: 'var(--fl-dim)' }}>pin_id: </span>
                      <code style={{ color: 'var(--fl-accent)' }}>{e.pin_id}</code>
                    </div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ color: 'var(--fl-dim)' }}>prev_hash: </span>
                      <code style={{ color: 'var(--fl-dim)' }}>{e.prev_hash || '(genesis)'}</code>
                    </div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ color: 'var(--fl-dim)' }}>content_hash: </span>
                      <code style={{ color: isBroken ? 'var(--fl-danger)' : 'var(--fl-gold)' }}>{e.content_hash}</code>
                    </div>
                    <div style={{ marginTop: 6, color: 'var(--fl-dim)' }}>payload:</div>
                    <pre style={{
                      margin: '4px 0 0', padding: '6px 8px', background: 'var(--fl-card)', borderRadius: 3,
                      fontSize: 10, overflow: 'auto', maxHeight: 260, wordBreak: 'break-all', whiteSpace: 'pre-wrap',
                      color: 'var(--fl-on-dark)',
                    }}>
                      {(() => {
                        try { return JSON.stringify(typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload, null, 2); }
                        catch { return String(e.payload); }
                      })()}
                    </pre>
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
