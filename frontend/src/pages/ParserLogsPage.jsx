import { useState, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import { FileText, ChevronDown, ChevronRight, RefreshCw, AlertCircle, CheckCircle2, AlertTriangle } from 'lucide-react';
import { useTheme } from '../utils/theme';
import apiClient from '../utils/api';

const STATUS_CONFIG = {
  ok:       { label: 'OK',       color: 'var(--fl-ok)',     icon: CheckCircle2 },
  degraded: { label: 'Dégradé',  color: 'var(--fl-warn)',   icon: AlertTriangle },
  error:    { label: 'Erreur',   color: 'var(--fl-danger)', icon: AlertCircle },
};

function deriveStatus(parseResults = []) {
  if (!parseResults.length) return 'ok';
  if (parseResults.some(r => r.status === 'error')) return 'error';
  if (parseResults.some(r => r.status === 'degraded')) return 'degraded';
  return 'ok';
}

function fmtDuration(parsed_at, updated_at) {
  if (!parsed_at || !updated_at) return '—';
  const ms = new Date(updated_at) - new Date(parsed_at);
  if (ms < 0) return '—';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms/1000).toFixed(1)}s`;
  return `${Math.round(ms/60000)}min`;
}

export default function ParserLogsPage() {
  const T = useTheme();
  const ctx = useOutletContext() || {};
  const { caseId, collectionId } = ctx;

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(new Set());
  const [error, setError] = useState(null);

  async function load() {
    if (!caseId) return;
    setLoading(true); setError(null);
    try {
      const params = collectionId ? `?evidence_id=${collectionId}` : '';
      const { data } = await apiClient.get(`/collection/${caseId}/parser-results${params}`);
      setRows(data || []);
    } catch (e) {
      setError(e.response?.data?.error || 'Erreur de chargement');
      setRows([]);
    }
    setLoading(false);
  }

  useEffect(() => { load(); }, [caseId, collectionId]);

  function toggleExpand(id) {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  return (
    <div style={{ padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <FileText size={16} style={{ color: T.accent }} />
        <h2 style={{ margin: 0, fontFamily: 'monospace', fontSize: 14, color: T.text }}>
          Logs de Parsing
        </h2>
        <button
          onClick={load}
          disabled={loading}
          style={{
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5,
            background: 'none', border: `1px solid ${T.border}`, borderRadius: 5,
            padding: '3px 10px', cursor: 'pointer', fontSize: 11, fontFamily: 'monospace',
            color: T.dim,
          }}
        >
          <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          Actualiser
        </button>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: 6, marginBottom: 12,
          background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)',
          border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)',
          fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'monospace' }}>
          {error}
        </div>
      )}

      {!loading && rows.length === 0 && !error && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: T.muted, fontFamily: 'monospace', fontSize: 12 }}>
          Aucun job de parsing trouvé pour cette collecte.
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {rows.map(row => {
          const raw = row.output_data?.parse_results;
          const parseResults = Array.isArray(raw)
            ? raw
            : raw && typeof raw === 'object'
              ? Object.entries(raw).map(([key, val]) => ({
                  parser: val.name || key,
                  status: val.status === 'success' ? 'ok' : (val.status || 'ok'),
                  record_count: val.normalized_records ?? val.record_count ?? val.count,
                  error: val.error || val.tool_output || null,
                  warning: val.warning || null,
                }))
              : [];
          const status = deriveStatus(parseResults);
          const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.ok;
          const isExpanded = expanded.has(row.id);
          const Icon = cfg.icon;

          return (
            <div key={row.id} style={{
              borderRadius: 8, border: `1px solid ${T.border}`,
              background: T.panel, overflow: 'hidden',
            }}>
              
              <div
                onClick={() => toggleExpand(row.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '8px 12px', cursor: 'pointer',
                  borderLeft: `3px solid ${cfg.color}`,
                }}
              >
                {isExpanded ? <ChevronDown size={13} style={{ color: T.muted, flexShrink: 0 }} /> : <ChevronRight size={13} style={{ color: T.muted, flexShrink: 0 }} />}
                <Icon size={12} style={{ color: cfg.color, flexShrink: 0 }} />
                <span style={{
                  padding: '1px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
                  background: `${cfg.color}18`, color: cfg.color, border: `1px solid ${cfg.color}30`,
                }}>
                  {cfg.label}
                </span>
                <span style={{ fontFamily: 'monospace', fontSize: 11, color: T.dim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                  {row.evidence_name || row.evidence_id?.slice(0, 8) || '—'}
                </span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {(row.record_count || 0).toLocaleString()} enreg.
                </span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {fmtDuration(row.parsed_at, row.updated_at)}
                </span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {row.updated_at ? new Date(row.updated_at).toLocaleString('fr-FR') : '—'}
                </span>
              </div>

              {isExpanded && (
                <div style={{ padding: '8px 12px', background: T.bg, borderTop: `1px solid ${T.border}` }}>
                  {parseResults.length === 0 ? (
                    <p style={{ margin: 0, fontSize: 11, color: T.muted, fontFamily: 'monospace' }}>Aucun détail disponible.</p>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                          {['Parser', 'Statut', 'Enregistrements', 'Erreur'].map(h => (
                            <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'monospace', fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase' }}>
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {parseResults.map((pr, i) => {
                          const pcfg = STATUS_CONFIG[pr.status] || STATUS_CONFIG.ok;
                          return (
                            <tr key={i} style={{ borderBottom: `1px solid ${T.border}` }}>
                              <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: T.dim }}>{pr.parser || pr.type || '—'}</td>
                              <td style={{ padding: '4px 8px' }}>
                                <span style={{
                                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
                                  background: `${pcfg.color}18`, color: pcfg.color, border: `1px solid ${pcfg.color}30`,
                                }}>
                                  {pcfg.label}
                                </span>
                              </td>
                              <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: T.text }}>
                                {pr.record_count != null ? pr.record_count.toLocaleString() : '—'}
                              </td>
                              <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: 'var(--fl-danger)', fontSize: 10, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {pr.error || pr.warning || '—'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
