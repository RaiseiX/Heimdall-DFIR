import { useState, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import { FileText, ChevronDown, ChevronRight, RefreshCw, AlertCircle, CheckCircle2, AlertTriangle, MinusCircle, ShieldAlert, CopyX, Loader2 } from 'lucide-react';
import { useTheme } from '../utils/theme';
import apiClient, { parsersAPI } from '../utils/api';
import { fmtLocal } from '../utils/formatters';
import { useTranslation } from 'react-i18next';

// Honest status vocabulary — every ingestion/parse state gets its own badge.
// NEVER collapse empty/degraded/quarantined/skipped(_duplicate) into a green "ok" badge.
const STATUS_CONFIG = {
  ok:                { key: 'parserLogs.status_ok',        color: 'var(--fl-ok)',     icon: CheckCircle2 },
  parsed:            { key: 'parserLogs.status_ok',        color: 'var(--fl-ok)',     icon: CheckCircle2 },
  empty:             { key: 'parserLogs.status_empty',     color: 'var(--fl-muted)',  icon: MinusCircle },
  degraded:          { key: 'parserLogs.status_degraded',  color: 'var(--fl-warn)',   icon: AlertTriangle },
  error:             { key: 'parserLogs.status_error',     color: 'var(--fl-danger)', icon: AlertCircle },
  quarantined:       { key: 'parserLogs.status_quarantined', color: 'var(--fl-purple)', icon: ShieldAlert },
  skipped:           { key: 'parserLogs.status_skipped',   color: 'var(--fl-artifact-registry)', icon: CopyX },
  skipped_duplicate: { key: 'parserLogs.status_skipped',   color: 'var(--fl-artifact-registry)', icon: CopyX },
  received:          { key: 'parserLogs.status_progress',  color: 'var(--fl-dim)',    icon: Loader2 },
  extracting:        { key: 'parserLogs.status_progress',  color: 'var(--fl-dim)',    icon: Loader2 },
  classified:        { key: 'parserLogs.status_progress',  color: 'var(--fl-dim)',    icon: Loader2 },
  queued:            { key: 'parserLogs.status_progress',  color: 'var(--fl-dim)',    icon: Loader2 },
  parsing:           { key: 'parserLogs.status_progress',  color: 'var(--fl-dim)',    icon: Loader2 },
};

// Priority order for rolling many per-parser statuses up into one header badge —
// worst / most-informative status wins. Nothing here folds into "ok".
const STATUS_PRIORITY = ['error', 'quarantined', 'degraded', 'empty', 'skipped_duplicate', 'skipped', 'parsing', 'queued', 'classified', 'extracting', 'received', 'ok', 'parsed'];

function deriveStatus(parseResults = []) {
  if (!parseResults.length) return 'ok';
  for (const s of STATUS_PRIORITY) {
    if (parseResults.some(r => r.status === s)) return s;
  }
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
  const { t } = useTranslation();
  const ctx = useOutletContext() || {};
  const { caseId, collectionId } = ctx;

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(new Set());
  const [error, setError] = useState(null);
  const [ingestionCounts, setIngestionCounts] = useState(null);

  async function load() {
    if (!caseId) return;
    setLoading(true); setError(null);
    try {
      const params = collectionId ? `?evidence_id=${collectionId}` : '';
      const { data } = await apiClient.get(`/collection/${caseId}/parser-results${params}`);
      setRows(data || []);
    } catch (e) {
      setError(e.response?.data?.error || t('parserLogs.load_error'));
      setRows([]);
    }
    setLoading(false);
  }

  // Honest 11-state ingestion rollup (received…parsed/empty/degraded/error/quarantined/skipped_duplicate)
  // for the selected evidence — distinct from the per-parser-run statuses in the table below.
  async function loadIngestionCounts() {
    if (!caseId || !collectionId) { setIngestionCounts(null); return; }
    try {
      const { data } = await parsersAPI.status(caseId, collectionId);
      setIngestionCounts(data?.counts || {});
    } catch (e) {
      setIngestionCounts(null);
    }
  }

  useEffect(() => { load(); loadIngestionCounts(); }, [caseId, collectionId]);

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
        <h2 style={{ margin: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 14, color: T.text }}>
          {t('parserLogs.title')}
        </h2>
        <button
          onClick={load}
          disabled={loading}
          style={{
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5,
            background: 'none', border: `1px solid ${T.border}`, borderRadius: 5,
            padding: '3px 10px', cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            color: T.dim,
          }}
        >
          <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          {t('common.refresh')}
        </button>
      </div>

      {ingestionCounts && Object.keys(ingestionCounts).length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
          {Object.entries(ingestionCounts).map(([status, count]) => {
            const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.ok;
            const Icon = cfg.icon;
            return (
              <span key={status} style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
                fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
                padding: '2px 9px', borderRadius: 4,
                background: `color-mix(in srgb, ${cfg.color} 10%, transparent)`, color: cfg.color,
                border: `1px solid color-mix(in srgb, ${cfg.color} 22%, transparent)` }}>
                <Icon size={11} />
                {count} {t(cfg.key)}
              </span>
            );
          })}
        </div>
      )}

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: 6, marginBottom: 12,
          background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)',
          border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)',
          fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          {error}
        </div>
      )}

      {!loading && rows.length === 0 && !error && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: T.muted, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
          {t('parserLogs.empty')}
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
          const isInProgress = cfg.key === 'parserLogs.status_progress';

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
                <Icon size={12} style={{ color: cfg.color, flexShrink: 0, animation: isInProgress ? 'spin 1s linear infinite' : 'none' }} />
                <span style={{
                  padding: '1px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  background: `color-mix(in srgb, ${cfg.color} 9%, transparent)`, color: cfg.color, border: `1px solid color-mix(in srgb, ${cfg.color} 19%, transparent)`,
                }}>
                  {t(cfg.key)}
                </span>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: T.dim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                  {row.evidence_name || row.evidence_id?.slice(0, 8) || '—'}
                </span>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {(row.record_count || 0).toLocaleString()} {t('parserLogs.records_short')}
                </span>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {fmtDuration(row.parsed_at, row.updated_at)}
                </span>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {row.updated_at ? fmtLocal(row.updated_at) : '—'}
                </span>
              </div>

              {isExpanded && (
                <div style={{ padding: '8px 12px', background: T.bg, borderTop: `1px solid ${T.border}` }}>
                  {parseResults.length === 0 ? (
                    <p style={{ margin: 0, fontSize: 11, color: T.muted, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('parserLogs.no_details')}</p>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                          {[t('parserLogs.col_parser'), t('parserLogs.col_status'), t('parserLogs.col_records'), t('parserLogs.col_error')].map(h => (
                            <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase' }}>
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
                              <td style={{ padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: T.dim }}>{pr.parser || pr.type || '—'}</td>
                              <td style={{ padding: '4px 8px' }}>
                                <span style={{
                                  padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                                  background: `color-mix(in srgb, ${pcfg.color} 9%, transparent)`, color: pcfg.color, border: `1px solid color-mix(in srgb, ${pcfg.color} 19%, transparent)`,
                                }}>
                                  {t(pcfg.key)}
                                </span>
                              </td>
                              <td style={{ padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: T.text }}>
                                {pr.record_count != null ? pr.record_count.toLocaleString() : '—'}
                              </td>
                              <td style={{ padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)', fontSize: 10, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
