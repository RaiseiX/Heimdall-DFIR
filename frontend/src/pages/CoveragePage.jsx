import { useState, useEffect, useCallback, useMemo } from 'react';
import { tableStyle, headStyle, cellStyle } from '../components/ui/tableIdiom';
import { useOutletContext } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ListChecks, RefreshCw, Search, Loader2, AlertCircle } from 'lucide-react';
import { useTheme } from '../utils/theme';
import { parsersAPI } from '../utils/api';
import { summarizeCoverage } from './coverageSummary';

const PAGE_SIZE = 200;

const STATUS_TONE = {
  parsed:            'var(--fl-ok)',
  empty:             'var(--fl-muted)',
  unsupported:       'var(--fl-warn)',
  archive_expanded:  'var(--fl-accent)',
  error:             'var(--fl-danger)',
  degraded:          'var(--fl-warn)',
  quarantined:       'var(--fl-danger)',
  skipped_duplicate: 'var(--fl-muted)',
};
const toneOf = s => STATUS_TONE[s] || 'var(--fl-muted)';

const fmtBytes = (n) => {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`;
};

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

export default function CoveragePage() {
  const T = useTheme();
  const { t } = useTranslation();
  const { caseId, collectionId } = useOutletContext() || {};

  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const [offset, setOffset] = useState(0);

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const params = { limit: PAGE_SIZE, offset };
      if (statusFilter) params.status = statusFilter;
      if (applied) params.search = applied;
      if (collectionId) params.evidence_id = collectionId;
      const r = await parsersAPI.coverage(caseId, params);
      setPayload(r.data);
    } catch (e) {
      setError(e?.response?.data?.error || e?.message || String(e));
      setPayload(null);
    } finally {
      setLoading(false);
    }
  }, [caseId, collectionId, statusFilter, applied, offset]);

  useEffect(() => { load(); }, [load]);

  const summary = useMemo(() => summarizeCoverage(payload), [payload]);
  const files = payload?.files || [];
  const filteredTotal = payload?.filtered_total ?? 0;
  const isFiltered = Boolean(statusFilter || applied);

  const toggleStatus = (key) => {
    setOffset(0);
    setStatusFilter(prev => (prev === key ? null : key));
  };

  const submitSearch = (e) => { e.preventDefault(); setOffset(0); setApplied(search.trim()); };

  return (
    <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14, height: '100%', overflow: 'auto' }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ListChecks size={15} style={{ color: 'var(--fl-accent)' }} />
        <h2 style={{ margin: 0, fontSize: 13, fontFamily: MONO, fontWeight: 600, color: T.text }}>
          {t('coverage.title')}
        </h2>
        <button
          onClick={load}
          disabled={loading}
          style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5, padding: '4px 9px', borderRadius: 5, fontFamily: MONO, fontSize: 10, cursor: loading ? 'default' : 'pointer', background: 'transparent', border: `1px solid ${T.border}`, color: T.dim }}
        >
          {loading ? <Loader2 size={11} className="fl-spin" /> : <RefreshCw size={11} />}
          {t('coverage.refresh')}
        </button>
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, flexWrap: 'wrap', padding: '11px 13px', borderRadius: 7, background: T.card, border: `1px solid ${T.border}` }}>
        <span style={{ fontFamily: MONO, fontSize: 21, fontWeight: 600, color: T.text }}>
          {summary.total.toLocaleString()}
        </span>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.muted }}>
          {t(summary.scope === 'evidence' ? 'coverage.registered_evidence' : 'coverage.registered_case')}
        </span>
        <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 10, color: summary.setAside > 0 ? 'var(--fl-warn)' : T.muted }}>
          {t('coverage.set_aside', { count: summary.setAside })}
        </span>
      </div>

      {!summary.consistent && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '7px 11px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 22%, transparent)' }}>
          <AlertCircle size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
          <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-danger)' }}>{t('coverage.inconsistent')}</span>
        </div>
      )}

      <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
        {summary.rows.map(({ key, n }) => {
          const tone = toneOf(key);
          const on = statusFilter === key;
          return (
            <button
              key={key}
              onClick={() => toggleStatus(key)}
              title={t(`coverage.status_help.${key}`, { defaultValue: '' }) || undefined}
              style={{
                display: 'flex', alignItems: 'baseline', gap: 6, padding: '5px 10px', borderRadius: 6, cursor: 'pointer',
                fontFamily: MONO, fontSize: 10,
                background: on ? `color-mix(in srgb, ${tone} 14%, transparent)` : 'transparent',
                border: `1px solid ${on ? `color-mix(in srgb, ${tone} 34%, transparent)` : T.border}`,
                color: on ? tone : T.dim,
              }}
            >
              <span style={{ fontWeight: 600, color: tone }}>{n.toLocaleString()}</span>
              <span>{t(`coverage.status.${key}`, { defaultValue: key })}</span>
            </button>
          );
        })}
      </div>

      <form onSubmit={submitSearch} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 420 }}>
          <Search size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: T.muted }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('coverage.search_placeholder')}
            style={{ width: '100%', padding: '6px 9px 6px 27px', borderRadius: 5, fontFamily: MONO, fontSize: 10, background: T.bg, border: `1px solid ${T.border}`, color: T.text, outline: 'none' }}
          />
        </div>
        {isFiltered && (
          <span style={{ fontFamily: MONO, fontSize: 10, color: T.muted }}>
            {t('coverage.filtered', { shown: filteredTotal.toLocaleString(), total: summary.total.toLocaleString() })}
          </span>
        )}
      </form>

      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '9px 11px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 22%, transparent)' }}>
          <AlertCircle size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
          <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-danger)' }}>{t('coverage.load_failed', { reason: error })}</span>
        </div>
      )}

      <div style={{ borderRadius: 7, border: `1px solid ${T.border}`, overflow: 'hidden' }}>
        <table style={tableStyle}>
          <thead>
            <tr style={{ background: T.card, borderBottom: `1px solid ${T.border}` }}>
              {['path', 'status', 'detail', 'size'].map(h => (
                <th key={h} style={headStyle(false)}>
                  {t(`coverage.col_${h}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {files.map((f, i) => (
              <tr key={`${f.relative_path}-${i}`} style={{ borderBottom: `1px solid ${T.border}` }}>
                <td title={f.relative_path} style={{ ...cellStyle(), fontFamily: MONO, fontSize: 10, color: T.text, wordBreak: 'break-all' }}>
                  {f.relative_path}
                </td>
                <td style={cellStyle()}>
                  <span style={{ padding: '1px 6px', borderRadius: 3, fontFamily: MONO, fontSize: 9, fontWeight: 700, whiteSpace: 'nowrap', background: `color-mix(in srgb, ${toneOf(f.status)} 9%, transparent)`, color: toneOf(f.status), border: `1px solid color-mix(in srgb, ${toneOf(f.status)} 19%, transparent)` }}>
                    {t(`coverage.status.${f.status}`, { defaultValue: f.status })}
                  </span>
                </td>
                <td title={f.status_detail || ''} style={{ ...cellStyle(), fontFamily: MONO, fontSize: 9, color: f.status_detail ? T.dim : T.muted, maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.status_detail || '—'}
                </td>
                <td style={{ ...cellStyle(), fontFamily: MONO, fontSize: 9, color: T.dim, whiteSpace: 'nowrap' }}>
                  {fmtBytes(f.file_size)}
                </td>
              </tr>
            ))}
            {files.length === 0 && !loading && (
              <tr>
                <td colSpan={4} style={{ padding: '18px 9px', textAlign: 'center', fontFamily: MONO, fontSize: 10, color: T.muted }}>
                  {isFiltered ? t('coverage.no_match') : t('coverage.no_ledger')}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {filteredTotal > PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 11 }}>
          <button
            onClick={() => setOffset(o => Math.max(o - PAGE_SIZE, 0))}
            disabled={offset === 0}
            style={{ padding: '4px 11px', borderRadius: 5, fontFamily: MONO, fontSize: 10, cursor: offset === 0 ? 'default' : 'pointer', background: 'transparent', border: `1px solid ${T.border}`, color: offset === 0 ? T.muted : T.dim }}
          >
            {t('coverage.prev')}
          </button>
          <span style={{ fontFamily: MONO, fontSize: 10, color: T.muted }}>
            {t('coverage.range', {
              from: (offset + 1).toLocaleString(),
              to: Math.min(offset + PAGE_SIZE, filteredTotal).toLocaleString(),
              total: filteredTotal.toLocaleString(),
            })}
          </span>
          <button
            onClick={() => setOffset(o => o + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= filteredTotal}
            style={{ padding: '4px 11px', borderRadius: 5, fontFamily: MONO, fontSize: 10, cursor: offset + PAGE_SIZE >= filteredTotal ? 'default' : 'pointer', background: 'transparent', border: `1px solid ${T.border}`, color: offset + PAGE_SIZE >= filteredTotal ? T.muted : T.dim }}
          >
            {t('coverage.next')}
          </button>
        </div>
      )}
    </div>
  );
}
