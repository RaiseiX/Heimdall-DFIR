import { useState, useEffect } from 'react';
import { useTheme } from '../utils/theme';
import { casesAPI, parsersAPI } from '../utils/api';
import {
  Table2, FolderOpen, ChevronDown, Loader2, FileText,
  Calendar, Hash, User, Info,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';

const PARSER_COLORS = {
  mft:      'var(--fl-purple)',
  prefetch: 'var(--fl-ok)',
  evtx:     'var(--fl-accent)',
  lnk:      'var(--fl-warn)',
  registry: 'var(--fl-pink)',
  amcache:  'var(--fl-gold)',
  appcompat:'var(--fl-warn)',
  shellbags:'var(--fl-purple)',
  jumplist: 'var(--fl-accent)',
  srum:     'var(--fl-danger)',
  wxtcmd:   'var(--fl-pink)',
  hayabusa: 'var(--fl-danger)',
};

function parserColor(name) {
  const key = (name || '').toLowerCase().replace(/[^a-z]/g, '');
  return PARSER_COLORS[key] || 'var(--fl-dim)';
}

function fmtDate(iso, locale) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' })
      + ' ' + d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function ParserBadge({ name }) {
  const col = parserColor(name);
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-mono font-bold"
      style={{ background: `color-mix(in srgb, ${col} 9%, transparent)`, color: col, border: `1px solid color-mix(in srgb, ${col} 19%, transparent)` }}
    >
      {name}
    </span>
  );
}

function ResultItem({ result, selected, onSelect, T, t, locale }) {
  const col = parserColor(result.parser_name);
  const isSelected = selected?.id === result.id;
  return (
    <button
      onClick={() => onSelect(result)}
      className="w-full text-left px-3 py-3 rounded-lg transition-all"
      style={{
        background: isSelected ? `color-mix(in srgb, ${col} 6%, transparent)` : 'transparent',
        border: `1px solid ${isSelected ? col + '40' : T.border}`,
        marginBottom: 4,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-1">
        <ParserBadge name={result.parser_name} />
        <span className="text-xs font-mono" style={{ color: T.dim }}>
          {result.record_count?.toLocaleString() ?? 0} {t('parsedData.rows')}
        </span>
      </div>
      <div className="text-xs truncate" style={{ color: T.text }}>
        {result.evidence_name || '—'}
      </div>
      <div className="text-xs mt-0.5" style={{ color: T.muted ?? T.dim }}>
        {fmtDate(result.created_at, locale)} · {result.parsed_by || 'system'}
      </div>
    </button>
  );
}

function DataTable({ records, T, t }) {
  if (!records || records.length === 0) {
    return (
      <div className="text-center py-10 text-sm" style={{ color: T.dim }}>
        {t('parsedData.empty_page')}
      </div>
    );
  }

  const colSet = new Set();
  records.slice(0, 5).forEach(r => Object.keys(r).forEach(k => colSet.add(k)));
  const columns = [...colSet].slice(0, 30);

  return (
    <div className="overflow-x-auto rounded-xl border" style={{ borderColor: T.border }}>
      <table className="text-xs w-full" style={{ borderCollapse: 'collapse', minWidth: 600 }}>
        <thead>
          <tr style={{ background: T.panel ?? 'var(--fl-bg)' }}>
            {columns.map(col => (
              <th
                key={col}
                className="text-left px-3 py-2 font-mono uppercase tracking-wider whitespace-nowrap"
                style={{ color: T.dim, borderBottom: `1px solid ${T.border}`, fontWeight: 600 }}
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {records.map((row, i) => (
            <tr
              key={i}
              style={{
                borderBottom: `1px solid color-mix(in srgb, ${T.border} 13%, transparent)`,
                background: i % 2 === 0 ? 'transparent' : `color-mix(in srgb, ${T.panel ?? 'var(--fl-panel)'} 50%, transparent)`,
              }}
            >
              {columns.map(col => {
                const val = row[col];
                const display = val === null || val === undefined ? '' : String(val);
                return (
                  <td
                    key={col}
                    className="px-3 py-1.5 font-mono"
                    style={{
                      color: T.text,
                      maxWidth: 280,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={display}
                  >
                    {display}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ParsedDataPage() {
  const T = useTheme();
  const { t, i18n } = useTranslation();

  const [cases, setCases]               = useState([]);
  const [caseId, setCaseId]             = useState('');
  const [loadingCases, setLoadingCases] = useState(true);

  const [results, setResults]           = useState([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [selectedResult, setSelectedResult] = useState(null);

  const [records, setRecords]           = useState([]);
  const [total, setTotal]               = useState(0);
  const [loadingData, setLoadingData]   = useState(false);
  const [dataError, setDataError]       = useState('');

  useEffect(() => {
    casesAPI.list({}).then(({ data }) => {
      const list = data.cases || (Array.isArray(data) ? data : []);
      setCases(list);
      if (list.length > 0) setCaseId(list[0].id);
    }).catch(() => {}).finally(() => setLoadingCases(false));
  }, []);

  useEffect(() => {
    if (!caseId) {
      setResults([]);
      setSelectedResult(null);
      setRecords([]);
      setTotal(0);
      return;
    }
    setLoadingResults(true);
    setSelectedResult(null);
    setRecords([]);
    setTotal(0);
    parsersAPI.results(caseId)
      .then(({ data }) => {
        setResults(Array.isArray(data) ? data : []);
      })
      .catch(() => setResults([]))
      .finally(() => setLoadingResults(false));
  }, [caseId]);

  useEffect(() => {
    if (!selectedResult) {
      setRecords([]);
      setTotal(0);
      return;
    }
    setLoadingData(true);
    setDataError('');

    parsersAPI.resultData(selectedResult.id, { page: 1, pageSize: 50 })
      .then(({ data }) => {
        setRecords(data.records || []);
        setTotal(data.total || 0);
      })
      .catch(() => {
        setDataError(t('parsedData.load_data_error'));
        setRecords([]);
        setTotal(0);
      })
      .finally(() => setLoadingData(false));
  }, [selectedResult]);

  const selectedCase = cases.find(c => String(c.id) === String(caseId));

  return (
    <div className="p-6" style={{ minHeight: '100vh', background: T.bg }}>

      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">
            <Table2 size={20} className="inline mr-2" style={{ color: T.accent, verticalAlign: 'text-bottom' }} />
            {t('parsedData.title')}
          </h1>
          <p className="fl-header-sub">{t('parsedData.subtitle')}</p>
        </div>
      </div>

      <div className="fl-card p-4 mb-5">
        <label
          className="text-xs font-mono uppercase tracking-widest mb-2 block"
          style={{ color: T.dim }}
        >
          <FolderOpen size={12} className="inline mr-1" />
          {t('parsedData.case_label')}
        </label>

        {loadingCases ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: T.dim }}>
            <Loader2 size={14} className="animate-spin" /> {t('parsedData.loading_cases')}
          </div>
        ) : cases.length === 0 ? (
          <span className="text-sm" style={{ color: 'var(--fl-danger)' }}>
            {t('parsedData.no_cases')}
          </span>
        ) : (
          <div className="relative">
            <select
              value={caseId}
              onChange={e => setCaseId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg text-sm font-mono outline-none appearance-none"
              style={{
                background: T.inputBg ?? T.bg,
                border: `1px solid ${T.border}`,
                color: T.text,
                paddingRight: 36,
              }}
            >
              {cases.map(c => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.title}
                </option>
              ))}
            </select>
            <ChevronDown
              size={14}
              style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: T.dim, pointerEvents: 'none' }}
            />
          </div>
        )}

        {selectedCase && (
          <div className="mt-2 flex items-center gap-1.5 text-xs font-mono" style={{ color: 'var(--fl-ok)' }}>
            <Info size={11} />
            {t('parsedData.isolated_view', { caseNumber: selectedCase.case_number })}
          </div>
        )}
      </div>

      {caseId && (
        <div className="flex gap-4" style={{ alignItems: 'flex-start' }}>

          <div
            className="rounded-xl border p-3 flex-shrink-0"
            style={{ width: 260, background: T.card ?? T.panel, borderColor: T.border }}
          >
            <div className="text-xs font-mono uppercase tracking-wider mb-3" style={{ color: T.dim }}>
              {t('parsedData.parse_results')}
              {!loadingResults && (
                <span className="ml-2 px-1.5 py-0.5 rounded font-bold" style={{ background: `color-mix(in srgb, ${T.accent} 9%, transparent)`, color: T.accent }}>
                  {results.length}
                </span>
              )}
            </div>

            {loadingResults ? (
              <div className="flex items-center justify-center py-8" style={{ color: T.dim }}>
                <Loader2 size={18} className="animate-spin" />
              </div>
            ) : results.length === 0 ? (
              <div className="text-center py-8">
                <FileText size={32} style={{ color: T.border, margin: '0 auto 8px' }} />
                <p className="text-xs" style={{ color: T.dim }}>
                  {t('parsedData.no_artifacts')}
                </p>
                <p className="text-xs mt-1" style={{ color: T.muted ?? T.dim }}>
                  {t('parsedData.parse_hint')}
                </p>
              </div>
            ) : (
              <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 260px)' }}>
                {results.map(r => (
                  <ResultItem
                    key={r.id}
                    result={r}
                    selected={selectedResult}
                    onSelect={setSelectedResult}
                    T={T}
                    t={t}
                    locale={i18n.language}
                  />
                ))}
              </div>
            )}
          </div>

          <div className="flex-1 min-w-0">
            {!selectedResult ? (

              <div
                className="rounded-xl border flex flex-col items-center justify-center"
                style={{ background: T.card ?? T.panel, borderColor: T.border, minHeight: 300 }}
              >
                <Table2 size={48} style={{ color: T.border, marginBottom: 12 }} />
                <p className="text-sm font-semibold" style={{ color: T.text }}>
                  {t('parsedData.select_result')}
                </p>
                <p className="text-xs mt-1" style={{ color: T.dim }}>
                  {t('parsedData.select_result_hint')}
                </p>
              </div>
            ) : (
              <>
                
                <div
                  className="rounded-xl border p-4 mb-4"
                  style={{ background: T.card ?? T.panel, borderColor: T.border }}
                >
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div className="flex items-center gap-3">
                      <ParserBadge name={selectedResult.parser_name} />
                      <span className="text-sm font-semibold" style={{ color: T.text }}>
                        {selectedResult.evidence_name || t('parsedData.unnamed_artifact')}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs font-mono" style={{ color: T.dim }}>
                      <span className="flex items-center gap-1">
                        <Hash size={11} />
                        {t('parsedData.records', { count: total.toLocaleString() })}
                      </span>
                      <span className="flex items-center gap-1">
                        <Calendar size={11} />
                        {fmtDate(selectedResult.created_at, i18n.language)}
                      </span>
                      <span className="flex items-center gap-1">
                        <User size={11} />
                        {selectedResult.parsed_by || 'system'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-2 text-xs font-mono flex items-center gap-1" style={{ color: 'var(--fl-ok)' }}>
                    <Info size={10} />
                    {t('parsedData.isolated_case', { caseNumber: selectedCase?.case_number })} · {t('parsedData.first_rows_hint')}
                  </div>
                </div>

                {loadingData ? (
                  <div
                    className="rounded-xl border flex items-center justify-center"
                    style={{ background: T.card ?? T.panel, borderColor: T.border, minHeight: 200 }}
                  >
                    <div className="text-center" style={{ color: T.dim }}>
                      <Loader2 size={22} className="animate-spin mx-auto mb-2" />
                      <span className="text-sm">{t('parsedData.loading_data')}</span>
                    </div>
                  </div>
                ) : dataError ? (
                  <div
                    className="rounded-xl border p-4 text-sm"
                    style={{
                      background: 'rgba(239,68,68,0.05)',
                      borderColor: 'rgba(239,68,68,0.25)',
                      color: 'var(--fl-danger)',
                    }}
                  >
                    {dataError}
                  </div>
                ) : (
                  <DataTable records={records} T={T} t={t} />
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
