import { useState, useEffect } from 'react';
import { useTheme } from '../utils/theme';
import { casesAPI, parsersAPI } from '../utils/api';
import {
  Table2, FolderOpen, ChevronDown, Loader2, FileText,
  Calendar, Hash, User, Info,
} from 'lucide-react';

const PARSER_COLORS = {
  mft:      'var(--fl-purple)',
  prefetch: '#22c55e',
  evtx:     'var(--fl-accent)',
  lnk:      'var(--fl-warn)',
  registry: 'var(--fl-pink)',
  amcache:  'var(--fl-gold)',
  appcompat:'#f59e0b',
  shellbags:'#06b6d4',
  jumplist: '#8b5cf6',
  srum:     '#f43f5e',
  wxtcmd:   '#d946ef',
  hayabusa: 'var(--fl-danger)',
};

function parserColor(name) {
  const key = (name || '').toLowerCase().replace(/[^a-z]/g, '');
  return PARSER_COLORS[key] || 'var(--fl-dim)';
}

function fmtDate(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' })
      + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function ParserBadge({ name }) {
  const col = parserColor(name);
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-mono font-bold"
      style={{ background: `${col}18`, color: col, border: `1px solid ${col}30` }}
    >
      {name}
    </span>
  );
}

function ResultItem({ result, selected, onSelect, T }) {
  const col = parserColor(result.parser_name);
  const isSelected = selected?.id === result.id;
  return (
    <button
      onClick={() => onSelect(result)}
      className="w-full text-left px-3 py-3 rounded-lg transition-all"
      style={{
        background: isSelected ? `${col}10` : 'transparent',
        border: `1px solid ${isSelected ? col + '40' : T.border}`,
        marginBottom: 4,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-1">
        <ParserBadge name={result.parser_name} />
        <span className="text-xs font-mono" style={{ color: T.dim }}>
          {result.record_count?.toLocaleString() ?? 0} lignes
        </span>
      </div>
      <div className="text-xs truncate" style={{ color: T.text }}>
        {result.evidence_name || '—'}
      </div>
      <div className="text-xs mt-0.5" style={{ color: T.muted ?? T.dim }}>
        {fmtDate(result.created_at)} · {result.parsed_by || 'system'}
      </div>
    </button>
  );
}

function DataTable({ records, T }) {
  if (!records || records.length === 0) {
    return (
      <div className="text-center py-10 text-sm" style={{ color: T.dim }}>
        Aucune donnée pour cette page.
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
                borderBottom: `1px solid ${T.border}20`,
                background: i % 2 === 0 ? 'transparent' : `${T.panel ?? '#0b101a'}80`,
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
        setDataError('Impossible de charger les données. Vérifiez la connexion.');
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
            Données Parsées
          </h1>
          <p className="fl-header-sub">Visualisation des artefacts parsés par cas forensique</p>
        </div>
      </div>

      <div className="fl-card p-4 mb-5">
        <label
          className="text-xs font-mono uppercase tracking-widest mb-2 block"
          style={{ color: T.dim }}
        >
          <FolderOpen size={12} className="inline mr-1" />
          Dossier d'investigation (isolation des données)
        </label>

        {loadingCases ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: T.dim }}>
            <Loader2 size={14} className="animate-spin" /> Chargement des cas…
          </div>
        ) : cases.length === 0 ? (
          <span className="text-sm" style={{ color: 'var(--fl-danger)' }}>
            Aucun cas disponible. Créez un cas d'abord.
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
          <div className="mt-2 flex items-center gap-1.5 text-xs font-mono" style={{ color: '#22c55e' }}>
            <Info size={11} />
            Affichage isolé — uniquement les données de{' '}
            <span style={{ fontWeight: 700 }}>{selectedCase.case_number}</span>
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
              Résultats de parsing
              {!loadingResults && (
                <span className="ml-2 px-1.5 py-0.5 rounded font-bold" style={{ background: `${T.accent}18`, color: T.accent }}>
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
                  Aucun artefact parsé pour ce cas.
                </p>
                <p className="text-xs mt-1" style={{ color: T.muted ?? T.dim }}>
                  Importez une collecte et lancez le parsing.
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
                  Sélectionnez un résultat
                </p>
                <p className="text-xs mt-1" style={{ color: T.dim }}>
                  Choisissez un artefact parsé dans la liste à gauche
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
                        {selectedResult.evidence_name || 'Artefact sans nom'}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs font-mono" style={{ color: T.dim }}>
                      <span className="flex items-center gap-1">
                        <Hash size={11} />
                        {total.toLocaleString()} enregistrements
                      </span>
                      <span className="flex items-center gap-1">
                        <Calendar size={11} />
                        {fmtDate(selectedResult.created_at)}
                      </span>
                      <span className="flex items-center gap-1">
                        <User size={11} />
                        {selectedResult.parsed_by || 'system'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-2 text-xs font-mono flex items-center gap-1" style={{ color: '#22c55e' }}>
                    <Info size={10} />
                    Données isolées — cas {selectedCase?.case_number}
                    {' '}· Affichage 50 premières lignes (pagination à venir)
                  </div>
                </div>

                {loadingData ? (
                  <div
                    className="rounded-xl border flex items-center justify-center"
                    style={{ background: T.card ?? T.panel, borderColor: T.border, minHeight: 200 }}
                  >
                    <div className="text-center" style={{ color: T.dim }}>
                      <Loader2 size={22} className="animate-spin mx-auto mb-2" />
                      <span className="text-sm">Chargement des données…</span>
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
                    ⚠ {dataError}
                  </div>
                ) : (
                  <DataTable records={records} T={T} />
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
