
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { parsersAPI } from '../../utils/api';
import {
  Table2, FileText, Loader2, Hash, Calendar, User,
  ChevronLeft, ChevronRight, RefreshCw, Info, Trash2, ExternalLink, Download,
} from 'lucide-react';

const PAGE_SIZE = 50;
const MAX_COLS  = 25;

const PARSER_COLORS = {

  evtx:       '#4d82c0',
  mft:        '#8b72d6',
  prefetch:   '#22c55e',
  lnk:        '#d97c20',
  registry:   '#c96898',
  amcache:    '#c89d1d',
  appcompat:  '#f59e0b',
  shellbags:  '#06b6d4',
  jumplist:   '#8b5cf6',
  srum:       '#f43f5e',
  wxtcmd:     '#14b8a6',
  recycle:    '#84cc16',
  bits:       '#fb923c',
  sum:        '#d946ef',
  hayabusa:   '#ef4444',

  mfteCmd:          '#8b72d6',
  pecmd:            '#22c55e',
  lecmd:            '#d97c20',
  sbecmd:           '#06b6d4',
  amcacheparser:    '#c89d1d',
  appcompatcacheparser: '#f59e0b',
  evtxecmd:         '#4d82c0',
  recmd:            '#c96898',
  jlecmd:           '#8b5cf6',
  srumeCmd:         '#f43f5e',
  wxtcmd2:          '#14b8a6',
  rbcmd:            '#84cc16',
  bitsparser:       '#fb923c',
  sumeCmd:          '#d946ef',
  unifiedtimeline:  '#7d8590',
  magnetresponseimport: '#484f58',
};

function parserColor(name = '') {
  const key = name.toLowerCase().replace(/[^a-z0-9]/g, '');

  if (PARSER_COLORS[key]) return PARSER_COLORS[key];

  for (const [k, v] of Object.entries(PARSER_COLORS)) {
    if (key.startsWith(k) || k.startsWith(key)) return v;
  }
  return '#7d8590';
}

function fmtDate(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('fr-FR') + ' '
      + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function flattenRaw(records) {
  if (!records || records.length === 0) return records;

  const first = records[0];
  if (!first || typeof first.raw !== 'object' || first.raw === null || Array.isArray(first.raw)) {
    return records;
  }
  return records.map(({ raw, ...rest }) => ({ ...rest, ...(raw || {}) }));
}

function deriveColumns(records, n = 5) {
  const colSet = new Set();
  records.slice(0, n).forEach(r => Object.keys(r).forEach(k => colSet.add(k)));
  return [...colSet].slice(0, MAX_COLS);
}

function ParserBadge({ name }) {
  const col = parserColor(name);
  return (
    <span style={{
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
      fontWeight: 700, background: `${col}18`, color: col, border: `1px solid ${col}30`,
    }}>
      {name}
    </span>
  );
}

function ResultChip({ result, isSelected, onClick, onDelete, deleting, onExplore }) {
  const col = parserColor(result.parser_name);
  return (
    <div style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        onClick={onClick}
        style={{
          display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
          padding: '8px 12px', paddingRight: 54, borderRadius: 8, cursor: 'pointer', textAlign: 'left',
          background: isSelected ? `${col}10` : '#0d1117',
          border: `1px solid ${isSelected ? col + '50' : '#30363d'}`,
          minWidth: 140, transition: 'all 0.15s',
        }}
      >
        <ParserBadge name={result.parser_name} />
        <span style={{ fontSize: 11, color: '#7d8590', marginTop: 4, fontFamily: 'monospace' }}>
          {(result.record_count ?? 0).toLocaleString()} lignes
        </span>
        <span style={{ fontSize: 10, color: '#484f58', marginTop: 2 }}>
          {fmtDate(result.created_at)}
        </span>
      </button>
      
      <button
        onClick={(e) => { e.stopPropagation(); onExplore(result); }}
        title="Ouvrir dans la Super Timeline"
        style={{
          position: 'absolute', top: 6, right: 28,
          width: 20, height: 20, borderRadius: 4,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'transparent', border: 'none', cursor: 'pointer',
          color: '#4d82c060', transition: 'color 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.color = '#4d82c0'}
        onMouseLeave={e => e.currentTarget.style.color = '#4d82c060'}
      >
        <ExternalLink size={11} />
      </button>
      <button
        onClick={(e) => { e.stopPropagation(); onDelete(result); }}
        disabled={deleting}
        title="Supprimer ce résultat"
        style={{
          position: 'absolute', top: 6, right: 6,
          width: 20, height: 20, borderRadius: 4,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'transparent', border: 'none', cursor: deleting ? 'not-allowed' : 'pointer',
          color: '#da363360', transition: 'color 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.color = '#da3633'}
        onMouseLeave={e => e.currentTarget.style.color = '#da363360'}
      >
        {deleting ? <Loader2 size={11} className="animate-spin" /> : <Trash2 size={11} />}
      </button>
    </div>
  );
}

function DataTable({ records, columns, loading }) {
  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '32px 0', color: '#7d8590' }}>
        <Loader2 size={20} className="animate-spin" style={{ display: 'inline', marginRight: 8 }} />
        Chargement des données…
      </div>
    );
  }

  if (!records || records.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '32px 0', color: '#7d8590', fontSize: 13 }}>
        Aucune donnée sur cette page.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid #30363d' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, minWidth: 600 }}>
        <thead>
          <tr style={{ background: '#0d1117' }}>
            {columns.map(col => (
              <th key={col} style={{
                textAlign: 'left', padding: '6px 10px', fontFamily: 'monospace',
                textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600,
                color: '#7d8590', borderBottom: '1px solid #30363d', whiteSpace: 'nowrap',
              }}>
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
                borderBottom: '1px solid #30363d15',
                background: i % 2 === 0 ? 'transparent' : '#0b101a80',
              }}
            >
              {columns.map(col => {
                const val = row[col];
                const display = val === null || val === undefined ? '' : String(val);
                return (
                  <td
                    key={col}
                    title={display}
                    style={{
                      padding: '5px 10px', fontFamily: 'monospace', color: '#e6edf3',
                      maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
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

function Pagination({ page, totalPages, total, pageSize, onChange }) {
  if (totalPages <= 1) return null;
  const from = (page - 1) * pageSize + 1;
  const to   = Math.min(page * pageSize, total);
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginTop: 12 }}>
      <button
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '5px 12px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace',
          background: '#1c2333', border: '1px solid #30363d',
          color: page <= 1 ? '#334155' : '#7d8590', cursor: page <= 1 ? 'not-allowed' : 'pointer',
        }}
      >
        <ChevronLeft size={12} /> Précédent
      </button>
      <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#7d8590' }}>
        {from.toLocaleString()}–{to.toLocaleString()} sur {total.toLocaleString()} · Page {page}/{totalPages}
      </span>
      <button
        disabled={page >= totalPages}
        onClick={() => onChange(page + 1)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '5px 12px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace',
          background: '#1c2333', border: '1px solid #30363d',
          color: page >= totalPages ? '#334155' : '#7d8590',
          cursor: page >= totalPages ? 'not-allowed' : 'pointer',
        }}
      >
        Suivant <ChevronRight size={12} />
      </button>
    </div>
  );
}

const UNIFIED_NAMES = ['UnifiedTimeline', 'MagnetRESPONSE_Import'];

export default function ParsedResultsViewer({ caseId, refreshKey = 0 }) {
  const navigate = useNavigate();

  const [results, setResults]         = useState([]);
  const [loadingList, setLoadingList] = useState(false);
  const [listError, setListError]     = useState('');

  const [selected, setSelected]       = useState(null);
  const [records, setRecords]         = useState([]);
  const [columns, setColumns]         = useState([]);
  const [total, setTotal]             = useState(0);
  const [page, setPage]               = useState(1);
  const [loadingData, setLoadingData] = useState(false);
  const [dataError, setDataError]     = useState('');

  const [artifactTypes, setArtifactTypes]   = useState([]);
  const [loadingTypes, setLoadingTypes]     = useState(false);
  const [selectedType, setSelectedType]     = useState(null);

  const [confirmDelete, setConfirmDelete]   = useState(null);
  const [deletingId, setDeletingId]         = useState(null);

  const isUnified = selected && UNIFIED_NAMES.includes(selected.parser_name);

  useEffect(() => {
    if (!caseId) return;
    setLoadingList(true);
    setListError('');
    setSelected(null);
    setArtifactTypes([]);
    setSelectedType(null);
    setRecords([]);
    setColumns([]);
    setTotal(0);
    setPage(1);
    parsersAPI.results(caseId)
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : [];
        setResults(list);

        const unified = list.find(r => UNIFIED_NAMES.includes(r.parser_name));
        if (unified) setSelected(unified);
        else if (list.length > 0) setSelected(list[0]);
      })
      .catch(() => {
        setListError('Impossible de charger la liste des résultats.');
        setResults([]);
      })
      .finally(() => setLoadingList(false));
  }, [caseId, refreshKey]);

  useEffect(() => {
    if (!selected || !selected.id || !UNIFIED_NAMES.includes(selected.parser_name)) {
      setArtifactTypes([]);
      setSelectedType(null);
      return;
    }
    setLoadingTypes(true);
    parsersAPI.resultTypes(selected.id)
      .then(({ data }) => {
        setArtifactTypes(data.types || []);
      })
      .catch(() => setArtifactTypes([]))
      .finally(() => setLoadingTypes(false));
  }, [selected]);

  useEffect(() => {
    if (!selected) { setRecords([]); setColumns([]); setTotal(0); return; }
    setLoadingData(true);
    setDataError('');
    const params = { page, pageSize: PAGE_SIZE };
    if (selectedType) params.artifactType = selectedType;
    parsersAPI.resultData(selected.id, params)
      .then(({ data }) => {
        const recs = flattenRaw(data.records || []);
        setRecords(recs);
        setTotal(data.total || 0);
        setColumns(deriveColumns(recs));
      })
      .catch(() => {
        setDataError('Impossible de charger les données de ce résultat.');
        setRecords([]);
        setTotal(0);
      })
      .finally(() => setLoadingData(false));
  }, [selected, page, selectedType]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const handleSelectResult = (r) => {
    setSelected(r);
    setPage(1);
    setSelectedType(null);
    setArtifactTypes([]);
  };

  const handleDeleteResult = async (result) => {
    setDeletingId(result.id);
    setConfirmDelete(null);
    try {
      await parsersAPI.deleteResult(result.id);
      setResults(prev => prev.filter(r => r.id !== result.id));
      if (selected?.id === result.id) {
        setSelected(null);
        setRecords([]);
        setColumns([]);
        setTotal(0);
      }
    } catch (e) {
      alert('Erreur suppression : ' + (e.response?.data?.error || e.message));
    }
    setDeletingId(null);
  };

  const handleRefresh = () => {
    setLoadingList(true);
    setListError('');
    parsersAPI.results(caseId)
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : [];
        setResults(list);
        if (list.length > 0 && !selected) {
          const unified = list.find(r => UNIFIED_NAMES.includes(r.parser_name));
          setSelected(unified || list[0]);
        }
      })
      .catch(() => setListError('Actualisation échouée.'))
      .finally(() => setLoadingList(false));
  };

  return (
    <div>
      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Table2 size={15} style={{ color: '#4d82c0' }} />
          <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#7d8590' }}>
            Résultats de parsing
          </span>
          {!loadingList && results.length > 0 && (
            <span style={{
              padding: '1px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
              fontWeight: 700, background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030',
            }}>
              {results.length}
            </span>
          )}
        </div>
        <button onClick={handleRefresh} disabled={loadingList}
          style={{
            display: 'flex', alignItems: 'center', gap: 4,
            padding: '4px 10px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid #30363d', color: '#7d8590', cursor: 'pointer',
          }}
        >
          <RefreshCw size={11} className={loadingList ? 'animate-spin' : ''} /> Actualiser
        </button>
      </div>

      <div style={{
        padding: 12, borderRadius: 10, border: '1px solid #30363d',
        background: '#0d1117', marginBottom: 16,
      }}>
        {loadingList ? (
          <div style={{ textAlign: 'center', padding: '16px 0', color: '#7d8590' }}>
            <Loader2 size={16} className="animate-spin" style={{ display: 'inline', marginRight: 6 }} />
            Chargement…
          </div>
        ) : listError ? (
          <div style={{ color: '#ef4444', fontSize: 12 }}>⚠ {listError}</div>
        ) : results.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' }}>
            <FileText size={20} style={{ color: '#334155' }} />
            <div>
              <div style={{ fontSize: 13, color: '#7d8590' }}>Aucun résultat de parsing pour ce cas.</div>
              <div style={{ fontSize: 11, color: '#484f58', marginTop: 2 }}>
                Sélectionnez un parseur et une preuve ci-dessus, puis cliquez sur "Exécuter".
              </div>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {results.map(r => (
              <ResultChip
                key={r.id}
                result={r}
                isSelected={selected?.id === r.id}
                onClick={() => handleSelectResult(r)}
                onDelete={(res) => setConfirmDelete(res)}
                deleting={deletingId === r.id}
                onExplore={(res) => navigate(`/super-timeline?caseId=${caseId}&resultId=${res.id}`)}
              />
            ))}
          </div>
        )}
      </div>

      {selected && (
        <div>
          
          <div style={{
            display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 16,
            padding: '8px 12px', borderRadius: 8, marginBottom: 10,
            background: '#1c2333', border: '1px solid #30363d',
          }}>
            <ParserBadge name={selected.parser_name} />
            <span style={{ fontSize: 12, color: '#e6edf3' }}>
              {selected.evidence_name || '—'}
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#7d8590', fontFamily: 'monospace' }}>
              <Hash size={11} /> {total.toLocaleString()} enregistrements
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#7d8590', fontFamily: 'monospace' }}>
              <Calendar size={11} /> {fmtDate(selected.created_at)}
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#7d8590', fontFamily: 'monospace' }}>
              <User size={11} /> {selected.parsed_by || 'system'}
            </span>
            {columns.length > 0 && (
              <span style={{ fontSize: 11, color: '#7d8590', fontFamily: 'monospace' }}>
                {columns.length} colonnes détectées
              </span>
            )}
            <button
              onClick={async () => {
                try {
                  const { data } = await parsersAPI.exportResultCsv(selected.id);
                  const url = URL.createObjectURL(new Blob([data], { type: 'text/csv' }));
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `parser-${selected.parser_name}-${new Date(selected.created_at).toISOString().slice(0,10)}.csv`;
                  a.click();
                  URL.revokeObjectURL(url);
                } catch  }
              }}
              title="Exporter en CSV"
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '3px 10px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                background: 'transparent', border: '1px solid #30363d',
                color: '#7d8590', cursor: 'pointer', marginLeft: 'auto',
              }}
            >
              <Download size={11} /> CSV
            </button>
          </div>

          {isUnified && (
            <div style={{
              display: 'flex', gap: 6, flexWrap: 'wrap',
              padding: '8px 10px', borderRadius: 8, marginBottom: 10,
              background: '#0d1117', border: '1px solid #30363d',
            }}>
              {loadingTypes ? (
                <span style={{ fontSize: 11, color: '#7d8590', fontFamily: 'monospace' }}>
                  <Loader2 size={11} style={{ display: 'inline', marginRight: 4 }} className="animate-spin" />
                  Chargement des types…
                </span>
              ) : (
                <>
                  
                  <button
                    onClick={() => { setSelectedType(null); setPage(1); }}
                    style={{
                      padding: '3px 10px', borderRadius: 20, fontSize: 11,
                      fontFamily: 'monospace', fontWeight: 600, cursor: 'pointer',
                      background: selectedType === null ? '#4d82c018' : 'transparent',
                      color:      selectedType === null ? '#4d82c0'   : '#7d8590',
                      border:    `1px solid ${selectedType === null ? '#4d82c040' : '#30363d'}`,
                    }}
                  >
                    Tous
                    <span style={{
                      marginLeft: 5, fontSize: 10,
                      color: selectedType === null ? '#4d82c0' : '#484f58',
                    }}>
                      {selected.record_count?.toLocaleString() ?? ''}
                    </span>
                  </button>

                  {artifactTypes.map(({ artifact_type, count }) => {
                    const col = parserColor(artifact_type);
                    const active = selectedType === artifact_type;
                    return (
                      <button
                        key={artifact_type}
                        onClick={() => { setSelectedType(artifact_type); setPage(1); }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 5,
                          padding: '3px 10px', borderRadius: 20, fontSize: 11,
                          fontFamily: 'monospace', fontWeight: 600, cursor: 'pointer',
                          background: active ? `${col}18` : 'transparent',
                          color:      active ? col        : '#7d8590',
                          border:    `1px solid ${active ? col + '40' : '#30363d'}`,
                        }}
                      >
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%',
                          background: col, display: 'inline-block', flexShrink: 0,
                        }} />
                        {artifact_type}
                        <span style={{ fontSize: 10, color: active ? col : '#484f58' }}>
                          {count.toLocaleString()}
                        </span>
                      </button>
                    );
                  })}
                </>
              )}
            </div>
          )}

          {dataError && (
            <div style={{
              padding: '8px 12px', borderRadius: 6, marginBottom: 10, fontSize: 12,
              background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
              color: '#ef4444',
            }}>
              ⚠ {dataError}
            </div>
          )}

          <DataTable records={records} columns={columns} loading={loadingData} />

          <Pagination
            page={page}
            totalPages={totalPages}
            total={total}
            pageSize={PAGE_SIZE}
            onChange={(p) => setPage(p)}
          />
        </div>
      )}

      {confirmDelete && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,0,0,0.75)',
        }}>
          <div style={{
            background: '#1c2333', border: '1px solid #da363340',
            borderRadius: 12, padding: 24, width: '100%', maxWidth: 400,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: '#da363320', display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Trash2 size={18} style={{ color: '#da3633' }} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3' }}>Supprimer le résultat</div>
                <div style={{ fontSize: 11, color: '#7d8590', marginTop: 2 }}>Action irréversible</div>
              </div>
            </div>
            <p style={{ fontSize: 12, color: '#a0aec0', marginBottom: 20 }}>
              Supprimer le résultat <strong style={{ color: '#e6edf3' }}>{confirmDelete.parser_name}</strong> ({(confirmDelete.record_count ?? 0).toLocaleString()} enregistrements) ?<br /><br />
              Les entrées associées dans la collection timeline seront également supprimées.
            </p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button
                onClick={() => setConfirmDelete(null)}
                style={{
                  padding: '6px 14px', borderRadius: 6, fontSize: 12,
                  background: 'transparent', border: '1px solid #30363d',
                  color: '#7d8590', cursor: 'pointer',
                }}
              >
                Annuler
              </button>
              <button
                onClick={() => handleDeleteResult(confirmDelete)}
                style={{
                  padding: '6px 14px', borderRadius: 6, fontSize: 12,
                  background: '#da363318', border: '1px solid #da363340',
                  color: '#da3633', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                }}
              >
                <Trash2 size={12} /> Supprimer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
