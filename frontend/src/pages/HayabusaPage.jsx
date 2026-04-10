import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useTheme } from '../utils/theme';
import { useTranslation } from 'react-i18next';
import { collectionAPI, casesAPI } from '../utils/api';
import { Shield, AlertTriangle, Download, Play, Loader2, RefreshCw, FolderOpen, Search, Star, X } from 'lucide-react';

const LEVEL_COLORS = { critical: '#da3633', high: '#d97c20', medium: '#c89d1d', low: '#3fb950', info: '#7d8590' };
const TACTIC_COLORS = {
  Execution: '#ef4444', Persistence: '#d97c20', 'Defense Evasion': '#c89d1d',
  Discovery: '#22c55e', 'Privilege Escalation': '#c96898', 'Lateral Movement': '#8b72d6',
  'Command and Control': '#4d82c0', 'Credential Access': '#f43f5e',
};

const ROW_H    = 36;
const OVERSCAN = 10;

export default function HayabusaPage() {
  const T = useTheme();
  const { t } = useTranslation();

  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [detections, setDetections] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [evtxCount, setEvtxCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [hasRun, setHasRun] = useState(false);

  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [selRow, setSelRow] = useState(null);
  const [highlights, setHighlights] = useState(new Set());

  const tableContainerRef = useRef(null);

  useEffect(() => {
    casesAPI.list({}).then(({ data }) => {
      setCases(data.cases || []);
      if (data.cases?.length > 0) setSelectedCase(data.cases[0].id);
    }).catch(() => {
      const demo = [
        { id: '1', case_number: 'CASE-2026-001', title: 'Intrusion Serveur Principal' },
        { id: '2', case_number: 'CASE-2026-002', title: 'Ransomware Dept. Finance' },
        { id: '3', case_number: 'CASE-2026-003', title: 'Analyse Clé USB Suspecte' },
      ];
      setCases(demo);
      setSelectedCase(demo[0].id);
    });
  }, []);

  useEffect(() => {
    if (!selectedCase) return;
    setLoading(true);
    setError('');
    collectionAPI.getHayabusa(selectedCase).then(({ data }) => {
      if (data.timeline && data.timeline.length > 0) {
        setDetections(data.timeline.map((d, i) => ({ ...d, id: i })));
        setStats(data.stats || {});
        setEvtxCount(data.evtx_files_count || 0);
        setHasRun(true);
      } else {
        setDetections([]);
        setStats({ critical: 0, high: 0, medium: 0, low: 0 });
        setHasRun(false);
      }
    }).catch(() => {
      setDetections([]);
      setHasRun(false);
    }).finally(() => setLoading(false));
  }, [selectedCase]);

  const runHayabusa = useCallback(async () => {
    if (!selectedCase) return;
    setRunning(true);
    setError('');
    try {
      const { data } = await collectionAPI.runHayabusa(selectedCase);
      setDetections((data.timeline || []).map((d, i) => ({ ...d, id: i })));
      setStats(data.stats || {});
      setEvtxCount(data.evtx_files_processed || 0);
      setHasRun(true);
    } catch (err) {
      setError(err.response?.data?.error || t('common.error'));
    }
    setRunning(false);
  }, [selectedCase, t]);

  const filtered = useMemo(() => {
    return detections.filter(d => {
      if (levelFilter !== 'all' && d.level !== levelFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (d.rule_title || d.ruleTitle || '').toLowerCase().includes(q)
          || (d.details || '').toLowerCase().includes(q)
          || (d.mitre_attack || d.mitre || '').toLowerCase().includes(q)
          || (d.channel || '').toLowerCase().includes(q)
          || String(d.event_id || d.eventId || '').includes(q);
      }
      return true;
    });
  }, [detections, levelFilter, search]);

  useEffect(() => {
    if (tableContainerRef.current) tableContainerRef.current.scrollTop = 0;
  }, [filtered]);

  const toggleHL = useCallback((id) => {
    setHighlights(p => {
      const n = new Set(p);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }, []);

  const getField = useCallback((d, ...keys) => {
    for (const k of keys) if (d[k] != null && d[k] !== '') return d[k];
    return '';
  }, []);

  const exportCSV = useCallback(() => {
    const rows = filtered.map(d =>
      [d.timestamp, d.level, d.event_id || d.eventId || '', d.channel,
       d.rule_title || d.ruleTitle || '', d.mitre_attack || d.mitre || '',
       (d.details || '').replace(/,/g, ';')].join(',')
    );
    const blob = new Blob(['Timestamp,Level,EventID,Channel,Rule,MITRE,Details\n' + rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `hayabusa_${selectedCase}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  }, [filtered, selectedCase]);

  const rowVirtualizer = useVirtualizer({
    count:          filtered.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize:   () => ROW_H,
    overscan:       OVERSCAN,
  });

  const virtualItems    = rowVirtualizer.getVirtualItems();
  const totalVirtualH   = rowVirtualizer.getTotalSize();
  const paddingTop      = virtualItems.length > 0 ? (virtualItems[0]?.start ?? 0) : 0;
  const paddingBottom   = virtualItems.length > 0
    ? totalVirtualH - (virtualItems[virtualItems.length - 1]?.end ?? 0)
    : 0;

  return (
    <div className="p-6">
      
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">
            <Shield size={20} className="inline mr-2" style={{ color: '#da3633', verticalAlign: 'text-bottom' }} />
            Hayabusa — JPCERT/CC
          </h1>
          <p className="fl-header-sub">
            Parser les fichiers EVTX avec les règles Sigma
            {hasRun && <span> · <span style={{ color: '#da3633' }}>{detections.length} détections</span> · {evtxCount} EVTX parsés</span>}
          </p>
        </div>
        {hasRun && (
          <div className="flex gap-2">
            <button onClick={exportCSV} className="fl-btn fl-btn-secondary fl-btn-sm">
              <Download size={13} /> CSV
            </button>
            <button onClick={runHayabusa} disabled={running} className="fl-btn fl-btn-secondary fl-btn-sm">
              <RefreshCw size={13} /> Relancer
            </button>
          </div>
        )}
      </div>

      <div className="flex gap-3 mb-6 items-end">
        <div className="flex-1">
          <label className="fl-label">
            <FolderOpen size={11} className="inline mr-1" /> Cas source (collecte Magnet RESPONSE)
          </label>
          <select
            value={selectedCase}
            onChange={e => setSelectedCase(e.target.value)}
            className="fl-select w-full"
          >
            <option value="">— Sélectionner un cas —</option>
            {cases.map(c => (
              <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
            ))}
          </select>
        </div>
        <button
          onClick={runHayabusa}
          disabled={running || !selectedCase}
          className="fl-btn fl-btn-danger"
          style={{ opacity: !selectedCase ? 0.45 : 1, whiteSpace: 'nowrap' }}
        >
          {running
            ? <><Loader2 size={14} className="animate-spin" /> Analyse…</>
            : <><Play size={14} /> Lancer Hayabusa</>
          }
        </button>
      </div>

      {error && (
        <div className="rounded-lg p-3 mb-4 text-sm flex items-center gap-2"
          style={{ background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: '#da3633' }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError('')} className="ml-auto"><X size={14} /></button>
        </div>
      )}

      {!hasRun && !loading && !running && (
        <div className="fl-empty" style={{ minHeight: 320 }}>
          <Shield size={48} className="fl-empty-icon" style={{ color: '#da363330' }} />
          <div className="fl-empty-title">{t('hayabusa.empty')}</div>
          <div className="fl-empty-sub">
            Sélectionnez un cas contenant une collecte Magnet RESPONSE avec des fichiers EVTX,<br />
            puis cliquez sur "Lancer Hayabusa" pour parser les Event Logs avec les règles Sigma.
          </div>
          <div className="mt-4 text-xs font-mono px-3 py-1.5 rounded" style={{ background: '#1c2333', border: '1px solid #30363d', color: '#484f58' }}>
            Import Collecte → Zimmerman (EVTX) → Hayabusa (Sigma)
          </div>
        </div>
      )}

      {loading && (
        <div className="text-center py-12">
          <Loader2 size={24} className="animate-spin mx-auto mb-3" style={{ color: '#4d82c0' }} />
          <div className="text-sm" style={{ color: '#7d8590' }}>{t('hayabusa.loading')}</div>
        </div>
      )}

      {hasRun && !loading && (
        <>
          
          <div className="grid grid-cols-5 gap-3 mb-5">
            {['critical', 'high', 'medium', 'low'].map(level => {
              const count = stats[level] ?? 0;
              const color = LEVEL_COLORS[level] || T.dim;
              return (
                <div key={level} className="rounded-lg p-4 border"
                  style={{ background: '#1c2333', borderColor: '#30363d', borderLeft: `3px solid ${color}` }}>
                  <div className="font-mono text-2xl font-bold mb-1" style={{ color: '#e6edf3' }}>{count}</div>
                  <div className="text-xs font-mono uppercase tracking-wider" style={{ color }}>{level}</div>
                </div>
              );
            })}
            <div className="rounded-lg p-4 border"
              style={{ background: '#1c2333', borderColor: '#30363d', borderLeft: `3px solid ${T.accent}` }}>
              <div className="font-mono text-2xl font-bold mb-1" style={{ color: '#e6edf3' }}>{evtxCount}</div>
              <div className="text-xs font-mono uppercase tracking-wider" style={{ color: T.accent }}>EVTX parsés</div>
            </div>
          </div>

          <div className="fl-filters mb-4">
            <div className="fl-search flex-1">
              <Search size={14} className="fl-search-icon" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Règle, MITRE, Event ID, channel…"
                className="fl-input"
                style={{ paddingLeft: 34 }}
              />
            </div>
            <div className="flex gap-1">
              {['all', 'critical', 'high', 'medium', 'low'].map(l => {
                const color = LEVEL_COLORS[l] || T.accent;
                const active = levelFilter === l;
                return (
                  <button key={l} onClick={() => setLevelFilter(l)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold uppercase"
                    style={{
                      background: active ? `${color}18` : 'transparent',
                      color: active ? color : '#7d8590',
                      border: `1px solid ${active ? color + '40' : '#30363d'}`,
                    }}>
                    {l === 'all' ? t('hayabusa.all_levels') : l}
                    {l !== 'all' && <span className="ml-1 opacity-70">({stats[l] || 0})</span>}
                  </button>
                );
              })}
            </div>
            <span className="text-xs font-mono" style={{ color: '#7d8590' }}>
              {filtered.length} détection{filtered.length !== 1 ? 's' : ''}
              {highlights.size > 0 && <span style={{ color: '#f59e0b' }}> · {highlights.size} ★</span>}
            </span>
          </div>

          <div className="fl-card" style={{ overflow: 'hidden' }}>
            
            <table className="fl-table" style={{ tableLayout: 'fixed', width: '100%' }}>
              <colgroup>
                <col style={{ width: 36 }} />
                <col style={{ width: 160 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 60 }} />
                <col style={{ width: 120 }} />
                <col />
                <col style={{ width: 110 }} />
                <col style={{ width: 200 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>★</th>
                  <th>Timestamp</th>
                  <th>Level</th>
                  <th>EID</th>
                  <th>Channel</th>
                  <th>Règle Sigma</th>
                  <th>MITRE</th>
                  <th>Détails</th>
                </tr>
              </thead>
            </table>

            <div
              ref={tableContainerRef}
              style={{ overflowY: 'auto', height: 480 }}
            >
              <table className="fl-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                <colgroup>
                  <col style={{ width: 36 }} />
                  <col style={{ width: 160 }} />
                  <col style={{ width: 80 }} />
                  <col style={{ width: 60 }} />
                  <col style={{ width: 120 }} />
                  <col />
                  <col style={{ width: 110 }} />
                  <col style={{ width: 200 }} />
                </colgroup>
                <tbody>
                  {paddingTop > 0 && <tr><td colSpan={8} style={{ height: paddingTop, padding: 0 }} /></tr>}

                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-sm" style={{ color: '#7d8590' }}>
                        {t('common.none')}
                      </td>
                    </tr>
                  ) : (
                    virtualItems.map(vRow => {
                      const d = filtered[vRow.index];
                      const rTitle = getField(d, 'rule_title', 'ruleTitle');
                      const eid    = getField(d, 'event_id', 'eventId');
                      const mitre  = getField(d, 'mitre_attack', 'mitre');
                      const details = getField(d, 'details');
                      const isHL   = highlights.has(d.id);
                      const isSel  = selRow === d.id;
                      const isCrit = d.level === 'critical';
                      const levelColor = LEVEL_COLORS[d.level] || '#7d8590';

                      return (
                        <tr
                          key={d.id ?? vRow.index}
                          data-index={vRow.index}
                          onClick={() => setSelRow(isSel ? null : d.id)}
                          style={{
                            height: ROW_H,
                            cursor: 'pointer',
                            background: isHL ? '#f59e0b08' : isSel ? `${levelColor}06` : 'transparent',
                            borderLeft: isCrit ? `3px solid ${levelColor}` : isHL ? `3px solid ${levelColor}50` : '3px solid transparent',
                          }}
                        >
                          <td
                            onClick={e => { e.stopPropagation(); toggleHL(d.id); }}
                            style={{ textAlign: 'center', color: isHL ? '#f59e0b' : '#484f58', cursor: 'pointer', fontSize: 13 }}
                          >
                            {isHL ? '★' : '☆'}
                          </td>
                          <td className="fl-td-mono fl-td-dim" style={{ fontSize: '0.7rem', whiteSpace: 'nowrap', overflow: 'hidden', maxWidth: 160 }}>
                            {(d.timestamp || '').replace('T', ' ').replace('Z', '').substring(0, 19)}
                          </td>
                          <td style={{ overflow: 'hidden' }}>
                            <span className="fl-badge" style={{ background: `${levelColor}14`, color: levelColor, border: `1px solid ${levelColor}28` }}>
                              {isCrit && <AlertTriangle size={9} className="inline mr-1" />}{d.level}
                            </span>
                          </td>
                          <td className="fl-td-mono font-bold" style={{ color: '#d97c20', fontSize: '0.75rem' }}>{eid}</td>
                          <td className="fl-td-dim" style={{ fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.channel}</td>
                          <td className="text-xs font-semibold" style={{ color: isCrit ? '#da3633' : '#e6edf3', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {rTitle}
                          </td>
                          <td>
                            {mitre && (
                              <span className="fl-badge" style={{ background: '#4d82c014', color: '#4d82c0', border: '1px solid #4d82c028' }}>
                                {mitre}
                              </span>
                            )}
                          </td>
                          <td className="fl-td-dim" style={{ fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {details}
                          </td>
                        </tr>
                      );
                    })
                  )}

                  {paddingBottom > 0 && <tr><td colSpan={8} style={{ height: paddingBottom, padding: 0 }} /></tr>}
                </tbody>
              </table>
            </div>
          </div>

          {selRow != null && (() => {
            const d = detections.find(x => x.id === selRow);
            if (!d) return null;
            const rTitle  = getField(d, 'rule_title', 'ruleTitle');
            const eid     = getField(d, 'event_id', 'eventId');
            const mitre   = getField(d, 'mitre_attack', 'mitre');
            const tactic  = getField(d, 'tactic');
            const details = getField(d, 'details');
            const computer = getField(d, 'computer');
            const levelColor = LEVEL_COLORS[d.level] || '#7d8590';

            return (
              <div className="mt-4 rounded-xl p-4 border"
                style={{ background: `${levelColor}06`, borderColor: '#30363d', borderLeft: `3px solid ${levelColor}` }}>
                <div className="flex gap-2 mb-3 flex-wrap">
                  <span className="fl-badge" style={{ background: `${levelColor}14`, color: levelColor }}>
                    {d.level?.toUpperCase()}
                  </span>
                  {mitre && (
                    <span className="fl-badge" style={{ background: '#4d82c014', color: '#4d82c0' }}>
                      ATT&CK {mitre}
                    </span>
                  )}
                  {tactic && (
                    <span className="fl-badge" style={{ background: `${TACTIC_COLORS[tactic] || '#7d8590'}14`, color: TACTIC_COLORS[tactic] || '#7d8590' }}>
                      {tactic}
                    </span>
                  )}
                </div>
                <div className="font-semibold mb-2" style={{ color: '#e6edf3' }}>{rTitle}</div>
                <div className="text-sm mb-3" style={{ color: '#7d8590' }}>{details}</div>
                <div className="grid grid-cols-4 gap-3 text-xs font-mono" style={{ color: '#7d8590' }}>
                  <div><span className="font-bold" style={{ color: '#da3633' }}>Computer:</span> {computer}</div>
                  <div><span className="font-bold" style={{ color: '#da3633' }}>Event ID:</span> {eid}</div>
                  <div><span className="font-bold" style={{ color: '#da3633' }}>Channel:</span> {d.channel}</div>
                  <div><span className="font-bold" style={{ color: '#da3633' }}>Source:</span> {d.source}</div>
                </div>
                {d.raw && (
                  <details className="mt-3">
                    <summary className="text-xs font-mono cursor-pointer" style={{ color: '#7d8590' }}>
                      Données brutes EVTX
                    </summary>
                    <pre className="mt-2 p-3 rounded-lg text-xs overflow-auto"
                      style={{ background: '#0d1117', border: '1px solid #30363d', color: '#7d8590', maxHeight: 200, fontFamily: 'monospace' }}>
                      {JSON.stringify(d.raw, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            );
          })()}

          {highlights.size > 0 && (
            <div className="mt-4 fl-card p-4">
              <div className="text-xs font-mono font-bold mb-3" style={{ color: '#f59e0b' }}>
                ★ {highlights.size} détection{highlights.size > 1 ? 's' : ''} surlignée{highlights.size > 1 ? 's' : ''}
              </div>
              {detections.filter(d => highlights.has(d.id)).map(d => {
                const levelColor = LEVEL_COLORS[d.level] || '#7d8590';
                return (
                  <div key={d.id} className="flex items-center gap-3 py-1.5" style={{ borderBottom: '1px solid #21262d' }}>
                    <span className="font-mono text-xs" style={{ color: '#484f58', width: 155 }}>
                      {(d.timestamp || '').replace('T', ' ').replace('Z', '').substring(0, 23)}
                    </span>
                    <span className="fl-badge" style={{ background: `${levelColor}14`, color: levelColor }}>{d.level}</span>
                    <span className="text-xs font-semibold flex-1" style={{ color: '#e6edf3' }}>
                      {getField(d, 'rule_title', 'ruleTitle')}
                    </span>
                    <button onClick={() => toggleHL(d.id)} style={{ color: '#da3633', fontSize: 11 }}>✕</button>
                  </div>
                );
              })}
            </div>
          )}

          <div className="mt-5 flex justify-between items-center text-xs font-mono" style={{ color: '#484f58' }}>
            <span>Hayabusa v2.x · Règles Sigma · JPCERT/CC</span>
            <span style={{ color: '#da3633' }}>{evtxCount} EVTX · {detections.length} détections totales</span>
          </div>
        </>
      )}
    </div>
  );
}
