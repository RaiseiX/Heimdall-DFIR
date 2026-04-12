import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useTranslation } from 'react-i18next';
import { collectionAPI, casesAPI } from '../utils/api';
import {
  Shield, AlertTriangle, Download, Play, Loader2, RefreshCw,
  FolderOpen, Search, X, ChevronLeft, ChevronRight,
} from 'lucide-react';
import { HAY_SEVERITY_BG } from '../constants/artifactColors';

const ROW_H    = 28;
const OVERSCAN = 12;

const LEVEL_COLORS = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      'var(--fl-ok)',
  info:     'var(--fl-dim)',
  informational: 'var(--fl-dim)',
};

const LEVEL_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };

// Column definitions
const COLS = [
  { key: 'timestamp',   label: 'Timestamp (UTC)', width: 172, mono: true },
  { key: 'level',       label: 'Level',           width: 82              },
  { key: 'event_id',    label: 'EID',              width: 54,  mono: true },
  { key: 'channel',     label: 'Channel',          width: 148, mono: true },
  { key: 'rule_title',  label: 'Règle Sigma',      flex: true             },
  { key: 'mitre',       label: 'MITRE',            width: 96,  mono: true },
  { key: 'tactic',      label: 'Tactic',           width: 118             },
];

function fmtTs(ts) {
  if (!ts) return '—';
  return String(ts).replace('T', ' ').replace('Z', '').substring(0, 23);
}

function Highlight({ text, term }) {
  const str = String(text ?? '');
  if (!term) return <>{str}</>;
  const idx = str.toLowerCase().indexOf(term.toLowerCase());
  if (idx === -1) return <>{str}</>;
  return (
    <>{str.slice(0, idx)}
      <mark style={{ background: '#f59e0b35', color: '#f59e0b', borderRadius: 2, padding: '0 1px' }}>
        {str.slice(idx, idx + term.length)}
      </mark>
      {str.slice(idx + term.length)}</>
  );
}

export default function HayabusaPage() {
  const { t } = useTranslation();

  const [cases, setCases]             = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [detections, setDetections]   = useState([]);
  const [stats, setStats]             = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [evtxCount, setEvtxCount]     = useState(0);
  const [loading, setLoading]         = useState(false);
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState('');
  const [hasRun, setHasRun]           = useState(false);

  const [search, setSearch]           = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [selId, setSelId]             = useState(null);
  const [starred, setStarred]         = useState(new Set());

  const tableContainerRef = useRef(null);

  // ── Load cases ───────────────────────────────────────────────────────────
  useEffect(() => {
    casesAPI.list({}).then(({ data }) => {
      const list = data.cases || [];
      setCases(list);
      if (list.length > 0) setSelectedCase(list[0].id);
    }).catch(() => {});
  }, []);

  // ── Load Hayabusa results for selected case ──────────────────────────────
  useEffect(() => {
    if (!selectedCase) return;
    setLoading(true);
    setError('');
    collectionAPI.getHayabusa(selectedCase).then(({ data }) => {
      if (data.timeline?.length > 0) {
        setDetections(data.timeline.map((d, i) => ({ ...d, _id: i })));
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
      setDetections((data.timeline || []).map((d, i) => ({ ...d, _id: i })));
      setStats(data.stats || {});
      setEvtxCount(data.evtx_files_processed || 0);
      setHasRun(true);
    } catch (err) {
      setError(err.response?.data?.error || t('common.error'));
    }
    setRunning(false);
  }, [selectedCase, t]);

  // ── Filtered rows ─────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let rows = detections;
    if (levelFilter !== 'all') rows = rows.filter(d => d.level === levelFilter);
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter(d =>
        (d.rule_title || d.ruleTitle || '').toLowerCase().includes(q) ||
        (d.details || '').toLowerCase().includes(q) ||
        (d.mitre_attack || d.mitre || '').toLowerCase().includes(q) ||
        (d.channel || '').toLowerCase().includes(q) ||
        (d.tactic || '').toLowerCase().includes(q) ||
        String(d.event_id || d.eventId || '').includes(q)
      );
    }
    return rows;
  }, [detections, levelFilter, search]);

  // Reset scroll on filter change
  useEffect(() => {
    if (tableContainerRef.current) tableContainerRef.current.scrollTop = 0;
    setSelId(null);
  }, [filtered]);

  // ── Virtualizer ───────────────────────────────────────────────────────────
  const rowVirtualizer = useVirtualizer({
    count:            filtered.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize:     () => ROW_H,
    overscan:         OVERSCAN,
  });

  const vItems     = rowVirtualizer.getVirtualItems();
  const totalH     = rowVirtualizer.getTotalSize();
  const padTop     = vItems.length > 0 ? (vItems[0]?.start ?? 0) : 0;
  const padBottom  = vItems.length > 0 ? totalH - (vItems[vItems.length - 1]?.end ?? 0) : 0;

  // ── Helpers ───────────────────────────────────────────────────────────────
  const getF = useCallback((d, ...keys) => {
    for (const k of keys) if (d[k] != null && d[k] !== '') return d[k];
    return '';
  }, []);

  const toggleStar = useCallback((id, e) => {
    e?.stopPropagation();
    setStarred(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }, []);

  const exportCSV = useCallback(() => {
    const header = 'Timestamp,Level,EventID,Channel,Règle,MITRE,Tactic,Détails';
    const rows = filtered.map(d => [
      d.timestamp, d.level,
      getF(d, 'event_id', 'eventId'),
      d.channel || '',
      getF(d, 'rule_title', 'ruleTitle'),
      getF(d, 'mitre_attack', 'mitre'),
      d.tactic || '',
      (d.details || '').replace(/,/g, ';'),
    ].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','));
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `hayabusa_${selectedCase}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  }, [filtered, selectedCase, getF]);

  // ── Selected row ──────────────────────────────────────────────────────────
  const selRow = selId != null ? detections.find(d => d._id === selId) : null;

  // ── Computed stats ────────────────────────────────────────────────────────
  const totalCount    = detections.length;
  const filteredCount = filtered.length;
  const starCount     = starred.size;

  // ── Navigate selected row ─────────────────────────────────────────────────
  const navigateSel = useCallback((dir) => {
    if (!selRow) return;
    const idx = filtered.findIndex(d => d._id === selId);
    const next = idx + dir;
    if (next >= 0 && next < filtered.length) {
      setSelId(filtered[next]._id);
      rowVirtualizer.scrollToIndex(next, { align: 'auto' });
    }
  }, [selRow, selId, filtered, rowVirtualizer]);

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* ── Toolbar ── */}
      <div className="fl-header" style={{ padding: '8px 16px 6px', flexDirection: 'column', alignItems: 'flex-start', gap: 6, flexShrink: 0 }}>
        {/* Row 1: title + counts */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
          <Shield size={15} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: 'var(--fl-text)' }}>
            Hayabusa
          </span>
          <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)' }}>JPCERT/CC · Sigma</span>
          {hasRun && (
            <>
              <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
                background: 'rgba(218,54,51,0.14)', color: 'var(--fl-danger)', border: '1px solid rgba(218,54,51,0.3)' }}>
                {totalCount} détections
              </span>
              <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                background: 'var(--fl-card)', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)' }}>
                {evtxCount} EVTX
              </span>
              {starCount > 0 && (
                <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                  background: '#f59e0b14', color: '#f59e0b', border: '1px solid #f59e0b30' }}>
                  ★ {starCount}
                </span>
              )}
            </>
          )}
        </div>

        {/* Row 2: case selector + actions */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', width: '100%' }}>
          <FolderOpen size={12} style={{ color: 'var(--fl-dim)', flexShrink: 0 }} />
          <select
            value={selectedCase}
            onChange={e => { setSelectedCase(e.target.value); setHasRun(false); setDetections([]); }}
            className="fl-select"
            style={{ fontSize: 11, padding: '3px 8px', flex: '0 1 320px', minWidth: 180 }}
          >
            <option value="">— Sélectionner un cas —</option>
            {cases.map(c => (
              <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
            ))}
          </select>

          <div style={{ width: 1, height: 18, background: 'var(--fl-sep)', flexShrink: 0 }} />

          <button
            onClick={runHayabusa}
            disabled={running || !selectedCase}
            className="fl-btn fl-btn-danger fl-btn-sm"
            style={{ opacity: !selectedCase ? 0.45 : 1 }}
          >
            {running
              ? <><Loader2 size={12} className="animate-spin" /> Analyse…</>
              : <><Play size={12} /> Lancer</>
            }
          </button>

          {hasRun && (
            <>
              <button onClick={runHayabusa} disabled={running} className="fl-btn fl-btn-ghost fl-btn-sm">
                <RefreshCw size={12} /> Relancer
              </button>
              <button onClick={exportCSV} className="fl-btn fl-btn-ghost fl-btn-sm">
                <Download size={12} /> CSV
              </button>
            </>
          )}
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div style={{ margin: '0 12px 6px', padding: '6px 10px', borderRadius: 6, fontSize: 11,
          background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: 'var(--fl-danger)',
          display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <AlertTriangle size={12} /> {error}
          <button onClick={() => setError('')} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}>
            <X size={12} />
          </button>
        </div>
      )}

      {/* ── Empty / Loading states ── */}
      {!hasRun && !loading && !running && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
          <Shield size={48} style={{ color: '#da363320' }} />
          <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 600, color: 'var(--fl-text)' }}>
            {t('hayabusa.empty')}
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', textAlign: 'center', maxWidth: 420 }}>
            Sélectionnez un cas contenant une collecte avec des fichiers EVTX,<br />
            puis cliquez sur "Lancer" pour parser avec les règles Sigma.
          </div>
          <div style={{ fontSize: 10, fontFamily: 'monospace', padding: '4px 10px', borderRadius: 4,
            background: 'var(--fl-card)', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)' }}>
            Import Collecte → Zimmerman (EVTX) → Hayabusa (Sigma)
          </div>
        </div>
      )}

      {loading && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
          <Loader2 size={20} className="animate-spin" style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--fl-dim)' }}>{t('hayabusa.loading')}</span>
        </div>
      )}

      {hasRun && !loading && (
        <>
          {/* ── Stats bar ── */}
          <div style={{ display: 'flex', gap: 6, padding: '5px 14px', borderBottom: '1px solid var(--fl-sep)', flexShrink: 0, flexWrap: 'wrap' }}>
            {['critical', 'high', 'medium', 'low'].map(lvl => {
              const col = LEVEL_COLORS[lvl];
              const cnt = stats[lvl] ?? 0;
              return (
                <span key={lvl} style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '2px 9px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
                  background: `${col}14`, color: col, border: `1px solid ${col}30` }}>
                  {lvl === 'critical' && <AlertTriangle size={9} />}
                  {lvl.toUpperCase()} <span style={{ opacity: 0.7, fontWeight: 400 }}>{cnt}</span>
                </span>
              );
            })}
          </div>

          {/* ── Filter bar ── */}
          <div style={{ display: 'flex', gap: 6, padding: '5px 10px', borderBottom: '1px solid var(--fl-sep)',
            alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
            {/* Search */}
            <div style={{ position: 'relative', flex: '1 1 200px', minWidth: 160 }}>
              <Search size={13} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-dim)' }} />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Règle, MITRE, EID, channel, tactic…"
                className="fl-input"
                style={{ paddingLeft: 28, width: '100%', fontSize: 11 }}
              />
              {search && (
                <button onClick={() => setSearch('')}
                  style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 0 }}>
                  <X size={11} />
                </button>
              )}
            </div>

            <div style={{ width: 1, height: 18, background: 'var(--fl-sep)' }} />

            {/* Level filter pills */}
            {['all', 'critical', 'high', 'medium', 'low'].map(l => {
              const col = LEVEL_COLORS[l] || 'var(--fl-accent)';
              const active = levelFilter === l;
              const cnt = l !== 'all' ? (stats[l] || 0) : totalCount;
              return (
                <button key={l} onClick={() => setLevelFilter(l)}
                  style={{
                    padding: '2px 9px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
                    cursor: 'pointer', textTransform: 'uppercase',
                    background: active ? `${col}18` : 'transparent',
                    color: active ? col : 'var(--fl-dim)',
                    border: `1px solid ${active ? col + '40' : 'var(--fl-border)'}`,
                  }}>
                  {l === 'all' ? 'Tous' : l}
                  {l !== 'all' && <span style={{ marginLeft: 4, opacity: 0.65, fontWeight: 400 }}>({cnt})</span>}
                </button>
              );
            })}

            <div style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
              {filteredCount !== totalCount
                ? <span>{filteredCount} <span style={{ opacity: 0.5 }}>/ {totalCount}</span></span>
                : <span>{totalCount} résultats</span>
              }
              {starCount > 0 && <span style={{ color: '#f59e0b', marginLeft: 6 }}>★ {starCount}</span>}
            </div>
          </div>

          {/* ── Table + Detail Panel ── */}
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0 }}>

            {/* Table area */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>

              {/* Fixed header */}
              <div style={{ flexShrink: 0, overflowX: 'hidden', borderBottom: '1px solid var(--fl-sep)' }}>
                <table style={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse' }}>
                  <colgroup>
                    <col style={{ width: 28 }} />
                    <col style={{ width: 28 }} />
                    {COLS.map(c => <col key={c.key} style={{ width: c.flex ? undefined : c.width }} />)}
                  </colgroup>
                  <thead>
                    <tr style={{ background: 'var(--fl-card)' }}>
                      <th style={{ padding: '4px 6px', fontSize: 9, fontFamily: 'monospace',
                        color: 'var(--fl-muted)', fontWeight: 600, textAlign: 'center', borderBottom: '1px solid var(--fl-sep)' }}>
                        ★
                      </th>
                      <th style={{ padding: '4px 0', borderBottom: '1px solid var(--fl-sep)' }} />
                      {COLS.map(c => (
                        <th key={c.key} style={{
                          padding: '4px 8px', fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
                          color: 'var(--fl-muted)', textAlign: 'left', textTransform: 'uppercase',
                          letterSpacing: '0.06em', borderBottom: '1px solid var(--fl-sep)',
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>
                          {c.label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                </table>
              </div>

              {/* Virtualized body */}
              <div ref={tableContainerRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>
                {filtered.length === 0 ? (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                    height: 200, fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)' }}>
                    Aucun résultat
                  </div>
                ) : (
                  <div style={{ height: totalH, position: 'relative' }}>
                    {padTop > 0 && <div style={{ height: padTop }} />}
                    <table style={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse' }}>
                      <colgroup>
                        <col style={{ width: 28 }} />
                        <col style={{ width: 28 }} />
                        {COLS.map(c => <col key={c.key} style={{ width: c.flex ? undefined : c.width }} />)}
                      </colgroup>
                      <tbody>
                        {vItems.map(vRow => {
                          const d         = filtered[vRow.index];
                          const rTitle    = getF(d, 'rule_title', 'ruleTitle');
                          const eid       = getF(d, 'event_id', 'eventId');
                          const mitre     = getF(d, 'mitre_attack', 'mitre');
                          const levelCol  = LEVEL_COLORS[d.level] || 'var(--fl-dim)';
                          const isSel     = d._id === selId;
                          const isStar    = starred.has(d._id);
                          const isCrit    = d.level === 'critical';
                          const rowBg     = isSel
                            ? `${levelCol}12`
                            : HAY_SEVERITY_BG[d.level] || 'transparent';

                          return (
                            <tr
                              key={d._id}
                              onClick={() => setSelId(isSel ? null : d._id)}
                              style={{
                                height: ROW_H, cursor: 'pointer',
                                background: rowBg,
                                borderLeft: isSel
                                  ? `3px solid ${levelCol}`
                                  : isCrit
                                    ? `3px solid ${levelCol}60`
                                    : isStar
                                      ? '3px solid #f59e0b50'
                                      : '3px solid transparent',
                                outline: isSel ? `1px solid ${levelCol}20` : 'none',
                              }}
                            >
                              {/* Star */}
                              <td onClick={e => toggleStar(d._id, e)}
                                style={{ textAlign: 'center', fontSize: 12, cursor: 'pointer',
                                  color: isStar ? '#f59e0b' : 'var(--fl-panel)',
                                  padding: '2px 4px' }}>
                                {isStar ? '★' : '☆'}
                              </td>

                              {/* Severity indicator dot */}
                              <td style={{ padding: '2px 4px', textAlign: 'center' }}>
                                <span style={{ display: 'inline-block', width: 6, height: 6,
                                  borderRadius: '50%', background: levelCol, opacity: isCrit ? 1 : 0.7 }} />
                              </td>

                              {/* Timestamp */}
                              <td style={{ padding: '2px 8px', fontFamily: 'monospace', fontSize: 10,
                                color: 'var(--fl-accent)', whiteSpace: 'nowrap', overflow: 'hidden' }}>
                                {fmtTs(d.timestamp)}
                              </td>

                              {/* Level */}
                              <td style={{ padding: '2px 8px', overflow: 'hidden' }}>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3,
                                  padding: '1px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                                  background: `${levelCol}18`, color: levelCol, border: `1px solid ${levelCol}28`,
                                  textTransform: 'uppercase' }}>
                                  {isCrit && <AlertTriangle size={8} />}
                                  {d.level}
                                </span>
                              </td>

                              {/* EID */}
                              <td style={{ padding: '2px 8px', fontFamily: 'monospace', fontSize: 10,
                                fontWeight: 700, color: 'var(--fl-warn)', overflow: 'hidden' }}>
                                <Highlight text={eid} term={search} />
                              </td>

                              {/* Channel */}
                              <td style={{ padding: '2px 8px', fontFamily: 'monospace', fontSize: 10,
                                color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                <Highlight text={d.channel || ''} term={search} />
                              </td>

                              {/* Rule title */}
                              <td style={{ padding: '2px 8px', fontSize: 11, fontWeight: isCrit ? 600 : 400,
                                color: isCrit ? 'var(--fl-danger)' : 'var(--fl-text)',
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                <Highlight text={rTitle} term={search} />
                              </td>

                              {/* MITRE */}
                              <td style={{ padding: '2px 8px', overflow: 'hidden' }}>
                                {mitre && (
                                  <span style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 600,
                                    padding: '1px 5px', borderRadius: 3,
                                    background: '#4d82c014', color: 'var(--fl-accent)', border: '1px solid #4d82c028',
                                    whiteSpace: 'nowrap' }}>
                                    <Highlight text={mitre} term={search} />
                                  </span>
                                )}
                              </td>

                              {/* Tactic */}
                              <td style={{ padding: '2px 8px', fontSize: 10, color: 'var(--fl-dim)',
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                <Highlight text={d.tactic || ''} term={search} />
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {padBottom > 0 && <div style={{ height: padBottom }} />}
                  </div>
                )}
              </div>
            </div>

            {/* ── Detail Panel ── */}
            {selRow && (() => {
              const rTitle   = getF(selRow, 'rule_title', 'ruleTitle');
              const eid      = getF(selRow, 'event_id', 'eventId');
              const mitre    = getF(selRow, 'mitre_attack', 'mitre');
              const tactic   = getF(selRow, 'tactic');
              const details  = getF(selRow, 'details');
              const computer = getF(selRow, 'computer');
              const source   = getF(selRow, 'source');
              const levelCol = LEVEL_COLORS[selRow.level] || 'var(--fl-dim)';
              const selIdx   = filtered.findIndex(d => d._id === selId);

              return (
                <div style={{
                  width: 360, flexShrink: 0, overflowY: 'auto',
                  borderLeft: `3px solid ${levelCol}`,
                  boxShadow: '-4px 0 20px rgba(0,0,0,0.5)',
                  background: '#0a0f1a',
                  display: 'flex', flexDirection: 'column',
                }}>
                  {/* Panel header */}
                  <div style={{ padding: '8px 12px 6px', borderBottom: `1px solid ${levelCol}25`,
                    background: `${levelCol}08`, flexShrink: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                      <button onClick={() => setSelId(null)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--fl-dim)', padding: 0, display: 'flex', alignItems: 'center' }}>
                        <X size={13} />
                      </button>
                      <span style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-muted)' }}>
                        {selIdx + 1} / {filteredCount}
                      </span>
                      <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
                        <button onClick={() => navigateSel(-1)} disabled={selIdx === 0}
                          style={{ background: 'none', border: 'none', cursor: selIdx === 0 ? 'default' : 'pointer',
                            color: selIdx === 0 ? 'var(--fl-panel)' : 'var(--fl-dim)', padding: 2 }}>
                          <ChevronLeft size={13} />
                        </button>
                        <button onClick={() => navigateSel(1)} disabled={selIdx === filteredCount - 1}
                          style={{ background: 'none', border: 'none',
                            cursor: selIdx === filteredCount - 1 ? 'default' : 'pointer',
                            color: selIdx === filteredCount - 1 ? 'var(--fl-panel)' : 'var(--fl-dim)', padding: 2 }}>
                          <ChevronRight size={13} />
                        </button>
                        <button onClick={e => toggleStar(selRow._id, e)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2,
                            fontSize: 14, color: starred.has(selRow._id) ? '#f59e0b' : 'var(--fl-dim)' }}>
                          {starred.has(selRow._id) ? '★' : '☆'}
                        </button>
                      </div>
                    </div>

                    {/* Level + MITRE + Tactic badges */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                        background: `${levelCol}18`, color: levelCol, border: `1px solid ${levelCol}35`,
                        textTransform: 'uppercase', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                        {selRow.level === 'critical' && <AlertTriangle size={8} />}
                        {selRow.level?.toUpperCase()}
                      </span>
                      {mitre && (
                        <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
                          background: '#4d82c018', color: 'var(--fl-accent)', border: '1px solid #4d82c030' }}>
                          ATT&CK {mitre}
                        </span>
                      )}
                      {tactic && (
                        <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
                          background: 'var(--fl-card)', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)' }}>
                          {tactic}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Panel body */}
                  <div style={{ padding: '10px 12px', flex: 1 }}>
                    {/* Rule title */}
                    <div style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600,
                      color: selRow.level === 'critical' ? 'var(--fl-danger)' : 'var(--fl-text)',
                      marginBottom: 8, lineHeight: 1.4 }}>
                      {rTitle}
                    </div>

                    {/* Details */}
                    {details && (
                      <div style={{ padding: '6px 9px', fontFamily: 'monospace', fontSize: 10,
                        color: 'var(--fl-on-dark)', background: `${levelCol}0c`, borderRadius: 5,
                        border: `1px solid ${levelCol}30`, marginBottom: 10, lineHeight: 1.6,
                        wordBreak: 'break-word' }}>
                        {details}
                      </div>
                    )}

                    {/* Key fields grid */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {[
                        ['Timestamp',  fmtTs(selRow.timestamp)],
                        ['Event ID',   eid],
                        ['Channel',    selRow.channel],
                        ['Computer',   computer],
                        ['Source',     source],
                      ].filter(([, v]) => v).map(([label, value]) => (
                        <div key={label} style={{ borderRadius: 4, overflow: 'hidden', border: `1px solid ${levelCol}22` }}>
                          <div style={{ fontFamily: 'monospace', fontSize: 9, color: levelCol,
                            padding: '2px 7px', background: `${levelCol}14`,
                            textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>
                            {label}
                          </div>
                          <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#c0cfe0',
                            padding: '4px 7px', wordBreak: 'break-all', lineHeight: 1.5,
                            background: '#0b101a', borderTop: `1px solid ${levelCol}14` }}>
                            {String(value).substring(0, 300)}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Raw data */}
                    {selRow.raw && Object.keys(selRow.raw).length > 0 && (
                      <details style={{ marginTop: 10 }}>
                        <summary style={{ fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                          color: 'var(--fl-dim)', padding: '3px 0' }}>
                          Données brutes EVTX
                        </summary>
                        <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 3 }}>
                          {Object.entries(selRow.raw).filter(([, v]) => v !== '' && v != null).map(([k, v]) => (
                            <div key={k} style={{ borderRadius: 3, overflow: 'hidden', border: `1px solid ${levelCol}18` }}>
                              <div style={{ fontFamily: 'monospace', fontSize: 9, color: levelCol,
                                padding: '2px 6px', background: `${levelCol}14`,
                                textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                                {k}
                              </div>
                              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#b0c0d8',
                                padding: '3px 6px', wordBreak: 'break-all', lineHeight: 1.4,
                                background: '#0b101a', borderTop: `1px solid ${levelCol}12` }}>
                                {String(v).substring(0, 400)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>

          {/* ── Bottom bar ── */}
          <div style={{ borderTop: '1px solid var(--fl-sep)', padding: '4px 12px',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            flexShrink: 0, background: 'var(--fl-bg)' }}>
            <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)' }}>
              Hayabusa v2.x · Sigma · JPCERT/CC
            </span>
            <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-danger)' }}>
              {evtxCount} EVTX · {totalCount} détections
            </span>
          </div>
        </>
      )}
    </div>
  );
}
