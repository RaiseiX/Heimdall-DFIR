import { useState, useEffect, useCallback } from 'react';
import { collectionAPI } from '../../utils/api';
import { useDateFormat } from '../../hooks/useDateFormat';
import {
  Shield, AlertTriangle, Download, Play, Loader2, RefreshCw,
  Search, Star, ChevronDown, ChevronUp, X,
} from 'lucide-react';

const LEVEL_COLORS = {
  critical:      '#da3633',
  high:          '#d97c20',
  medium:        '#c89d1d',
  low:           '#3fb950',
  informational: '#7d8590',
  info:          '#7d8590',
};

const TACTIC_COLORS = {
  Execution:              '#ef4444',
  Persistence:            '#d97c20',
  'Defense Evasion':      '#c89d1d',
  Discovery:              '#22c55e',
  'Privilege Escalation': '#c96898',
  'Lateral Movement':     '#8b72d6',
  'Command and Control':  '#00ccff',
  'Credential Access':    '#f43f5e',
  'Initial Access':       '#d97c20',
  'Collection':           '#8b5cf6',
  'Exfiltration':         '#06b6d4',
  'Impact':               '#ef4444',
};

const LEVELS = ['critical', 'high', 'medium', 'low'];

const LEVEL_ROW_BG = {
  critical:      '#da363312',
  high:          '#f0883e0d',
  medium:        '#c89d1d09',
  low:           'transparent',
  informational: 'transparent',
  info:          'transparent',
};

const getField = (d, ...keys) => {
  for (const k of keys) if (d[k] != null && d[k] !== '') return d[k];
  return '';
};

const fmtTs = (ts) => (ts || '').replace('T', ' ').replace('Z', '').substring(0, 19);

function LevelBadge({ level }) {
  const col = LEVEL_COLORS[level] || '#7d8590';
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-bold"
      style={{ background: `${col}18`, color: col, border: `1px solid ${col}30` }}>
      {level === 'critical' && <AlertTriangle size={9} />}
      {level}
    </span>
  );
}

function MitreBadge({ mitre, tactic }) {
  if (!mitre && !tactic) return null;
  const tacticCol = TACTIC_COLORS[tactic] || '#7d8590';
  return (
    <div className="flex flex-wrap gap-1">
      {mitre && (
        <span className="px-1.5 py-0.5 rounded text-xs font-mono font-bold"
          style={{ background: '#4d82c014', color: '#4d82c0', border: '1px solid #4d82c028' }}>
          {mitre}
        </span>
      )}
      {tactic && (
        <span className="px-1.5 py-0.5 rounded text-xs font-mono"
          style={{ background: `${tacticCol}12`, color: tacticCol, border: `1px solid ${tacticCol}25` }}>
          {tactic}
        </span>
      )}
    </div>
  );
}

export default function CaseHayabusaView({ caseId, reloadKey = 0, onTotalChange }) {
  const { fmtDateTime } = useDateFormat();
  const [detections, setDetections]   = useState([]);
  const [stats, setStats]             = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [evtxCount, setEvtxCount]     = useState(0);
  const [loading, setLoading]         = useState(false);
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState('');
  const [hasData, setHasData]         = useState(false);
  const [generatedAt, setGeneratedAt] = useState(null);

  const [search, setSearch]           = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [tacticFilter, setTacticFilter] = useState('all');

  const [selId, setSelId]             = useState(null);
  const [highlights, setHighlights]   = useState(new Set());
  const [showHL, setShowHL]           = useState(false);

  const loadData = useCallback(async (cid) => {
    if (!cid) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await collectionAPI.getHayabusa(cid);
      if (data.timeline && data.timeline.length > 0) {
        const mapped = data.timeline.map((d, i) => ({ ...d, _id: i }));
        setDetections(mapped);
        setStats(data.stats || { critical: 0, high: 0, medium: 0, low: 0 });
        setEvtxCount(data.evtx_files_count || 0);
        setGeneratedAt(data.generated_at || null);
        setHasData(true);
        if (onTotalChange) onTotalChange(data.total_detections || mapped.length);
      } else {
        setDetections([]);
        setStats({ critical: 0, high: 0, medium: 0, low: 0 });
        setHasData(false);
        if (onTotalChange) onTotalChange(0);
      }
    } catch {
      setDetections([]);
      setHasData(false);
    } finally {
      setLoading(false);
    }
  }, [onTotalChange]);

  useEffect(() => {
    setSearch('');
    setLevelFilter('all');
    setTacticFilter('all');
    setSelId(null);
    loadData(caseId);
  }, [caseId, reloadKey, loadData]);

  const runHayabusa = async () => {
    if (!caseId || running) return;
    setRunning(true);
    setError('');
    try {
      const { data } = await collectionAPI.runHayabusa(caseId);
      const mapped = (data.timeline || []).map((d, i) => ({ ...d, _id: i }));
      setDetections(mapped);
      setStats(data.stats || { critical: 0, high: 0, medium: 0, low: 0 });
      setEvtxCount(data.evtx_files_processed || 0);
      setGeneratedAt(new Date().toISOString());
      setHasData(true);
      if (onTotalChange) onTotalChange(data.total_detections || mapped.length);
    } catch (err) {
      setError(err.response?.data?.error || 'Erreur lors de l\'exécution de Hayabusa');
    } finally {
      setRunning(false);
    }
  };

  const filtered = detections.filter(d => {
    if (levelFilter !== 'all' && d.level !== levelFilter) return false;
    const tactic = getField(d, 'tactic');
    if (tacticFilter !== 'all' && tactic !== tacticFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (getField(d, 'rule_title', 'ruleTitle')).toLowerCase().includes(q)
        || (d.details || '').toLowerCase().includes(q)
        || (getField(d, 'mitre_attack', 'mitre')).toLowerCase().includes(q)
        || (d.channel || '').toLowerCase().includes(q)
        || String(getField(d, 'event_id', 'eventId')).includes(q)
        || (d.computer || '').toLowerCase().includes(q)
        || tactic.toLowerCase().includes(q);
    }
    return true;
  });

  const tactics = [...new Set(detections.map(d => getField(d, 'tactic')).filter(Boolean))].sort();

  const toggleHL = (id) => setHighlights(p => {
    const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n;
  });

  const exportCSV = () => {
    const rows = filtered.map(d =>
      [
        fmtTs(d.timestamp),
        d.level,
        getField(d, 'event_id', 'eventId'),
        d.channel || '',
        getField(d, 'rule_title', 'ruleTitle'),
        getField(d, 'mitre_attack', 'mitre'),
        getField(d, 'tactic'),
        (d.details || '').replace(/[",\n]/g, ' '),
        d.computer || '',
      ].map(v => `"${v}"`).join(',')
    );
    const blob = new Blob(
      ['Timestamp,Level,EventID,Channel,Règle Sigma,MITRE,Tactique,Détails,Computer\n' + rows.join('\n')],
      { type: 'text/csv' }
    );
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `hayabusa_${caseId}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const selDetection = selId != null ? detections.find(d => d._id === selId) : null;

  return (
    <div className="space-y-4">

      
      <div className="flex items-center gap-3">
        <button
          onClick={runHayabusa}
          disabled={running || loading}
          className="fl-btn fl-btn-danger fl-btn-sm flex items-center gap-2"
          style={{ opacity: (running || loading) ? 0.6 : 1 }}>
          {running
            ? <><Loader2 size={13} className="animate-spin" /> Analyse EVTX…</>
            : <><Play size={13} /> {hasData ? 'Relancer Hayabusa' : 'Lancer Hayabusa'}</>}
        </button>
        {hasData && !running && (
          <button onClick={() => loadData(caseId)} disabled={loading}
            className="fl-btn fl-btn-ghost fl-btn-sm p-2"
            title="Recharger les résultats">
            <RefreshCw size={13} />
          </button>
        )}
        {generatedAt && (
          <span className="text-xs font-mono ml-auto" style={{ color: '#334155' }}>
            Dernière analyse : {fmtDateTime(generatedAt)}
          </span>
        )}
      </div>

      
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg text-sm"
          style={{ background: '#da363310', border: '1px solid #da363330', color: '#da3633' }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      
      {loading && (
        <div className="flex items-center justify-center py-12 gap-3" style={{ color: '#7d8590' }}>
          <Loader2 size={20} className="animate-spin" style={{ color: '#da3633' }} />
          Chargement des résultats Hayabusa…
        </div>
      )}

      
      {!hasData && !loading && !running && (
        <div className="text-center py-12 rounded-xl border" style={{ background: '#1c2333', borderColor: '#30363d' }}>
          <Shield size={44} style={{ color: '#da3633', margin: '0 auto 14px', opacity: 0.25 }} />
          <p className="text-sm font-semibold mb-1" style={{ color: '#e6edf3' }}>Aucune analyse Hayabusa</p>
          <p className="text-xs mb-4" style={{ color: '#7d8590' }}>
            Importez une collecte contenant des fichiers EVTX,<br />
            puis cliquez sur <strong style={{ color: '#da3633' }}>Lancer Hayabusa</strong> pour détecter les menaces avec les règles Sigma.
          </p>
          <span className="text-xs font-mono px-3 py-1.5 rounded" style={{ background: '#0d1117', border: '1px solid #30363d', color: '#7d8590' }}>
            Import Collecte → Zimmerman (EVTX) → Hayabusa (Sigma)
          </span>
        </div>
      )}

      
      {hasData && !loading && (
        <>
          
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
            {LEVELS.map(lvl => (
              <button key={lvl}
                onClick={() => setLevelFilter(levelFilter === lvl ? 'all' : lvl)}
                className="rounded-xl p-3 border text-left transition-all"
                style={{
                  background: levelFilter === lvl ? `${LEVEL_COLORS[lvl]}10` : '#1c2333',
                  borderColor: levelFilter === lvl ? `${LEVEL_COLORS[lvl]}50` : '#30363d',
                  borderLeft: `3px solid ${LEVEL_COLORS[lvl]}`,
                  cursor: 'pointer',
                }}>
                <div className="text-2xl font-bold font-mono" style={{ color: LEVEL_COLORS[lvl] }}>
                  {stats[lvl] || 0}
                </div>
                <div className="text-xs uppercase tracking-wider mt-0.5" style={{ color: '#7d8590' }}>{lvl}</div>
              </button>
            ))}
            <div className="rounded-xl p-3 border" style={{ background: '#1c2333', borderColor: '#30363d', borderLeft: '3px solid #4d82c0' }}>
              <div className="text-2xl font-bold font-mono" style={{ color: '#4d82c0' }}>{evtxCount}</div>
              <div className="text-xs uppercase tracking-wider mt-0.5" style={{ color: '#7d8590' }}>EVTX parsés</div>
            </div>
          </div>

          
          <div className="flex gap-2 items-center flex-wrap">
            
            <div className="relative" style={{ minWidth: 220, flex: 1 }}>
              <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Règle Sigma, MITRE, Event ID, channel, computer…"
                className="w-full pl-8 pr-3 py-2 rounded-lg text-xs font-mono outline-none"
                style={{ background: '#0d1117', border: '1px solid #30363d', color: '#e6edf3' }} />
            </div>

            
            <div className="flex gap-1">
              {['all', ...LEVELS].map(l => (
                <button key={l} onClick={() => setLevelFilter(l)}
                  className="px-2.5 py-1.5 rounded text-xs font-mono font-bold uppercase"
                  style={{
                    background: levelFilter === l ? `${LEVEL_COLORS[l] || '#4d82c0'}18` : 'transparent',
                    color: LEVEL_COLORS[l] || '#4d82c0',
                    border: `1px solid ${levelFilter === l ? (LEVEL_COLORS[l] || '#4d82c0') + '40' : '#30363d'}`,
                  }}>
                  {l === 'all' ? 'Tous' : l}
                </button>
              ))}
            </div>

            
            {tactics.length > 0 && (
              <select value={tacticFilter} onChange={e => setTacticFilter(e.target.value)}
                className="px-3 py-1.5 rounded text-xs font-mono outline-none"
                style={{ background: '#0d1117', border: '1px solid #30363d', color: tacticFilter !== 'all' ? (TACTIC_COLORS[tacticFilter] || '#e6edf3') : '#7d8590' }}>
                <option value="all">Toutes les tactiques</option>
                {tactics.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            )}

            
            <button onClick={exportCSV} className="flex items-center gap-1 px-3 py-1.5 rounded text-xs font-mono"
              style={{ border: '1px solid #30363d', color: '#7d8590' }}>
              <Download size={11} /> CSV
            </button>

            
            <span className="text-xs font-mono" style={{ color: '#334155' }}>
              {filtered.length} / {detections.length}
            </span>
            {highlights.size > 0 && (
              <button onClick={() => setShowHL(s => !s)}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs font-mono"
                style={{ background: '#da363312', color: '#da3633', border: '1px solid #da363330' }}>
                <Star size={11} /> {highlights.size} surlignée(s)
                {showHL ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
              </button>
            )}
          </div>

          
          {showHL && highlights.size > 0 && (
            <div className="rounded-xl p-3 border" style={{ background: '#da363308', borderColor: '#da363325' }}>
              <div className="text-xs font-mono font-bold mb-2" style={{ color: '#da3633' }}>
                ★ {highlights.size} DÉTECTION(S) SURLIGNÉE(S)
              </div>
              <div className="space-y-1">
                {detections.filter(d => highlights.has(d._id)).map(d => (
                  <div key={d._id} className="flex items-center gap-3 py-0.5">
                    <span className="font-mono text-xs w-36 flex-shrink-0" style={{ color: '#7d8590' }}>
                      {fmtTs(d.timestamp)}
                    </span>
                    <LevelBadge level={d.level} />
                    <span className="text-xs font-semibold flex-1" style={{ color: '#e6edf3' }}>
                      {getField(d, 'rule_title', 'ruleTitle')}
                    </span>
                    <button onClick={() => toggleHL(d._id)} style={{ color: '#7d8590' }}>
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          
          <div className="rounded-xl border overflow-hidden" style={{ background: '#1c2333', borderColor: '#30363d' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="w-full text-sm" style={{ borderCollapse: 'collapse', minWidth: 900 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #30363d', background: '#0d1117' }}>
                    <th className="w-8 px-2 py-2.5 text-center text-xs" style={{ color: '#334155' }}>★</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>Timestamp</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>Level</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>EID</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>Channel</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>Règle Sigma</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>MITRE / Tactique</th>
                    <th className="text-left px-3 py-2.5 text-xs font-mono uppercase tracking-wider" style={{ color: '#da3633' }}>Détails</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((d) => {
                    const rTitle   = getField(d, 'rule_title', 'ruleTitle');
                    const eid      = getField(d, 'event_id', 'eventId');
                    const mitre    = getField(d, 'mitre_attack', 'mitre');
                    const tactic   = getField(d, 'tactic');
                    const isCrit   = d.level === 'critical';
                    const isHL     = highlights.has(d._id);
                    const isSel    = selId === d._id;
                    const lvlCol   = LEVEL_COLORS[d.level] || '#7d8590';

                    return (
                      <>
                        <tr key={d._id}
                          onClick={() => setSelId(isSel ? null : d._id)}
                          style={{
                            borderBottom: `1px solid #30363d25`,
                            borderLeft: `3px solid ${isCrit || isHL ? lvlCol : lvlCol + '35'}`,
                            background: isHL ? `${lvlCol}14` : isSel ? `${lvlCol}0c` : (LEVEL_ROW_BG[d.level] || 'transparent'),
                            cursor: 'pointer',
                          }}>
                          <td className="px-2 py-2 text-center"
                            onClick={e => { e.stopPropagation(); toggleHL(d._id); }}>
                            <span style={{ fontSize: 12, color: isHL ? '#da3633' : '#334155' }}>
                              {isHL ? '★' : '☆'}
                            </span>
                          </td>
                          <td className="px-3 py-2 font-mono text-xs whitespace-nowrap" style={{ color: '#7d8590' }}>
                            {fmtTs(d.timestamp)}
                          </td>
                          <td className="px-3 py-2">
                            <LevelBadge level={d.level} />
                          </td>
                          <td className="px-3 py-2 font-mono text-xs font-bold" style={{ color: '#c89d1d' }}>
                            {eid}
                          </td>
                          <td className="px-3 py-2 text-xs" style={{ color: '#7d8590', whiteSpace: 'nowrap' }}>
                            {d.channel}
                          </td>
                          <td className="px-3 py-2 text-xs font-semibold" style={{ color: isCrit ? '#da3633' : '#e6edf3', maxWidth: 200 }}>
                            {isCrit && <AlertTriangle size={11} className="inline mr-1 mb-0.5" style={{ color: '#da3633' }} />}
                            {rTitle}
                          </td>
                          <td className="px-3 py-2">
                            <MitreBadge mitre={mitre} tactic={tactic} />
                          </td>
                          <td className="px-3 py-2 text-xs" style={{ color: '#7d8590', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {d.details}
                          </td>
                        </tr>

                        
                        {isSel && (
                          <tr key={`${d._id}-detail`}>
                            <td colSpan={8} style={{ padding: 0 }}>
                              <div className="px-4 py-3 border-b"
                                style={{ background: `${lvlCol}06`, borderTop: `1px solid ${lvlCol}25`, borderBottom: `1px solid #30363d` }}>
                                
                                <div className="flex gap-2 mb-3 flex-wrap">
                                  <LevelBadge level={d.level} />
                                  {mitre && (
                                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                                      style={{ background: '#4d82c014', color: '#4d82c0', border: '1px solid #4d82c030' }}>
                                      ATT&amp;CK {mitre}
                                    </span>
                                  )}
                                  {tactic && (
                                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                                      style={{ background: `${TACTIC_COLORS[tactic] || '#7d8590'}14`, color: TACTIC_COLORS[tactic] || '#7d8590', border: `1px solid ${TACTIC_COLORS[tactic] || '#7d8590'}28` }}>
                                      {tactic}
                                    </span>
                                  )}
                                </div>
                                
                                <div className="text-sm font-semibold mb-1" style={{ color: '#e6edf3' }}>{getField(d, 'rule_title', 'ruleTitle')}</div>
                                {d.details && (
                                  <div className="text-xs mb-3" style={{ color: '#7d8590', lineHeight: 1.6 }}>{d.details}</div>
                                )}
                                
                                <div className="grid gap-3 text-xs" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
                                  {[
                                    ['Computer',  getField(d, 'computer')],
                                    ['Event ID',  eid],
                                    ['Channel',   d.channel],
                                    ['Source',    d.source || d.channel],
                                  ].map(([label, val]) => (
                                    <div key={label}>
                                      <span className="font-mono font-bold" style={{ color: '#da3633' }}>{label}: </span>
                                      <span style={{ color: '#7d8590' }}>{val || '—'}</span>
                                    </div>
                                  ))}
                                </div>
                                
                                {d.raw && (
                                  <details className="mt-3">
                                    <summary className="text-xs font-mono cursor-pointer select-none" style={{ color: '#334155' }}>
                                      Données brutes EVTX
                                    </summary>
                                    <pre className="mt-2 p-3 rounded-lg text-xs overflow-auto font-mono"
                                      style={{ background: '#0d1117', border: '1px solid #30363d', color: '#7d8590', maxHeight: 200 }}>
                                      {JSON.stringify(d.raw, null, 2)}
                                    </pre>
                                  </details>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}

                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-center py-10 text-sm" style={{ color: '#7d8590' }}>
                        Aucune détection pour ces filtres
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          
          <div className="flex justify-between items-center text-xs font-mono" style={{ color: '#334155' }}>
            <span>Hayabusa · Règles Sigma · JPCERT/CC · <span style={{ color: '#da3633' }}>yamato-security/hayabusa</span></span>
            <span>{evtxCount} EVTX · {detections.length} détections totales</span>
          </div>
        </>
      )}
    </div>
  );
}
