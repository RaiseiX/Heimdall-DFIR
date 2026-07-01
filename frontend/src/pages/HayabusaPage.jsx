import { useState, useEffect, useCallback, useRef } from 'react';
import { collectionAPI, casesAPI, timelineRulesAPI } from '../utils/api';
import { useTimelineStore }  from '../components/supertimeline/store/useTimelineStore';
import { sortRules }         from '../utils/colorRulesEngine';
import CommandBar  from '../components/supertimeline/CommandBar/CommandBar';
import EventGrid   from '../components/supertimeline/EventGrid/EventGrid';
import StatusBar   from '../components/supertimeline/StatusBar/StatusBar';
import DetailPanel from '../components/supertimeline/DetailPanel/DetailPanel';
import TipsTab     from '../components/supertimeline/ExplorerPanel/TipsTab';
import {
  Shield, Play, RefreshCw, Loader2, X, AlertTriangle, FolderOpen,
} from 'lucide-react';

const LEVEL_COLOR = {
  critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-warn)', low: 'var(--fl-ok)', informational: 'var(--fl-accent)',
};

// ── Diagnostic banner ─────────────────────────────────────────────────────────
function DiagnosticBanner({ diagnostic }) {
  return (
    <div style={{ margin: '6px 12px 0', padding: '10px 14px', borderRadius: 6, flexShrink: 0,
      background: (diagnostic.rules_count > 0) ? '#0f0d05' : '#0f0505',
      border: `1px solid ${diagnostic.rules_count > 0 ? '#3a3010' : '#3a1010'}`,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
      <div style={{ fontWeight: 700, color: 'var(--fl-warn)', marginBottom: 6 }}>
        ⚠ 0 detections - engine diagnostics
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 12px', color: '#4a6080' }}>
        <span style={{ color: '#2a3a50' }}>Engine</span>
        <span style={{ color: diagnostic.engine_used === 'hayabusa_binary' ? 'var(--fl-ok)' : 'var(--fl-warn)' }}>
          {diagnostic.engine_used === 'hayabusa_binary' ? '✓ Hayabusa binary' : '⚠ Sigma fallback'}
        </span>
        <span style={{ color: '#2a3a50' }}>Sigma rules</span>
        <span style={{ color: diagnostic.rules_count > 0 ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
          {diagnostic.rules_count > 0
            ? `✓ ${diagnostic.rules_count} rules`
            : "✗ No rules — rebuild the Docker image"}
        </span>
        <span style={{ color: '#2a3a50' }}>EVTX</span>
        <span>{diagnostic.evtx_files} analyzed</span>
        {diagnostic.stderr_snippet && (
          <>
            <span style={{ color: '#2a3a50' }}>Stderr</span>
            <span style={{ color: 'var(--fl-danger)', wordBreak: 'break-all' }}>{diagnostic.stderr_snippet}</span>
          </>
        )}
      </div>
      {!diagnostic.rules_present && (
        <div style={{ marginTop: 8, color: 'var(--fl-danger)', fontSize: 10 }}>
          Required action: <code>docker compose build --no-cache odin</code>
        </div>
      )}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function HayabusaPage() {
  // Hayabusa-specific state (case selector, run button, metadata)
  const [cases, setCases]             = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState('');
  const [hayMeta, setHayMeta]         = useState(null);
  const [hasRun, setHasRun]           = useState(false);

  const [activeLevel, setActiveLevel] = useState('');

  // SuperTimeline store — powers the grid
  const {
    setCaseId, setFilter, setColorRules, loadTimeline, applyFilters,
    total, loading,
  } = useTimelineStore();

  // ── Load cases ──────────────────────────────────────────────────────────────
  useEffect(() => {
    casesAPI.list({}).then(({ data }) => {
      const list = data.cases || [];
      setCases(list);
      if (list.length > 0) setSelectedCase(list[0].id);
    }).catch(() => {});
  }, []);

  // ── When selected case changes ──────────────────────────────────────────────
  useEffect(() => {
    if (!selectedCase) return;

    // Init timeline store locked to hayabusa
    setActiveLevel('');
    setCaseId(selectedCase);
    setFilter('artifactTypes', ['hayabusa']);

    // Load color rules, then timeline data
    timelineRulesAPI.list(selectedCase)
      .then(r => {
        const rules = r.data?.rules || r.data || [];
        setColorRules(sortRules(Array.isArray(rules) ? rules : []));
      })
      .catch(() => setColorRules([]))
      .finally(() => loadTimeline());

    // Fetch Hayabusa metadata (stats, diagnostic) from the dedicated endpoint
    collectionAPI.getHayabusa(selectedCase, { limit: 1 }).then(({ data }) => {
      setHayMeta({
        stats:           data.stats           || {},
        evtxCount:       data.evtx_files_count || 0,
        totalDetections: data.total_detections || 0,
        diagnostic:      data.diagnostic      || null,
      });
      setHasRun((data.total_detections || 0) > 0);
    }).catch(() => { setHasRun(false); setHayMeta(null); });

    // Restore unfiltered store when navigating away
    return () => {
      useTimelineStore.getState().setFilter('artifactTypes', []);
      useTimelineStore.getState().setFilter('search', '');
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCase]);

  // ── Level quick-filter ────────────────────────────────────────────────────────
  useEffect(() => {
    // No-op on empty level — case-change effect already calls loadTimeline()
    if (!activeLevel) {
      setFilter('search', '');
      return;
    }
    // Match both full name ([critical]) and Hayabusa abbreviation ([crit], [med], [info]).
    // Using the abbreviated prefix covers both: "[crit" matches "[crit]" AND "[critical]".
    const LEVEL_PREFIX = { critical: '[crit', medium: '[med', informational: '[info', high: '[high', low: '[low' };
    setFilter('search', LEVEL_PREFIX[activeLevel] || `[${activeLevel}`);
    applyFilters();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLevel]);

  // ── Run Hayabusa analysis ───────────────────────────────────────────────────
  const runHayabusa = useCallback(async () => {
    if (!selectedCase || running) return;
    setRunning(true);
    setError('');
    try {
      const { data } = await collectionAPI.runHayabusa(selectedCase);
      setHayMeta({
        stats:           data.stats            || {},
        evtxCount:       data.evtx_files_processed || 0,
        totalDetections: data.total_detections  || 0,
        diagnostic:      data.diagnostic        || null,
      });
      setHasRun(true);
      // Reload the grid
      setCaseId(selectedCase);
      setFilter('artifactTypes', ['hayabusa']);
      loadTimeline();
    } catch (err) {
      setError(err.response?.data?.error || 'Error');
    }
    setRunning(false);
  }, [selectedCase, running, setCaseId, setFilter, loadTimeline]);

  const { stats = {}, evtxCount = 0, diagnostic = null } = hayMeta || {};
  const showContent = hasRun || loading || running;

  // ─────────────────────────────────────────────────────────────────────────────
  return (
    <div style={{
      height: '100%', background: '#0a0c11',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>

      {/* ── Header strip ── */}
      <div style={{ height: 32, background: '#0a0c11', borderBottom: '1px solid #1a1f2c',
        display: 'flex', alignItems: 'center', padding: '0 14px', gap: 10,
        flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        <Shield size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
        <span style={{ fontSize: 10, color: 'var(--fl-accent)', fontWeight: 700, letterSpacing: '0.08em' }}>
          HEIMDALL
        </span>
        <span style={{ width: 1, height: 14, background: '#1a1f2c' }} />
        <span style={{ fontSize: 10, color: '#556070', fontWeight: 600,
          letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Hayabusa
        </span>
        <span style={{ fontSize: 9, color: '#2a3a50' }}>JPCERT/CC · Sigma</span>
        {hasRun && total > 0 && (
          <>
            <span style={{ width: 1, height: 14, background: '#1a1f2c' }} />
            <span style={{ padding: '1px 7px', borderRadius: 3, fontSize: 9, fontWeight: 700,
              background: '#1a0a0a', color: 'var(--fl-danger)', border: '1px solid #3a1a1a',
              letterSpacing: '0.06em' }}>
              {total.toLocaleString('fr-FR')} detections
            </span>
            <span style={{ padding: '1px 7px', borderRadius: 3, fontSize: 9,
              background: '#131722', color: 'var(--fl-muted)', border: '1px solid #1a1f2c' }}>
              {evtxCount} EVTX
            </span>
          </>
        )}
        <TipsButton />
      </div>

      {/* ── Control bar — case selector + action buttons ── */}
      <div style={{ background: '#0a0c11', borderBottom: '1px solid #1a1f2c',
        padding: '6px 14px', display: 'flex', gap: 6, alignItems: 'center',
        flexShrink: 0, flexWrap: 'wrap' }}>

        <FolderOpen size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
        <select
          value={selectedCase}
          onChange={e => { setSelectedCase(e.target.value); setHasRun(false); setHayMeta(null); }}
          style={{ fontSize: 11, padding: '3px 8px', flex: '0 1 300px', minWidth: 160,
            background: '#0e1118', border: '1px solid var(--fl-subtle)', color: 'var(--fl-dim)',
            borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', outline: 'none' }}>
          <option value="">— Select a case —</option>
          {cases.map(c => (
            <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
          ))}
        </select>

        <span style={{ width: 1, height: 18, background: '#1a1f2c', flexShrink: 0 }} />

        <button onClick={runHayabusa} disabled={running || !selectedCase}
          style={{ padding: '4px 12px', borderRadius: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            fontWeight: 600, display: 'flex', alignItems: 'center', gap: 5,
            cursor: !selectedCase || running ? 'default' : 'pointer',
            background: running || !selectedCase ? '#1a0a0a' : '#2a0a0a',
            border: '1px solid #3a1a1a',
            color: running || !selectedCase ? '#5a2a2a' : 'var(--fl-danger)',
            opacity: !selectedCase ? 0.5 : 1 }}>
          {running
            ? <><Loader2 size={11} className="animate-spin" /> Analyzing…</>
            : <><Play size={11} /> Run</>}
        </button>

        {hasRun && !running && (
          <button onClick={runHayabusa}
            style={{ padding: '4px 10px', borderRadius: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer',
              background: 'transparent', border: '1px solid #1a1f2c', color: 'var(--fl-muted)' }}>
            <RefreshCw size={11} /> Rerun
          </button>
        )}

        {/* Level filter badges — always visible when data is loaded, clickable to filter */}
        {hasRun && (
          <>
            <span style={{ width: 1, height: 18, background: '#1a1f2c', flexShrink: 0 }} />
            {['critical', 'high', 'medium', 'low', 'informational'].map(lvl => {
              const col   = LEVEL_COLOR[lvl];
              const cnt   = stats[lvl] || 0;
              const isAct = activeLevel === lvl;
              return (
                <button key={lvl} onClick={() => setActiveLevel(isAct ? '' : lvl)}
                  title={cnt ? `Filter: ${cnt} ${lvl}` : `No ${lvl} events`}
                  style={{
                    padding: '1px 6px', borderRadius: 3, fontSize: 9,
                    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, textTransform: 'uppercase',
                    cursor: 'pointer', border: 'none', outline: 'none',
                    background: isAct ? `color-mix(in srgb, ${col} 16%, transparent)` : (cnt ? `color-mix(in srgb, ${col} 7%, transparent)` : 'transparent'),
                    color: cnt ? col : `color-mix(in srgb, ${col} 25%, transparent)`,
                    boxShadow: isAct ? `0 0 0 1px ${col}` : `0 0 0 1px ${cnt ? col + '30' : col + '18'}`,
                    opacity: cnt ? 1 : 0.45,
                    transition: 'all 0.1s',
                  }}>
                  {lvl} <span style={{ fontWeight: 400, opacity: 0.65 }}>{cnt || 0}</span>
                </button>
              );
            })}
            {activeLevel && (
              <button onClick={() => setActiveLevel('')}
                title="Effacer le filtre de niveau"
                style={{ padding: '1px 5px', borderRadius: 3, fontSize: 9,
                  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', border: 'none',
                  background: 'transparent', color: 'var(--fl-muted)',
                  boxShadow: '0 0 0 1px #1a1f2c' }}>
                ✕ filtre
              </button>
            )}
          </>
        )}
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div style={{ margin: '0 12px', padding: '5px 10px', borderRadius: 5, fontSize: 11,
          background: '#1a0505', border: '1px solid #3a1010', color: 'var(--fl-danger)',
          display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <AlertTriangle size={11} /> {error}
          <button onClick={() => setError('')}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}>
            <X size={10} />
          </button>
        </div>
      )}

      {/* ── Diagnostic banners ── */}
      {hasRun && !loading && total === 0 && diagnostic && (
        <DiagnosticBanner diagnostic={diagnostic} />
      )}
      {hasRun && !loading && total > 0 && diagnostic?.engine_used === 'sigma_fallback' && (
        <div style={{ margin: '4px 12px 0', padding: '5px 12px', borderRadius: 5, flexShrink: 0,
          background: '#0f0d05', border: '1px solid #2a2510',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-warn)',
          display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={10} />
          Sigma fallback engine — partial coverage · {diagnostic.rules_count || 0} rules
        </div>
      )}

      {/* ── Empty state ── */}
      {!showContent && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', gap: 12 }}>
          <Shield size={42} style={{ color: '#1a0a0a' }} />
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, fontWeight: 600,
            color: '#4a6080', letterSpacing: '0.04em' }}>
            No Hayabusa analysis
          </div>
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: '#2a3a50',
            textAlign: 'center', maxWidth: 380, lineHeight: 1.7 }}>
            Select a case containing EVTX files,<br />
            then click <span style={{ color: 'var(--fl-accent)' }}>Run</span> to parse with Sigma rules.
          </div>
          <div style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '4px 10px', borderRadius: 4,
            background: '#0a0f18', border: '1px solid #1a1f2c', color: 'var(--fl-subtle)',
            letterSpacing: '0.05em' }}>
            Collection import → Zimmerman (EVTX) → Hayabusa (Sigma)
          </div>
        </div>
      )}

      {/* ── SuperTimeline grid — CommandBar + EventGrid + DetailPanel + StatusBar ── */}
      {showContent && (
        <>
          <CommandBar />
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            <EventGrid />
            <DetailPanel />
          </div>
          <StatusBar />
        </>
      )}
    </div>
  );
}

function TipsButton() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} style={{ position: 'relative', marginLeft: 'auto' }}>
      <button
        onClick={() => setOpen(v => !v)}
        title="Tips — Search & Filter guide"
        style={{
          width: 22, height: 22, borderRadius: 4, border: `1px solid ${open ? 'color-mix(in srgb, var(--fl-accent) 38%, transparent)' : '#1a1f2c'}`,
          background: open ? '#131722' : 'transparent',
          color: open ? 'var(--fl-accent)' : 'var(--fl-muted)',
          cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700,
          display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1,
        }}
        onMouseEnter={e => { if (!open) { e.currentTarget.style.color = '#6aabdb'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 25%, transparent)'; } }}
        onMouseLeave={e => { if (!open) { e.currentTarget.style.color = 'var(--fl-muted)'; e.currentTarget.style.borderColor = '#1a1f2c'; } }}
      >?</button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 2000,
          width: 280, maxHeight: 'calc(100vh - 80px)',
          background: '#0a0c11', border: '1px solid #1a1f2c', borderRadius: 6,
          boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          <div style={{ padding: '8px 12px 6px', borderBottom: '1px solid #0e1118',
            fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
            letterSpacing: '0.08em', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>
            Search &amp; Filter Tips
          </div>
          <TipsTab />
        </div>
      )}
    </div>
  );
}
