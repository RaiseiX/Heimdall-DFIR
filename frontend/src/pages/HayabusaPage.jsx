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

import { markStyle } from '../components/ui/tableIdiom';
import { controlStyle, controlHover, separatorStyle } from '../components/ui/controlIdiom';

const INLINE_PICTO = { verticalAlign: '-1px' };

const FS_MARK_SM = 9;
const SEG_ROW = { display: 'flex', gap: 12, alignItems: 'baseline', flexWrap: 'wrap' };

const LEVEL_COLOR = {
  critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)', informational: 'var(--fl-dim)',
};

function DiagnosticBanner({ diagnostic }) {
  return (
    <div style={{ margin: '6px 12px 0', padding: '10px 14px', borderRadius: 6, flexShrink: 0,
      background: (diagnostic.rules_count > 0) ? 'color-mix(in srgb, var(--fl-warn) 8%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 8%, transparent)',
      border: `1px solid ${diagnostic.rules_count > 0 ? 'color-mix(in srgb, var(--fl-warn) 25%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 25%, transparent)'}`,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
      <div style={{ fontWeight: 700, color: 'var(--fl-warn)', marginBottom: 6 }}>
        <AlertTriangle size={11} style={INLINE_PICTO} /> 0 detections - engine diagnostics
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 12px', color: 'var(--fl-dim)' }}>
        <span style={{ color: 'var(--fl-subtle)' }}>Engine</span>
        <span style={{ color: diagnostic.engine_used === 'hayabusa_binary' ? 'var(--fl-ok)' : 'var(--fl-warn)' }}>
          {diagnostic.engine_used === 'hayabusa_binary' ? '✓ Hayabusa binary' : '⚠ Sigma fallback'}
        </span>
        <span style={{ color: 'var(--fl-subtle)' }}>Sigma rules</span>
        <span style={{ color: diagnostic.rules_count > 0 ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
          {diagnostic.rules_count > 0
            ? `✓ ${diagnostic.rules_count} rules`
            : "✗ No rules — rebuild the Docker image"}
        </span>
        <span style={{ color: 'var(--fl-subtle)' }}>EVTX</span>
        <span>{diagnostic.evtx_files} analyzed</span>
        {diagnostic.stderr_snippet && (
          <>
            <span style={{ color: 'var(--fl-subtle)' }}>Stderr</span>
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

export default function HayabusaPage() {
  const [cases, setCases]             = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState('');
  const [hayMeta, setHayMeta]         = useState(null);
  const [hasRun, setHasRun]           = useState(false);

  const [activeLevel, setActiveLevel] = useState('');

  const {
    setCaseId, setFilter, setColorRules, loadTimeline, applyFilters,
    total, loading,
  } = useTimelineStore();

  useEffect(() => {
    casesAPI.list({}).then(({ data }) => {
      const list = data.cases || [];
      setCases(list);
      if (list.length > 0) setSelectedCase(list[0].id);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedCase) return;

    setActiveLevel('');
    setCaseId(selectedCase);
    setFilter('artifactTypes', ['hayabusa']);

    timelineRulesAPI.list(selectedCase)
      .then(r => {
        const rules = r.data?.rules || r.data || [];
        setColorRules(sortRules(Array.isArray(rules) ? rules : []));
      })
      .catch(() => setColorRules([]))
      .finally(() => loadTimeline());

    collectionAPI.getHayabusa(selectedCase, { limit: 1 }).then(({ data }) => {
      setHayMeta({
        stats:           data.stats           || {},
        evtxCount:       data.evtx_files_count || 0,
        totalDetections: data.total_detections || 0,
        diagnostic:      data.diagnostic      || null,
      });
      setHasRun((data.total_detections || 0) > 0);
    }).catch(() => { setHasRun(false); setHayMeta(null); });

    return () => {
      useTimelineStore.getState().setFilter('artifactTypes', []);
      useTimelineStore.getState().setFilter('search', '');
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCase]);

  useEffect(() => {
    if (!activeLevel) {
      setFilter('search', '');
      return;
    }
    const LEVEL_PREFIX = { critical: '[crit', medium: '[med', informational: '[info', high: '[high', low: '[low' };
    setFilter('search', LEVEL_PREFIX[activeLevel] || `[${activeLevel}`);
    applyFilters();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLevel]);

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

  return (
    <div style={{
      height: '100%', background: 'var(--fl-bg)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>

      <div style={{ height: 32, background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)',
        display: 'flex', alignItems: 'center', padding: '0 14px', gap: 10,
        flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        <Shield size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
        <span style={{ fontSize: 10, color: 'var(--fl-accent)', fontWeight: 700, letterSpacing: '0.08em' }}>
          HEIMDALL
        </span>
        <span style={separatorStyle} />
        <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontWeight: 600,
          letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Hayabusa
        </span>
        <span style={{ fontSize: 9, color: 'var(--fl-subtle)' }}>JPCERT/CC · Sigma</span>
        {hasRun && total > 0 && (
          <>
            <span style={separatorStyle} />
            <span style={markStyle('var(--fl-text)', FS_MARK_SM)}>
              {total.toLocaleString('fr-FR')} detections
            </span>
            <span style={markStyle('var(--fl-muted)', FS_MARK_SM)}>
              {evtxCount} EVTX
            </span>
          </>
        )}
        <TipsButton />
      </div>

      <div style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)',
        padding: '6px 14px', display: 'flex', gap: 12, alignItems: 'center',
        flexShrink: 0, flexWrap: 'wrap' }}>

        <FolderOpen size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
        <select
          value={selectedCase}
          onChange={e => { setSelectedCase(e.target.value); setHasRun(false); setHayMeta(null); }}
          style={{ fontSize: 11, padding: '3px 8px', flex: '0 1 300px', minWidth: 160,
            background: 'var(--fl-panel)', border: '1px solid var(--fl-subtle)', color: 'var(--fl-dim)',
            borderRadius: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', outline: 'none' }}>
          <option value="">— Select a case —</option>
          {cases.map(c => (
            <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
          ))}
        </select>

        <span style={separatorStyle} />

        <button onClick={runHayabusa} disabled={running || !selectedCase}
          style={{ ...controlStyle(false),
            cursor: !selectedCase || running ? 'default' : 'pointer',
            color: running || !selectedCase ? 'var(--fl-muted)' : 'var(--fl-danger)',
            opacity: !selectedCase ? 0.5 : 1 }}>
          {running
            ? <><Loader2 size={11} className="animate-spin" /> Analyzing…</>
            : <><Play size={11} /> Run</>}
        </button>

        {hasRun && !running && (
          <button onClick={runHayabusa}
            style={controlStyle(false)} {...controlHover(false)}>
            <RefreshCw size={11} /> Rerun
          </button>
        )}

        {hasRun && (
          <>
            <span style={separatorStyle} />
            {['critical', 'high', 'medium', 'low', 'informational'].map(lvl => {
              const col   = LEVEL_COLOR[lvl];
              const cnt   = stats[lvl] || 0;
              const isAct = activeLevel === lvl;
              return (
                <button key={lvl} onClick={() => setActiveLevel(isAct ? '' : lvl)}
                  title={cnt ? `Filter: ${cnt} ${lvl}` : `No ${lvl} events`}
                  style={{ ...controlStyle(isAct), opacity: cnt ? 1 : 0.45 }}
                  {...controlHover(isAct)}>
                  {lvl} <span style={{ color: cnt ? col : 'var(--fl-muted)' }}>{cnt || 0}</span>
                </button>
              );
            })}
            {activeLevel && (
              <button onClick={() => setActiveLevel('')}
                title="Effacer le filtre de niveau"
                style={controlStyle(false)} {...controlHover(false)}>
                <X size={10} style={INLINE_PICTO} /> filtre
              </button>
            )}
          </>
        )}
      </div>

      {error && (
        <div style={{ margin: '0 12px', padding: '5px 10px', borderRadius: 5, fontSize: 11,
          background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', color: 'var(--fl-danger)',
          display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <AlertTriangle size={11} /> {error}
          <button onClick={() => setError('')}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}>
            <X size={10} />
          </button>
        </div>
      )}

      {hasRun && !loading && total === 0 && diagnostic && (
        <DiagnosticBanner diagnostic={diagnostic} />
      )}
      {hasRun && !loading && total > 0 && diagnostic?.engine_used === 'sigma_fallback' && (
        <div style={{ margin: '4px 12px 0', padding: '5px 12px', borderRadius: 5, flexShrink: 0,
          background: 'color-mix(in srgb, var(--fl-warn) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-warn) 20%, transparent)',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-warn)',
          display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={10} />
          Sigma fallback engine — partial coverage · {diagnostic.rules_count || 0} rules
        </div>
      )}

      {!showContent && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', gap: 12 }}>
          <Shield size={42} style={{ color: 'color-mix(in srgb, var(--fl-danger) 14%, transparent)' }} />
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, fontWeight: 600,
            color: 'var(--fl-dim)', letterSpacing: '0.04em' }}>
            No Hayabusa analysis
          </div>
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-subtle)',
            textAlign: 'center', maxWidth: 380, lineHeight: 1.7 }}>
            Select a case containing EVTX files,<br />
            then click <span style={{ color: 'var(--fl-accent)' }}>Run</span> to parse with Sigma rules.
          </div>
          <div style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '4px 10px', borderRadius: 4,
            background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', color: 'var(--fl-subtle)',
            letterSpacing: '0.05em' }}>
            Collection import → Zimmerman (EVTX) → Hayabusa (Sigma)
          </div>
        </div>
      )}

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
        style={controlStyle(open)} {...controlHover(open)}
      >?</button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 2000,
          width: 280, maxHeight: 'calc(100vh - 80px)',
          background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 6,
          boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          <div style={{ padding: '8px 12px 6px', borderBottom: '1px solid var(--fl-panel)',
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
