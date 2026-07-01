import { useState, useEffect, useRef, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, CheckCircle2, Ban, XCircle, Clock } from 'lucide-react';
import { collectionAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, "Inter", sans-serif)';

const STATUS = {
  queued:  { icon: Clock,        color: 'var(--fl-muted)',  k: 'collection.pm_queued' },
  parsing: { icon: Loader2,      color: 'var(--fl-accent)', k: 'collection.pm_parsing' },
  done:    { icon: CheckCircle2, color: 'var(--fl-ok)',     k: 'collection.pm_done' },
  skipped: { icon: Ban,          color: 'var(--fl-muted)',  k: 'collection.pm_skipped' },
  error:   { icon: XCircle,      color: 'var(--fl-danger)', k: 'collection.pm_error' },
};

// artifact key → ATT&CK tactic (mirrors backend ARTIFACT_MITRE) for the live coverage strip.
const PARSER_TACTIC = {
  registry: 'persistence', lnk: 'persistence', jumplist: 'persistence', bits: 'persistence', schtasks: 'persistence', wmi: 'persistence',
  amcache: 'execution', appcompat: 'execution', prefetch: 'execution', srum: 'execution', pwsh: 'execution', userassist: 'execution',
  usn: 'defense-evasion', indx: 'defense-evasion', recycle: 'defense-evasion',
  shellbags: 'discovery', evtx: 'discovery', netprofile: 'discovery',
  sqle: 'collection', webcache: 'collection', sum: 'lateral-movement',
  usb: 'exfiltration', dns: 'command-and-control', 'vuln-drivers': 'privilege-escalation',
};
const TACTICS = [
  ['execution', 'Execution'], ['persistence', 'Persistence'], ['privilege-escalation', 'Privilege escalation'],
  ['defense-evasion', 'Defense evasion'], ['discovery', 'Discovery'], ['lateral-movement', 'Lateral movement'],
  ['collection', 'Collection'], ['command-and-control', 'C2'], ['exfiltration', 'Exfiltration'],
];

function Radial({ pct }) {
  const r = 26, c = 2 * Math.PI * r;
  const off = c * (1 - Math.max(0, Math.min(100, pct)) / 100);
  return (
    <div style={{ position: 'relative', width: 64, height: 64, flexShrink: 0 }}>
      <svg width="64" height="64" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="32" cy="32" r={r} fill="none" stroke="var(--fl-border2)" strokeWidth="5" />
        <circle cx="32" cy="32" r={r} fill="none" stroke="var(--fl-accent)" strokeWidth="5" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off} style={{ transition: 'stroke-dashoffset 0.4s ease' }} />
      </svg>
      <span style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: MONO, fontSize: 13, fontWeight: 700, color: 'var(--fl-text)', fontFeatureSettings: '"tnum"' }}>
        {Math.round(pct)}%
      </span>
    </div>
  );
}

function ParserCard({ parser, state, justDone, t }) {
  const status = state?.status || 'queued';
  const meta = STATUS[status] || STATUS.queued;
  const Icon = meta.icon;
  const records = state?.records;
  return (
    <div className={justDone ? 'fl-tile-pulse' : ''} style={{
      border: `1px solid ${status === 'parsing' ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
      borderRadius: 8, background: status === 'parsing' ? 'color-mix(in srgb, var(--fl-accent) 5%, transparent)' : 'var(--fl-panel)',
      padding: 10, display: 'flex', flexDirection: 'column', gap: 7, minWidth: 0, transition: 'all 0.3s',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <span style={{ width: 8, height: 8, borderRadius: 2, background: parser.color, flexShrink: 0 }} />
        <span style={{ fontSize: 11.5, color: 'var(--fl-text)', fontFamily: UI, whiteSpace: 'nowrap',
          overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>{parser.name}</span>
        <Icon size={12} style={{ color: meta.color, flexShrink: 0,
          animation: status === 'parsing' ? 'fl-spin 0.9s linear infinite' : 'none' }} />
      </div>
      <div style={{ height: 4, borderRadius: 2, background: 'var(--fl-card)', overflow: 'hidden' }}>
        {status === 'parsing'
          ? <div className="fl-indeterminate" style={{ height: '100%', width: '40%', background: meta.color, borderRadius: 2 }} />
          : <div style={{ height: '100%', borderRadius: 2, background: meta.color,
              width: (status === 'done' || status === 'skipped' || status === 'error') ? '100%' : '0%' }} />}
      </div>
      <div style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>
        {status === 'done' && records != null
          ? t('collection.pm_records', { n: Number(records).toLocaleString() })
          : t(meta.k)}
      </div>
    </div>
  );
}

function fmtEta(sec) {
  if (!Number.isFinite(sec) || sec <= 0) return '';
  if (sec < 60) return `~${Math.ceil(sec)}s restantes`;
  return `~${Math.ceil(sec / 60)} min restantes`;
}

export default function ParsingMonitor({ fileName, parsers, states, globalPct, live, caseId }) {
  const { t } = useTranslation();

  // Live event-density sparkline — polls the timeline histogram while parsing.
  const [hist, setHist] = useState([]);
  useEffect(() => {
    if (!caseId || !live) return;
    let alive = true;
    let inFlight = false;
    // Guard against overlapping polls: this aggregates the whole case timeline
    // (can be millions of rows), so never issue a new request until the prior
    // one resolves — otherwise slow scans stack up and exhaust the DB pool.
    const poll = () => {
      if (inFlight) return;
      inFlight = true;
      collectionAPI.timelineHistogram(caseId, 48)
        .then(r => { if (alive) setHist(r.data?.buckets || []); })
        .catch(() => {})
        .finally(() => { inFlight = false; });
    };
    poll();
    const iv = setInterval(poll, 10000);
    return () => { alive = false; clearInterval(iv); };
  }, [caseId, live]);
  const histMax = Math.max(1, ...hist);

  const totalRecords = useMemo(
    () => Object.values(states || {}).reduce((s, v) => s + (Number(v?.records) || 0), 0), [states]);

  // Live throughput + ETA from successive polls (15 s window).
  const samplesRef = useRef([]);
  const [rate, setRate] = useState(0);
  const [eta, setEta] = useState(0);
  useEffect(() => {
    const now = Date.now();
    samplesRef.current.push({ t: now, records: totalRecords, pct: globalPct || 0 });
    samplesRef.current = samplesRef.current.filter(s => now - s.t < 15000);
    const s = samplesRef.current;
    if (s.length >= 2) {
      const a = s[0], b = s[s.length - 1];
      const dt = (b.t - a.t) / 1000;
      if (dt > 0.5) {
        setRate(Math.max(0, (b.records - a.records) / dt));
        const pctRate = (b.pct - a.pct) / dt;
        setEta(pctRate > 0.01 ? (100 - b.pct) / pctRate : 0);
      }
    }
  }, [totalRecords, globalPct]);

  // Track which tiles just transitioned to "done" → brief pulse.
  const prevStatus = useRef({});
  const justDone = {};
  for (const p of parsers || []) {
    const cur = states?.[p.key]?.status;
    if (cur === 'done' && prevStatus.current[p.key] && prevStatus.current[p.key] !== 'done') justDone[p.key] = true;
    if (cur) prevStatus.current[p.key] = cur;
  }

  // Tactics covered = a tactic whose parser reached done.
  const covered = useMemo(() => {
    const set = new Set();
    for (const p of parsers || []) {
      if (states?.[p.key]?.status === 'done' && PARSER_TACTIC[p.key]) set.add(PARSER_TACTIC[p.key]);
    }
    return set;
  }, [parsers, states]);

  if (!parsers || parsers.length === 0) return null;

  return (
    <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-panel)', padding: 14, marginBottom: 12 }}>
      {/* Cockpit header: radial + title + throughput/ETA */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 14 }}>
        <Radial pct={globalPct || 0} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fl-text)', fontFamily: UI }}>
              {t('collection.parsing_monitor')}
            </span>
            {live && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9.5, fontFamily: MONO, color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              <span className="fl-pulse" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fl-accent)' }} /> live
            </span>}
          </div>
          {fileName && <div style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{fileName}</div>}
          <div style={{ display: 'flex', gap: 14, marginTop: 6, fontFamily: MONO, fontSize: 11, fontFeatureSettings: '"tnum"' }}>
            <span style={{ color: 'var(--fl-dim)' }}><span style={{ color: 'var(--fl-text)', fontWeight: 700 }}>{totalRecords.toLocaleString('fr-FR')}</span> enreg.</span>
            {rate > 0 && <span style={{ color: 'var(--fl-accent)' }}>{Math.round(rate).toLocaleString('fr-FR')} l/s</span>}
            {eta > 0 && <span style={{ color: 'var(--fl-muted)' }}>{fmtEta(eta)}</span>}
          </div>
        </div>
      </div>

      {/* Live ATT&CK coverage strip */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 14 }}>
        {TACTICS.map(([key, label]) => {
          const on = covered.has(key);
          return (
            <span key={key} style={{ fontSize: 9.5, fontFamily: MONO, padding: '2px 8px', borderRadius: 4, transition: 'all 0.3s',
              background: on ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
              color: on ? 'var(--fl-accent)' : 'var(--fl-subtle)',
              border: `1px solid ${on ? 'color-mix(in srgb, var(--fl-accent) 28%, transparent)' : 'var(--fl-border2)'}` }}>
              {label}
            </span>
          );
        })}
      </div>

      {/* Live event-density sparkline (builds as the timeline fills) */}
      {hist.some(v => v > 0) && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 40 }}>
            {hist.map((v, i) => {
              // Log scale: one huge bucket would otherwise flatten all the others to a dash.
              const h = v > 0 ? Math.max(8, (Math.log(v + 1) / Math.log(histMax + 1)) * 100) : 0;
              return (
                <div key={i} title={`${v.toLocaleString('fr-FR')} events`} style={{ flex: 1, alignSelf: 'flex-end',
                  height: `${h}%`, minHeight: v > 0 ? 3 : 0, borderRadius: '2px 2px 0 0',
                  background: v > 0 ? 'color-mix(in srgb, var(--fl-accent) 55%, transparent)' : 'transparent',
                  transition: 'height 0.5s ease' }} />
              );
            })}
          </div>
          <div style={{ fontSize: 9, fontFamily: MONO, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 5 }}>
            Event density (timeline)
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 10 }}>
        {parsers.map(p => <ParserCard key={p.key} parser={p} state={states?.[p.key]} justDone={justDone[p.key]} t={t} />)}
      </div>
    </div>
  );
}
