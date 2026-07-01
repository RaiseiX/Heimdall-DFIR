import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Shield, AlertTriangle, Crosshair,
  Plus, Search, Terminal,
  Activity, Radio, CheckSquare, ChevronRight,
  FolderPlus, Pencil, CheckCircle2, Upload, Trash2, ShieldAlert, Settings, KeyRound, Dot,
  Clock, HardDrive,
} from 'lucide-react';
import { casesAPI, playbooksAPI, settingsAPI } from '../utils/api';
import { useSocket, useSocketEvent } from '../hooks/useSocket';

const C = {
  bg:      'var(--fl-bg)',
  panel:   'var(--fl-panel)',
  card:    'var(--fl-card)',
  border:  'var(--fl-border)',
  border2: 'var(--fl-border2)',
  accent:  'var(--fl-accent)',
  danger:  'var(--fl-danger)',
  warn:    'var(--fl-warn)',
  ok:      'var(--fl-ok)',
  gold:    'var(--fl-gold)',
  purple:  'var(--fl-purple)',
  text:    'var(--fl-text)',
  sub:     'var(--fl-dim)',
  muted:   'var(--fl-muted)',
};

const MONO    = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI      = 'var(--f-ui, "Inter", sans-serif)';
const DISPLAY = 'var(--f-display, "Space Grotesk", "Inter", sans-serif)';

function fmtBytes(b) {
  if (!b) return { val: '—', unit: '' };
  if (b >= 1e12) return { val: (b / 1e12).toFixed(1), unit: 'To' };
  if (b >= 1e9)  return { val: (b / 1e9).toFixed(1),  unit: 'Go' };
  return { val: (b / 1e6).toFixed(0), unit: 'Mo' };
}

function threatLevel(s, t) {
  if (!s) return { label: t('dashboard.threat_unknown'), color: C.muted, icon: Shield, severity: 0 };
  if (s.cases.critical_cases > 0 && s.iocs.malicious_iocs > 4)
    return { label: t('dashboard.threat_critical'), color: C.danger, icon: AlertTriangle, severity: 5 };
  if (s.cases.critical_cases > 0 || s.iocs.malicious_iocs > 3)
    return { label: t('dashboard.threat_high'), color: C.warn, icon: AlertTriangle, severity: 4 };
  if (s.cases.active_cases > 0)
    return { label: t('dashboard.threat_moderate'), color: C.gold, icon: Activity, severity: 2 };
  return { label: t('dashboard.threat_low'), color: C.ok, icon: Shield, severity: 1 };
}

function fmtRelTime(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const ACTION_ICON = {
  create_case:     { icon: FolderPlus,   color: C.accent },
  update_case:     { icon: Pencil,       color: C.purple },
  close_case:      { icon: CheckCircle2, color: C.ok },
  upload_evidence: { icon: Upload,       color: C.accent },
  delete_evidence: { icon: Trash2,       color: C.danger },
  create_ioc:      { icon: ShieldAlert,  color: C.warn },
  parse_collection:{ icon: Settings,     color: C.purple },
  login:           { icon: KeyRound,     color: C.purple },
  default:         { icon: Dot,          color: C.muted },
};

function Spark({ data, color, height = 28 }) {
  if (!data || data.length < 2) return <div style={{ height }} />;
  const max = Math.max(...data, 1);
  const W = 100, H = height;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - Math.max((v / max) * H, 0);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const last = data[data.length - 1];
  const lx = W, ly = H - Math.max((last / max) * H, 0);
  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5}
        strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={lx} cy={ly} r={2} fill={color} />
    </svg>
  );
}

function Pip() {
  return <span style={{ width: 4, height: 4, borderRadius: '50%', background: C.muted, display: 'inline-block', flexShrink: 0 }} />;
}

function ThreatLevelCard({ s, tl, t }) {
  const SEGMENTS = 5;
  const stats = [
    { n: s.cases.critical_cases || 0, l: t('dashboard.gauge_critical') },
    { n: s.cases.active_cases   || 0, l: t('dashboard.gauge_active') },
    { n: s.iocs.total_iocs      || 0, l: t('dashboard.gauge_monitored') },
  ];
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 10, padding: 16,
      border: `1px solid ${C.border}`, borderRadius: 8,
      background: C.panel,
      position: 'relative',
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontSize: 10, fontFamily: MONO, letterSpacing: '0.14em', textTransform: 'uppercase', color: C.muted }}>
          {t('dashboard.threat_global')}
        </span>
        <span style={{ fontSize: 18, fontWeight: 500, fontFamily: DISPLAY, color: tl.color }}>
          {tl.label}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 3, height: 4 }}>
        {Array.from({ length: SEGMENTS }, (_, i) => (
          <div key={i} style={{ flex: 1, borderRadius: 1, background: i < tl.severity ? tl.color : C.card }} />
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, paddingTop: 8, borderTop: `1px solid ${C.border2}` }}>
        {stats.map(st => (
          <div key={st.l}>
            <div style={{ fontSize: 18, fontWeight: 500, fontFamily: MONO, color: C.text, lineHeight: 1 }}>{st.n}</div>
            <div style={{ fontSize: 10.5, color: C.muted, marginTop: 2 }}>{st.l}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function KpiCard({ label, value, valueColor, delta, sub, spark, sparkColor }) {
  const up = delta != null && delta > 0;
  const down = delta != null && delta < 0;
  return (
    <div style={{
      padding: 16, border: `1px solid ${C.border}`, borderRadius: 8,
      background: C.panel, display: 'flex', flexDirection: 'column', gap: 8,
      position: 'relative', overflow: 'hidden', transition: 'border-color 0.14s ease',
    }}
    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--fl-border3)'; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.12em', color: C.muted }}>{label}</span>
        <span style={{ flex: 1 }} />
        {(up || down) && (
          <span style={{ fontSize: 10.5, fontFamily: MONO, display: 'flex', alignItems: 'center', gap: 2, color: up ? C.danger : C.ok }}>
            {up ? '↑' : '↓'}{Math.abs(delta)}
          </span>
        )}
      </div>
      <div style={{ fontSize: 32, fontWeight: 500, fontFamily: DISPLAY, color: valueColor || C.text, letterSpacing: '-0.02em', lineHeight: 1, fontFeatureSettings: '"tnum"' }}>
        {value}
      </div>
      {spark
        ? <Spark data={spark} color={sparkColor} height={28} />
        : sub && <div style={{ fontSize: 11, fontFamily: UI, color: C.muted }}>{sub}</div>
      }
    </div>
  );
}

function DashCard({ title, badge, children, flush, grow }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, display: 'flex', flexDirection: 'column', overflow: 'hidden', ...(grow ? { flex: 1, minHeight: 0 } : {}) }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: `1px solid ${C.border2}` }}>
        <span style={{ fontSize: 12, fontWeight: 500, color: C.text, fontFamily: UI }}>{title}</span>
        <span style={{ flex: 1 }} />
        {badge}
      </div>
      <div style={{ padding: flush ? 0 : 16, ...(grow ? { flex: 1, display: 'flex', flexDirection: 'column' } : {}) }}>
        {children}
      </div>
    </div>
  );
}

function ActivityFeed({ items, t }) {
  if (!items || items.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '28px 16px', gap: 6, minHeight: 160 }}>
        <Radio size={20} style={{ color: C.border }} />
        <span style={{ fontSize: 11, fontFamily: MONO, color: C.muted }}>{t('dashboard.no_activity')}</span>
      </div>
    );
  }
  const shown = items.slice(0, 6);
  return (
    <div style={{ padding: '8px 0' }}>
      {shown.map((item, i) => {
        const def = ACTION_ICON[item.action] || ACTION_ICON.default;
        // Strict aggregate: show actor + action + entity type only — never case titles or values.
        const entity = (item.entity_type || '').replace(/_/g, ' ');
        return (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: '24px 1fr auto', gap: 12, padding: '10px 16px', position: 'relative' }}>
            {i < shown.length - 1 && (
              <div style={{ position: 'absolute', left: 27, top: 32, bottom: -10, width: 1, background: C.border2 }} />
            )}
            <div style={{
              width: 24, height: 24, borderRadius: '50%', zIndex: 1,
              background: C.card, border: `1px solid ${C.border}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <def.icon size={12} style={{ color: def.color }} />
            </div>
            <div style={{ fontSize: 12.5, color: C.sub, lineHeight: 1.4 }}>
              <span style={{ color: C.text, fontWeight: 500 }}>{item.full_name || t('dashboard.system_actor')}</span>
              {' '}
              <span>{(item.action || '').replace(/_/g, ' ')}</span>
              {entity && <span style={{ color: C.muted }}> · {entity}</span>}
            </div>
            <div style={{ fontFamily: MONO, fontSize: 10.5, color: C.muted }}>{fmtRelTime(item.created_at)}</div>
          </div>
        );
      })}
    </div>
  );
}

function QuickActions({ navigate, t }) {
  const actions = [
    { icon: Plus,      label: t('dashboard.qa_new_case'), sub: t('dashboard.qa_new_case_sub'), kbd: 'N', to: '/cases' },
    { icon: Terminal,  label: t('dashboard.qa_agent'),    sub: t('dashboard.qa_agent_sub'),    kbd: 'U', to: '/collection-agent' },
    { icon: Crosshair, label: t('dashboard.qa_ioc'),      sub: t('dashboard.qa_ioc_sub'),      kbd: 'I', to: '/iocs' },
    { icon: Search,    label: t('dashboard.qa_hunt'),     sub: t('dashboard.qa_hunt_sub'),     kbd: 'Q', to: '/threat-hunt' },
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
      {actions.map(a => (
        <button key={a.label} onClick={() => navigate(a.to)} style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: 12,
          border: `1px solid ${C.border}`, borderRadius: 6,
          background: C.panel, cursor: 'pointer', textAlign: 'left',
          transition: 'background 0.14s ease, border-color 0.14s ease',
        }}
        onMouseEnter={e => { e.currentTarget.style.background = C.card; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-text) 14%, transparent)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = C.panel; e.currentTarget.style.borderColor = C.border; }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: C.card, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.sub, flexShrink: 0 }}>
            <a.icon size={14} />
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 12.5, color: C.text, fontFamily: UI, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.label}</div>
            <div style={{ fontSize: 10.5, color: C.muted, fontFamily: UI, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.sub}</div>
          </div>
          <span style={{ fontSize: 10, fontFamily: MONO, color: C.muted, padding: '1px 5px', borderRadius: 3, border: `1px solid ${C.border}`, flexShrink: 0 }}>{a.kbd}</span>
        </button>
      ))}
    </div>
  );
}

function MyTasks({ items, navigate, t }) {
  if (!items || items.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px 16px', gap: 6, minHeight: 120 }}>
        <CheckSquare size={20} style={{ color: C.border }} />
        <span style={{ fontSize: 11, fontFamily: MONO, color: C.muted, textAlign: 'center' }}>{t('dashboard.my_tasks_empty')}</span>
      </div>
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {items.map((task, i) => (
        <button key={`${task.instance_id}-${task.step_id}`} onClick={() => navigate(`/cases/${task.case_id}`)} style={{
          display: 'flex', alignItems: 'center', gap: 10, width: '100%', textAlign: 'left',
          padding: '9px 4px', background: 'transparent', border: 'none', cursor: 'pointer',
          borderBottom: i < items.length - 1 ? `1px solid ${C.border2}` : 'none',
        }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: task.note_required ? C.warn : C.accent, flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, color: C.text, fontFamily: UI, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{task.step_title}</div>
            <div style={{ fontSize: 10, color: C.muted, fontFamily: MONO, marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{task.playbook_title}</div>
          </div>
          <ChevronRight size={12} style={{ color: C.muted, flexShrink: 0 }} />
        </button>
      ))}
    </div>
  );
}

// ── Shared triage-widget primitives (Observatory: hairlines, square state dots) ─
function SqDot({ color, halo }) {
  // Square dot = state (charter §13), distinct from round info dots.
  // halo = solid ring (no blur) reserved for critical — not a glow.
  return (
    <span style={{
      width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0,
      boxShadow: halo ? `0 0 0 3px color-mix(in srgb, ${color} 22%, transparent)` : 'none',
    }} />
  );
}

function MetricRow({ dot, label, count, frac, barColor }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', alignItems: 'center', gap: 10, padding: '5px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        {dot}
        <span style={{ fontSize: 11.5, color: C.sub, fontFamily: UI, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
      </div>
      <div style={{ height: 4, borderRadius: 2, background: C.card, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.round(Math.max(0, Math.min(1, frac)) * 100)}%`, background: barColor, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 12, fontFamily: MONO, color: C.text, fontFeatureSettings: '"tnum"', minWidth: 24, textAlign: 'right' }}>{count}</span>
    </div>
  );
}

function EmptyMini({ icon: Icon, label }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '22px 16px', gap: 6 }}>
      <Icon size={18} style={{ color: C.border }} />
      <span style={{ fontSize: 11, fontFamily: MONO, color: C.muted, textAlign: 'center' }}>{label}</span>
    </div>
  );
}

// ── SLA / deadlines (aggregate buckets only — no case titles) ────────────────
function SlaWidget({ deadlines, sla, t }) {
  const counts = { urgent: 0, warning: 0, upcoming: 0 };
  for (const d of deadlines || []) {
    const h = parseFloat(d.hours_remaining);
    if (!Number.isFinite(h) || h < 0) continue;
    if (h <= sla.urgentH)        counts.urgent++;
    else if (h <= sla.warningH)  counts.warning++;
    else if (h <= sla.upcomingH) counts.upcoming++;
  }
  const total = counts.urgent + counts.warning + counts.upcoming;
  if (total === 0) return <EmptyMini icon={Clock} label={t('dashboard.sla_empty')} />;
  const maxC = Math.max(counts.urgent, counts.warning, counts.upcoming, 1);
  const rows = [
    { key: 'urgent',   label: `${t('dashboard.sla_urgent')} · ≤${sla.urgentH}h`,   color: C.danger },
    { key: 'warning',  label: `${t('dashboard.sla_warning')} · ≤${sla.warningH}h`,  color: C.warn },
    { key: 'upcoming', label: `${t('dashboard.sla_upcoming')} · ≤${sla.upcomingH}h`, color: C.purple },
  ];
  return (
    <div>
      {rows.map(r => (
        <MetricRow key={r.key}
          dot={<SqDot color={r.color} halo={r.key === 'urgent' && counts.urgent > 0} />}
          label={r.label} count={counts[r.key]} frac={counts[r.key] / maxC} barColor={r.color} />
      ))}
    </div>
  );
}

// ── Scan & parse health (aggregate evidence states + parse coverage) ─────────
function ScanHealthWidget({ data, t }) {
  const rows = [
    { key: 'clean',       label: t('dashboard.scan_clean'),       color: C.ok },
    { key: 'quarantined', label: t('dashboard.scan_quarantined'), color: C.danger },
    { key: 'pending',     label: t('dashboard.scan_pending'),     color: C.muted },
    { key: 'error',       label: t('dashboard.scan_error'),       color: C.warn },
  ];
  const total = data?.total || 0;
  if (total === 0) return <EmptyMini icon={HardDrive} label={t('dashboard.scan_empty')} />;
  const maxC = Math.max(...rows.map(r => data?.[r.key] || 0), 1);
  const cov = Math.round(((data.parsed || 0) / total) * 100);
  return (
    <div>
      {rows.filter(r => (data[r.key] || 0) > 0 || r.key === 'clean').map(r => (
        <MetricRow key={r.key}
          dot={<SqDot color={r.color} halo={r.key === 'quarantined' && (data[r.key] || 0) > 0} />}
          label={r.label} count={data[r.key] || 0} frac={(data[r.key] || 0) / maxC} barColor={r.color} />
      ))}
      <div style={{ marginTop: 8, paddingTop: 8, borderTop: `1px solid ${C.border2}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 10.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.08em', color: C.muted }}>{t('dashboard.scan_coverage')}</span>
        <span style={{ fontSize: 12, fontFamily: MONO, color: C.text }}>{data.parsed || 0}/{total} · {cov}%</span>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { t, i18n } = useTranslation();
  const [stats, setStats]         = useState(null);
  const [loading, setLoading]     = useState(true);
  const [liveFlash, setLiveFlash] = useState(false);
  const [deadlines, setDeadlines] = useState([]);
  const [myTasks, setMyTasks]     = useState([]);
  const [slaConfig, setSlaConfig] = useState({ urgentH: 24, warningH: 72, upcomingH: 168 });
  const { socket } = useSocket();

  const loadStats = useCallback(() => {
    casesAPI.deadlines().then(r => setDeadlines(r.data.deadlines || [])).catch(() => {});
    settingsAPI.getDashboard().then(r => { if (r.data?.sla) setSlaConfig(r.data.sla); }).catch(() => {});
    playbooksAPI.myOpenSteps().then(r => setMyTasks(r.data || [])).catch(() => {});
    casesAPI.stats().then(r => {
      setStats(r?.data || {
        cases:    { active_cases: 0, pending_cases: 0, closed_cases: 0, critical_cases: 0, total_cases: 0 },
        evidence: { total_evidence: 0, highlighted_evidence: 0, total_size: 0 },
        iocs:     { total_iocs: 0, malicious_iocs: 0, ioc_types: 0 },
        daily_activity: [],
      });
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);

  useSocketEvent(socket, 'dashboard:update', () => {
    setLiveFlash(true);
    loadStats();
    setTimeout(() => setLiveFlash(false), 1500);
  });

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', background: C.bg }}>
      <span style={{ fontSize: 12, fontFamily: MONO, color: C.muted }}>{t('dashboard.loading')}</span>
    </div>
  );

  const s = stats;
  const tl = threatLevel(s, t);
  const currentUser = (() => { try { return JSON.parse(localStorage.getItem('heimdall_user') || '{}'); } catch { return {}; } })();
  const firstName = (currentUser.full_name || '').split(' ')[0] || currentUser.username || '';
  const dateStr = new Date().toLocaleDateString(i18n.language, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  const hour = new Date().getHours();
  const greeting = hour < 12 ? t('dashboard.greeting_morning') : hour < 18 ? t('dashboard.greeting_afternoon') : t('dashboard.greeting_evening');

  const closedPct = s.cases.total_cases > 0
    ? Math.round((s.cases.closed_cases / s.cases.total_cases) * 100)
    : 0;

  const urgentDeadlines = deadlines.filter(d => parseFloat(d.hours_remaining) < 48).length;
  const summaryBase = s.cases.critical_cases > 0
    ? t('dashboard.summary_critical', { count: s.cases.critical_cases })
    : urgentDeadlines > 0
      ? t('dashboard.summary_urgent', { count: urgentDeadlines })
      : s.cases.active_cases > 0
        ? t('dashboard.summary_active', { count: s.cases.active_cases, pct: closedPct })
        : t('dashboard.summary_calm');
  const lastActivity = (s.recent_activity || [])[0];
  const lastActivityDesc = (() => {
    if (!lastActivity) return null;
    // Strict aggregate: actor + action + time only — no case titles or values.
    const who = lastActivity.full_name || t('dashboard.system_actor');
    const action = (lastActivity.action || '').replace(/_/g, ' ');
    return `${who} — ${action} · ${fmtRelTime(lastActivity.created_at)}`;
  })();

  const act     = s.daily_activity || [];
  const iocData = act.map(d => parseInt(d.iocs)   || 0);
  const evtData = act.map(d => parseInt(d.events) || 0);
  const delta = (arr) => arr.length < 2 ? 0 : arr[arr.length - 1] - arr[arr.length - 2];
  const iocDelta = delta(iocData);
  const evtDelta = delta(evtData);
  const forensic = fmtBytes(s.evidence.total_size);

  return (
    <div style={{ padding: '18px 22px', background: C.bg, minHeight: '100%', display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Hero */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20, alignItems: 'start' }}>
        <div style={{ minWidth: 0 }}>
          <h1 style={{ fontSize: 26, fontWeight: 600, margin: '0 0 6px', color: C.text, fontFamily: DISPLAY, letterSpacing: '-0.02em' }}>
            {greeting}{firstName ? `, ${firstName}` : ''}.
          </h1>
          <div style={{ fontSize: 13, color: C.sub, fontFamily: UI }}>
            {summaryBase}{lastActivityDesc ? ` ${lastActivityDesc}` : ''}
          </div>
          <div style={{ marginTop: 12, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap', fontFamily: MONO, fontSize: 11, color: C.muted }}>
            <span style={{ textTransform: 'capitalize' }}>{dateStr}</span>
            {currentUser.role && (
              <>
                <Pip />
                <span style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>{currentUser.role}</span>
              </>
            )}
            <Pip />
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: liveFlash ? C.accent : C.ok }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: liveFlash ? C.accent : C.ok, display: 'inline-block' }} />
              {liveFlash ? t('dashboard.updating') : t('dashboard.operational')}
            </span>
          </div>
        </div>
        <ThreatLevelCard s={s} tl={tl} t={t} />
      </div>

      {/* KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        <KpiCard
          label={t('dashboard.kpi_active')}
          value={s.cases.active_cases}
          sub={t('dashboard.kpi_pending', { n: s.cases.pending_cases })}
        />
        <KpiCard
          label={t('dashboard.kpi_critical')}
          value={s.cases.critical_cases}
          valueColor={s.cases.critical_cases > 0 ? C.danger : undefined}
          sub={s.cases.critical_cases > 0 ? t('dashboard.kpi_attention') : t('dashboard.kpi_none_active')}
        />
        <KpiCard
          label={`${t('dashboard.kpi_malicious_iocs')} · 24h`}
          value={s.iocs.malicious_iocs}
          delta={iocDelta}
          spark={iocData}
          sparkColor={C.danger}
        />
        <KpiCard
          label={t('dashboard.kpi_forensic')}
          value={<>{forensic.val}<span style={{ fontSize: 18, color: C.muted, marginLeft: 4 }}>{forensic.unit}</span></>}
          sub={t('dashboard.kpi_evidence', { n: s.evidence.total_evidence, h: s.evidence.highlighted_evidence })}
        />
      </div>

      {/* Bento body — two interlocking columns that stretch to equal height */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.5fr) minmax(0, 1fr)', gap: 20, alignItems: 'stretch', flex: 1, minHeight: 0 }}>

        {/* Left column — SLA on top, recent activity filling the rest */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, minWidth: 0 }}>
          <DashCard title={t('dashboard.sla_title')}>
            <SlaWidget deadlines={deadlines} sla={slaConfig} t={t} />
          </DashCard>
          <DashCard
            title={t('dashboard.recent_activity')}
            flush grow
            badge={(
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9.5, fontWeight: 600,
                fontFamily: MONO, padding: '3px 8px', borderRadius: 4, textTransform: 'uppercase', letterSpacing: '0.04em',
                background: 'color-mix(in srgb, var(--fl-ok) 13%, transparent)', color: C.ok, border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)',
              }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: C.ok, display: 'inline-block' }} />
                Live
              </span>
            )}
          >
            <ActivityFeed items={s.recent_activity || []} t={t} />
          </DashCard>
        </div>

        {/* Right column — scan health, quick actions, my tasks filling the rest */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, minWidth: 0 }}>
          <DashCard title={t('dashboard.scan_title')}>
            <ScanHealthWidget data={s.scan_health || {}} t={t} />
          </DashCard>

          <DashCard title={t('dashboard.quick_actions')}>
            <QuickActions navigate={navigate} t={t} />
          </DashCard>

          <DashCard
            title={t('dashboard.my_tasks')}
            grow
            badge={myTasks.length > 0 && (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9.5, fontWeight: 600,
                fontFamily: MONO, padding: '3px 8px', borderRadius: 4, textTransform: 'uppercase', letterSpacing: '0.04em',
                background: 'color-mix(in srgb, var(--fl-accent) 13%, transparent)', color: C.accent, border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)',
              }}>
                {myTasks.length}
              </span>
            )}
          >
            <MyTasks items={myTasks} navigate={navigate} t={t} />
          </DashCard>
        </div>

      </div>

    </div>
  );
}
