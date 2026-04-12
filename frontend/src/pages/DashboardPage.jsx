import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Shield, AlertTriangle, FileText, Crosshair,
  Plus, Search, FolderOpen, ChevronRight,
  Database, Activity, Clock, TrendingUp,
  Circle, Zap, CalendarDays, ShieldAlert, Link2, Radio,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer,
} from 'recharts';
import { casesAPI, iocsAPI } from '../utils/api';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import { PRIORITY_COLORS } from '../utils/colorScheme';

const C = {
  bg:      'var(--fl-bg)',
  panel:   'var(--fl-panel)',
  card:    'var(--fl-card)',
  border:  'var(--fl-border)',
  border2: 'var(--fl-panel)',
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

function fmtBytes(b) {
  if (!b) return '—';
  if (b >= 1e12) return `${(b / 1e12).toFixed(1)} To`;
  if (b >= 1e9)  return `${(b / 1e9).toFixed(1)} Go`;
  return `${(b / 1e6).toFixed(0)} Mo`;
}

function threatLevel(s, t) {
  if (!s) return { label: t('dashboard.threat_unknown'), color: C.muted, icon: Shield };
  if (s.cases.critical_cases > 0 && s.iocs.malicious_iocs > 4)
    return { label: t('dashboard.threat_critical'), color: C.danger, icon: AlertTriangle };
  if (s.cases.critical_cases > 0 || s.iocs.malicious_iocs > 3)
    return { label: t('dashboard.threat_high'), color: C.warn, icon: AlertTriangle };
  if (s.cases.active_cases > 0)
    return { label: t('dashboard.threat_moderate'), color: C.gold, icon: Activity };
  return { label: t('dashboard.threat_low'), color: C.ok, icon: Shield };
}

function StatCard({ icon: Icon, label, value, sub, color, deltaLabel, deltaPositive, onClick }) {
  return (
    <button onClick={onClick} style={{
      display: 'flex', alignItems: 'center', gap: 16, padding: '18px 20px',
      background: `linear-gradient(135deg, ${C.card}, ${C.bg})`,
      border: `1px solid ${color}30`,
      borderRadius: 10,
      cursor: onClick ? 'pointer' : 'default', textAlign: 'left',
      width: '100%', transition: 'border-color 0.2s',
    }}
    onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = `${color}60`; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = `${color}30`; }}>
      <div style={{ width: 42, height: 42, borderRadius: 10, background: `${color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Icon size={18} style={{ color }} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 32, fontWeight: 800, color, lineHeight: 1, fontFamily: 'monospace' }}>{value}</div>
        <div style={{ fontSize: 10, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub, marginTop: 4 }}>{label}</div>
        {deltaLabel && (
          <div style={{ fontSize: 10, fontFamily: 'monospace', color: deltaPositive === true ? C.ok : deltaPositive === false ? C.danger : C.muted, marginTop: 3 }}>
            {deltaLabel}
          </div>
        )}
        {sub && !deltaLabel && <div style={{ fontSize: 10, fontFamily: 'monospace', color: C.muted, marginTop: 3 }}>{sub}</div>}
      </div>
    </button>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 7, padding: '8px 12px', fontSize: 11, fontFamily: 'monospace' }}>
      <div style={{ color: C.sub, marginBottom: 5 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.stroke, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: p.stroke, flexShrink: 0 }} />
          {p.name} : <strong style={{ color: C.text }}>{p.value}</strong>
        </div>
      ))}
    </div>
  );
}

function CaseRow({ c, onClick, statusMap, prioMap }) {
  const st = statusMap[c.status] || { label: c.status, color: C.muted };
  const pr = prioMap[c.priority]  || { label: c.priority, color: C.muted };
  return (
    <button onClick={onClick} style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '9px 12px', width: '100%', textAlign: 'left',
      background: 'transparent', border: '1px solid transparent',
      borderRadius: 8, cursor: 'pointer', transition: 'all 0.12s',
    }}
    onMouseEnter={e => { e.currentTarget.style.background = `${C.accent}08`; e.currentTarget.style.borderColor = `${C.accent}25`; }}
    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'transparent'; }}>
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: pr.color, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 500, color: C.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</div>
        <div style={{ fontSize: 10, color: C.muted, fontFamily: 'monospace', marginTop: 1 }}>{c.case_number}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
        <span style={{
          fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4,
          background: `${st.color}14`, color: st.color, border: `1px solid ${st.color}30`,
        }}>{st.label}</span>
        <ChevronRight size={12} style={{ color: C.muted }} />
      </div>
    </button>
  );
}

const MEDALS = ['🥇', '🥈', '🥉'];

function LeaderboardWidget({ rows, currentUserId }) {
  const maxDone = Math.max(...rows.map(r => r.total_done), 1);

  if (rows.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '28px 0', gap: 6 }}>
        <Zap size={24} style={{ color: C.border }} />
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.muted }}>
          Aucun step de playbook complété pour l'instant
        </span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {rows.map((r, i) => {
        const pct     = Math.round((r.total_done / maxDone) * 100);
        const isMe    = r.id === currentUserId;
        const barCol  = i === 0 ? C.gold : i === 1 ? C.sub : i === 2 ? '#8b5e3c' : C.accent;

        return (
          <div key={r.id} style={{
            padding: '10px 14px',
            borderRadius: 8,
            background: isMe ? `${C.accent}0a` : C.panel,
            border: `1px solid ${isMe ? `${C.accent}30` : C.border2}`,
            display: 'flex', alignItems: 'center', gap: 12,
          }}>
            
            <div style={{ width: 28, textAlign: 'center', flexShrink: 0 }}>
              {i < 3
                ? <span style={{ fontSize: 16 }}>{MEDALS[i]}</span>
                : <span style={{ fontSize: 12, fontWeight: 700, color: C.muted, fontFamily: 'monospace' }}>#{i + 1}</span>
              }
            </div>

            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: isMe ? C.accent : C.text, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.full_name}{isMe && <span style={{ fontSize: 9, color: C.accent, marginLeft: 6, fontWeight: 400 }}>(vous)</span>}
                </span>
                <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.muted, flexShrink: 0, marginLeft: 8 }}>
                  {r.active_cases} cas actif{r.active_cases !== 1 ? 's' : ''}
                </span>
              </div>

              <div style={{ height: 5, background: C.border2, borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3,
                  width: `${pct}%`,
                  background: isMe ? C.accent : barCol,
                  transition: 'width 0.7s ease',
                  boxShadow: isMe ? `0 0 6px ${C.accent}60` : undefined,
                }} />
              </div>
            </div>

            
            <div style={{ flexShrink: 0, textAlign: 'right', minWidth: 60 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.text, fontFamily: 'monospace', lineHeight: 1 }}>
                {r.total_done}
                <span style={{ fontSize: 9, fontWeight: 400, color: C.muted, marginLeft: 2 }}>steps</span>
              </div>
              {r.steps_this_week > 0 && (
                <div style={{ fontSize: 10, fontFamily: 'monospace', color: C.ok, marginTop: 2 }}>
                  +{r.steps_this_week} cette sem.
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Spark({ data, color }) {
  if (!data || data.length < 2) return <div style={{ height: 32 }} />;
  const max = Math.max(...data, 1);
  const W = 84, H = 32;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - Math.max((v / max) * H, 0);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const fill = `0,${H} ` + pts + ` ${W},${H}`;
  return (
    <svg width={W} height={H} style={{ display: 'block', overflow: 'visible' }}>
      <polygon points={fill} fill={`${color}18`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5}
        strokeLinejoin="round" strokeLinecap="round" />
      
      {(() => {
        const last = data[data.length - 1];
        const x = W, y = H - Math.max((last / max) * H, 0);
        return <circle cx={x} cy={y} r={2.5} fill={color} />;
      })()}
    </svg>
  );
}

function ThreatKpiCards({ s, deadlines }) {
  const urgentCount = deadlines.filter(d => parseFloat(d.hours_remaining) < 48).length;
  const activity    = s.daily_activity || [];
  const iocData     = activity.map(d => parseInt(d.iocs)   || 0);
  const evtData     = activity.map(d => parseInt(d.events) || 0);

  const delta = (arr) => {
    if (arr.length < 2) return 0;
    return arr[arr.length - 1] - arr[arr.length - 2];
  };
  const iocDelta = delta(iocData);
  const evtDelta = delta(evtData);

  const cards = [
    {
      label: 'IOCs malicieux',
      value: s.iocs.malicious_iocs || 0,
      spark: iocData,
      color: C.danger,
      delta: iocDelta,
      sub: `${s.iocs.total_iocs || 0} total`,
    },
    {
      label: 'Cas critiques',
      value: s.cases.critical_cases || 0,
      spark: null,
      color: C.warn,
      delta: null,
      sub: s.cases.critical_cases > 0 ? 'Attention requise' : 'Aucun actif',
    },
    {
      label: 'Cas actifs',
      value: s.cases.active_cases || 0,
      spark: evtData,
      color: C.accent,
      delta: evtDelta,
      sub: `${s.cases.total_cases || 0} cas au total`,
    },
    {
      label: 'Urgences 48h',
      value: urgentCount,
      spark: null,
      color: urgentCount > 0 ? C.danger : C.ok,
      delta: null,
      sub: urgentCount === 0 ? 'Aucune échéance proche' : 'deadline imminente',
    },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
      {cards.map(card => {
        const up   = card.delta > 0;
        const down = card.delta < 0;
        return (
          <div key={card.label} style={{
            padding: '11px 13px 9px',
            background: C.panel,
            borderRadius: 8,
            border: `1px solid ${C.border2}`,
            display: 'flex', flexDirection: 'column', gap: 6,
          }}>
            
            <div style={{ fontSize: 9, fontFamily: 'monospace', color: C.muted,
              textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {card.label}
            </div>

            
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 26, fontWeight: 700, color: card.color,
                fontFamily: 'monospace', lineHeight: 1 }}>
                {card.value}
              </span>
              {card.delta !== null && card.delta !== 0 && (
                <span style={{ fontSize: 11, fontFamily: 'monospace',
                  color: up ? C.danger : C.ok, fontWeight: 600 }}>
                  {up ? '↑' : '↓'}{Math.abs(card.delta)}
                </span>
              )}
              {card.delta === null && urgentCount === 0 && card.label === 'Urgences 48h' && (
                <span style={{ fontSize: 13, color: C.ok }}>✓</span>
              )}
              {card.delta === null && urgentCount > 0 && card.label === 'Urgences 48h' && (
                <span style={{ fontSize: 13, color: C.danger }}>⚠</span>
              )}
            </div>

            
            {card.spark
              ? <Spark data={card.spark} color={card.color} />
              : <div style={{ height: 32, display: 'flex', alignItems: 'center' }}>
                  <div style={{ flex: 1, height: 1, background: `${card.color}30`,
                    borderRadius: 1 }} />
                </div>
            }

            
            <div style={{ fontSize: 9, fontFamily: 'monospace', color: C.muted }}>
              {card.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ThreatRadar({ s, deadlines, tl }) {
  const cx = 120, cy = 90, r = 55;
  const N = 5;
  const a0 = -Math.PI / 2;

  const urgentCount = deadlines.filter(d => parseFloat(d.hours_remaining) < 72).length;
  const totalCases  = Math.max(s.cases.total_cases  || 0, 1);
  const totalIocs   = Math.max(s.iocs.total_iocs    || 0, 1);

  const dims = [
    { key: 'ioc_mal',   label: 'IOCs malicieux', value: Math.min((s.iocs.malicious_iocs  || 0) / 5,          1) },
    { key: 'critiques', label: 'Critiques',       value: Math.min((s.cases.critical_cases || 0) / 4,          1) },
    { key: 'taux_ioc',  label: 'Taux IOC',        value:          (s.iocs.malicious_iocs  || 0) / totalIocs       },
    { key: 'urgences',  label: 'Urgences',         value: Math.min(urgentCount / 3,                            1) },
    { key: 'actifs',    label: 'Actifs',           value: Math.min((s.cases.active_cases  || 0) / totalCases, 1) },
  ];

  const score = Math.round(dims.reduce((acc, d) => acc + d.value, 0) / N * 100);

  const pt = (i, val) => {
    const angle = a0 + i * (2 * Math.PI / N);
    return [cx + r * val * Math.cos(angle), cy + r * val * Math.sin(angle)];
  };

  const outerPts = dims.map((_, i) => pt(i, 1));
  const valPts   = dims.map((d, i) => pt(i, Math.max(d.value, 0.05)));
  const valPath  = valPts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ') + 'Z';
  const gradId   = `rg${tl.color.replace('#', '')}`;
  const lR = r + 22;

  return (
    <svg width="100%" viewBox="0 0 240 180" style={{ display: 'block', marginTop: -4 }}>
      <defs>
        <radialGradient id={gradId} cx="50%" cy="50%" r="50%">
          <stop offset="0%"   stopColor={tl.color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={tl.color} stopOpacity="0.05" />
        </radialGradient>
        <filter id="rglow" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="3.5" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      
      {[0.25, 0.5, 0.75, 1].map(ring => {
        const pts = dims.map((_, i) => pt(i, ring).map(v => v.toFixed(2)).join(',')).join(' ');
        return (
          <polygon key={ring} points={pts} fill="none"
            stroke={ring === 1 ? 'var(--fl-border)' : '#1e2530'}
            strokeWidth={ring === 1 ? 1 : 0.5}
            strokeDasharray={ring < 1 ? '3,4' : undefined}
          />
        );
      })}

      
      {outerPts.map(([x, y], i) => (
        <line key={i} x1={cx} y1={cy} x2={x.toFixed(2)} y2={y.toFixed(2)}
          stroke="#1e2530" strokeWidth={0.5} />
      ))}

      
      <path d={valPath}
        fill={`url(#${gradId})`} stroke={tl.color}
        strokeWidth={1.5} strokeLinejoin="round"
        filter="url(#rglow)" opacity={0.45}
      />

      
      <path d={valPath}
        fill={`url(#${gradId})`} stroke={tl.color}
        strokeWidth={1.5} strokeLinejoin="round"
      />

      
      {valPts.map(([x, y], i) => (
        <circle key={i} cx={x.toFixed(2)} cy={y.toFixed(2)} r={2.5} fill={tl.color} />
      ))}

      
      <text x={cx} y={cy - 8} textAnchor="middle" fontSize={22} fontWeight={700}
        fontFamily="monospace" fill={tl.color}>
        {score}
      </text>
      <text x={cx} y={cy + 9} textAnchor="middle" fontSize={7}
        fontFamily="monospace" fill={C.muted}>
        SCORE /100
      </text>

      
      {dims.map((d, i) => {
        const angle = a0 + i * (2 * Math.PI / N);
        const lx = cx + lR * Math.cos(angle);
        const ly = cy + lR * Math.sin(angle);
        const anchor = Math.abs(lx - cx) < 8 ? 'middle' : lx < cx ? 'end' : 'start';
        const pct    = Math.round(d.value * 100);
        const pctCol = pct > 65 ? C.danger : pct > 35 ? C.warn : C.ok;
        return (
          <g key={d.key}>
            <text x={lx.toFixed(1)} y={(ly - 4).toFixed(1)} textAnchor={anchor}
              fontSize={7.5} fontFamily="monospace" fill={C.sub}>
              {d.label}
            </text>
            <text x={lx.toFixed(1)} y={(ly + 8).toFixed(1)} textAnchor={anchor}
              fontSize={9} fontWeight={700} fontFamily="monospace" fill={pctCol}>
              {pct}%
            </text>
          </g>
        );
      })}
    </svg>
  );
}

const PRIO_COL = PRIORITY_COLORS; // source unique → src/utils/colorScheme.js

function MiniCalendar({ deadlines, onNavigate }) {
  const { t, i18n } = useTranslation();
  const today = new Date();
  const [year, setYear]   = useState(today.getFullYear());
  const [month, setMonth] = useState(today.getMonth());

  const WD = useMemo(() => {
    const base = new Date(2024, 0, 1); // Monday Jan 1 2024
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(base);
      d.setDate(1 + i);
      return d.toLocaleDateString(i18n.language, { weekday: 'narrow' });
    });
  }, [i18n.language]);

  const monthLabel = useMemo(() =>
    new Date(year, month, 1).toLocaleDateString(i18n.language, { month: 'long', year: 'numeric' })
  , [year, month, i18n.language]);

  const byDay = {};
  deadlines.forEach(d => {
    const key = d.report_deadline.slice(0, 10);
    if (!byDay[key]) byDay[key] = [];
    byDay[key].push(d);
  });

  const first = new Date(year, month, 1);
  let dow = first.getDay();
  dow = dow === 0 ? 6 : dow - 1;
  const dim = new Date(year, month + 1, 0).getDate();
  const cells = [];
  for (let i = 0; i < dow; i++) cells.push(null);
  for (let d = 1; d <= dim; d++) cells.push(d);

  const prevM = () => { if (month === 0) { setMonth(11); setYear(y => y - 1); } else setMonth(m => m - 1); };
  const nextM = () => { if (month === 11) { setMonth(0);  setYear(y => y + 1); } else setMonth(m => m + 1); };

  const sorted = [...deadlines].sort((a, b) => new Date(a.report_deadline) - new Date(b.report_deadline));

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden' }}>

      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <CalendarDays size={13} style={{ color: C.sub }} />
          <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>{t('dashboard.deadlines')}</span>
        </div>
        <button onClick={() => onNavigate('/calendar')} style={{ fontSize: 10, color: C.accent, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 3 }}>
          {t('dashboard.see_all_deadlines')} <ChevronRight size={10} />
        </button>
      </div>

      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button onClick={prevM} style={{ background: 'none', border: 'none', cursor: 'pointer', color: C.sub, fontSize: 16, lineHeight: 1, padding: '0 4px' }}>‹</button>
        <span style={{ fontSize: 11, fontWeight: 600, color: C.text, fontFamily: 'monospace', textTransform: 'capitalize' }}>
          {monthLabel}
        </span>
        <button onClick={nextM} style={{ background: 'none', border: 'none', cursor: 'pointer', color: C.sub, fontSize: 16, lineHeight: 1, padding: '0 4px' }}>›</button>
      </div>

      
      <div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', marginBottom: 4 }}>
          {WD.map((d, i) => (
            <div key={i} style={{ textAlign: 'center', fontSize: 9, fontFamily: 'monospace', color: C.muted }}>{d}</div>
          ))}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2 }}>
          {cells.map((day, i) => {
            if (!day) return <div key={`e${i}`} />;
            const key = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
            const hits = byDay[key] || [];
            const isToday = day === today.getDate() && month === today.getMonth() && year === today.getFullYear();
            const topHit = hits.find(h => h.priority === 'critical') || hits.find(h => h.priority === 'high') || hits[0];
            const dotColor = topHit ? (PRIO_COL[topHit.priority] || C.sub) : null;
            return (
              <div
                key={key}
                onClick={hits.length > 0 ? () => onNavigate(hits.length === 1 ? `/cases/${hits[0].id}` : '/calendar') : undefined}
                title={hits.map(h => `${h.title} — ${Math.floor(parseFloat(h.hours_remaining) / 24)}d ${t('dashboard.days_remaining')}`).join('\n') || undefined}
                style={{
                  position: 'relative', textAlign: 'center', padding: '3px 0', borderRadius: 4,
                  cursor: hits.length > 0 ? 'pointer' : 'default',
                  background: isToday ? `${C.accent}20` : hits.length > 0 ? `${dotColor}12` : 'transparent',
                  border: isToday ? `1px solid ${C.accent}40` : '1px solid transparent',
                }}
              >
                <span style={{
                  fontSize: 10, fontFamily: 'monospace',
                  color: isToday ? C.accent : hits.length > 0 ? dotColor : C.sub,
                  fontWeight: isToday || hits.length > 0 ? 700 : 400,
                }}>
                  {day}
                </span>
                {hits.length > 0 && (
                  <div style={{ position: 'absolute', bottom: 1, left: '50%', transform: 'translateX(-50%)', width: 4, height: 4, borderRadius: '50%', background: dotColor }} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      
      <div style={{ borderTop: `1px solid ${C.border2}`, paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 5, overflow: 'auto', maxHeight: 130 }}>
        {sorted.length === 0 ? (
          <div style={{ textAlign: 'center', fontSize: 11, color: C.muted, fontFamily: 'monospace', padding: '6px 0' }}>
            {t('dashboard.no_deadlines')}
          </div>
        ) : sorted.slice(0, 5).map(d => {
          const h = parseFloat(d.hours_remaining);
          const days = Math.floor(h / 24);
          const hrs  = Math.round(h % 24);
          const isUrgent = h < 48;
          const isWeek   = h >= 48 && h < 168;
          const col = isUrgent ? C.danger : isWeek ? C.warn : C.sub;
          const label = h < 24
            ? `${Math.round(h)}h`
            : `${days}j${hrs > 0 ? ` ${hrs}h` : ''}`;
          return (
            <button key={d.id} onClick={() => onNavigate(`/cases/${d.id}`)} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left', padding: '2px 0',
            }}>
              <div style={{ width: 3, height: 26, borderRadius: 2, background: PRIO_COL[d.priority] || C.sub, flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{d.title}</div>
                <div style={{ fontSize: 10, color: C.muted, fontFamily: 'monospace' }}>{d.case_number}</div>
              </div>
              <div style={{ flexShrink: 0, textAlign: 'right' }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: col, fontFamily: 'monospace' }}>
                  {isUrgent && '⚠ '}{label}
                </div>
                <div style={{ fontSize: 9, color: C.muted, fontFamily: 'monospace' }}>{t('dashboard.days_remaining')}</div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

const ARTIFACT_COLORS = {
  evtx: 'var(--fl-accent)', prefetch: '#a855f7', mft: '#22c55e', lnk: '#eab308',
  registry: '#f59e0b', amcache: 'var(--fl-danger)', appcompat: '#3b82f6', shellbags: '#06b6d4',
  jumplist: 'var(--fl-purple)', srum: '#10b981', wxtcmd: '#f97316', recycle: '#6b7280',
  bits: '#ec4899', sum: '#14b8a6', sqle: '#84cc16', hayabusa: '#dc2626',
};

function ArtifactStats({ artifacts }) {
  if (!artifacts) return null;
  const breakdown = artifacts.breakdown || [];
  const total = parseInt(artifacts.total_lines) || 0;
  if (total === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '20px 0', gap: 6 }}>
        <Database size={22} style={{ color: C.border }} />
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.muted }}>Aucun artefact parsé</span>
      </div>
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      
      <div style={{ display: 'flex', gap: 16, marginBottom: 4 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 800, color: C.accent, fontFamily: 'monospace', lineHeight: 1 }}>
            {total.toLocaleString()}
          </div>
          <div style={{ fontSize: 9, color: C.muted, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em' }}>lignes totales</div>
        </div>
        <div>
          <div style={{ fontSize: 22, fontWeight: 800, color: C.purple, fontFamily: 'monospace', lineHeight: 1 }}>
            {parseInt(artifacts.artifact_types) || 0}
          </div>
          <div style={{ fontSize: 9, color: C.muted, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em' }}>types d'artefacts</div>
        </div>
      </div>
      
      {breakdown.slice(0, 8).map(({ type, lines }) => {
        const count = parseInt(lines) || 0;
        const pct   = Math.round((count / total) * 100);
        const color = ARTIFACT_COLORS[type] || C.sub;
        return (
          <div key={type}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
                <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.sub, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{type}</span>
              </div>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.text, fontWeight: 600 }}>
                {count.toLocaleString()} <span style={{ color: C.muted, fontWeight: 400 }}>({pct}%)</span>
              </span>
            </div>
            <div style={{ height: 3, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.6s ease' }} />
            </div>
          </div>
        );
      })}
      {breakdown.length > 8 && (
        <div style={{ fontSize: 9, color: C.muted, fontFamily: 'monospace', textAlign: 'right' }}>
          +{breakdown.length - 8} autres types
        </div>
      )}
    </div>
  );
}

const ACTION_ICON = {
  create_case:    { icon: '📁', color: '#4d82c0' },
  update_case:    { icon: '✏️', color: '#8b72d6' },
  close_case:     { icon: '✓',  color: '#22c55e' },
  upload_evidence:{ icon: '⬆', color: '#4d82c0' },
  delete_evidence:{ icon: '🗑', color: '#da3633' },
  create_ioc:     { icon: '⚠', color: '#d97c20' },
  parse_collection:{ icon: '⚙', color: '#06b6d4' },
  login:          { icon: '🔑', color: '#8b72d6' },
  default:        { icon: '·',  color: '#6e7681'  },
};

function fmtRelTime(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'à l\'instant';
  if (m < 60) return `il y a ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `il y a ${h}h`;
  return `il y a ${Math.floor(h / 24)}j`;
}

function ActivityFeed({ items }) {
  if (!items || items.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px 0', gap: 6 }}>
        <Radio size={22} style={{ color: C.border }} />
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.muted }}>Aucune activité récente</span>
      </div>
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {items.map((item, i) => {
        const def = ACTION_ICON[item.action] || ACTION_ICON.default;
        const details = typeof item.details === 'string'
          ? (() => { try { return JSON.parse(item.details); } catch { return {}; } })()
          : (item.details || {});
        return (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 10, padding: '7px 4px',
            borderBottom: i < items.length - 1 ? `1px solid ${C.border2}` : 'none',
          }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%', flexShrink: 0,
              background: def.color + '18', border: `1px solid ${def.color}30`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, marginTop: 1,
            }}>
              {def.icon}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: C.text, lineHeight: 1.4 }}>
                <span style={{ color: def.color, fontWeight: 600 }}>{item.full_name || 'Système'}</span>
                {' — '}
                <span style={{ color: C.dim }}>{(item.action || '').replace(/_/g, ' ')}</span>
                {details.title && <span style={{ color: C.muted }}> · {String(details.title).slice(0, 40)}</span>}
              </div>
              <div style={{ fontSize: 9, fontFamily: 'monospace', color: C.muted, marginTop: 2 }}>
                {fmtRelTime(item.created_at)}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { t, i18n } = useTranslation();
  const [stats, setStats]         = useState(null);
  const [cases, setCases]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const [liveFlash, setLiveFlash] = useState(false);
  const [deadlines, setDeadlines]     = useState([]);
  const [leaderboard, setLeaderboard] = useState([]);
  const [topSharedIOCs, setTopSharedIOCs] = useState([]);
  const [riskDist, setRiskDist]           = useState([]);
  const { socket } = useSocket();

  const PRIO = useMemo(() => ({
    critical: { label: t('dashboard.prio_critical'), color: C.danger },
    high:     { label: t('dashboard.prio_high'),     color: C.warn },
    medium:   { label: t('dashboard.prio_medium'),   color: C.gold },
    low:      { label: t('dashboard.prio_low'),      color: C.ok },
  }), [t]);

  const STATUS = useMemo(() => ({
    active:   { label: t('dashboard.status_active'),  color: C.accent },
    pending:  { label: t('dashboard.status_pending'), color: C.warn },
    closed:   { label: t('dashboard.status_closed'),  color: C.muted },
    archived: { label: t('case.status_archived'),     color: C.muted },
  }), [t]);

  const loadStats = useCallback(() => {
    casesAPI.deadlines().then(r => setDeadlines(r.data.deadlines || [])).catch(() => {});
    casesAPI.leaderboard().then(r => setLeaderboard(r.data.leaderboard || [])).catch(() => {});
    iocsAPI.topShared().then(r => setTopSharedIOCs(r.data || [])).catch(() => {});

    casesAPI.list({ limit: 200 }).then(r => {
      const list = r.data?.cases || (Array.isArray(r.data) ? r.data : []);
      const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, null: 0 };
      list.forEach(c => { const l = c.risk_level || 'null'; dist[l] = (dist[l] || 0) + 1; });
      setRiskDist([
        { level: 'CRITICAL', count: dist.CRITICAL, color: C.danger },
        { level: 'HIGH',     count: dist.HIGH,     color: C.warn  },
        { level: 'MEDIUM',   count: dist.MEDIUM,   color: C.gold  },
        { level: 'LOW',      count: dist.LOW,      color: C.ok    },
      ].filter(d => d.count > 0));
    }).catch(() => {});
    Promise.all([
      casesAPI.stats().catch(() => null),
      casesAPI.list({ limit: 6 }).catch(() => ({ data: { cases: [] } })),
    ]).then(([statsRes, casesRes]) => {
      setStats(statsRes?.data || {
        cases:    { active_cases: 0, pending_cases: 0, closed_cases: 0, critical_cases: 0, total_cases: 0 },
        evidence: { total_evidence: 0, highlighted_evidence: 0, total_size: 0 },
        iocs:     { total_iocs: 0, malicious_iocs: 0, ioc_types: 0 },
        daily_activity: [],
      });
      const list = casesRes.data?.cases || (Array.isArray(casesRes.data) ? casesRes.data : []);
      setCases(list.slice(0, 6));
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
      <span style={{ fontSize: 12, fontFamily: 'monospace', color: C.muted }}>{t('dashboard.loading')}</span>
    </div>
  );

  const s = stats;
  const tl = threatLevel(s, t);
  const TLIcon = tl.icon;
  const currentUserId = (() => { try { return JSON.parse(localStorage.getItem('heimdall_user') || '{}').id; } catch { return null; } })();
  const dateStr = new Date().toLocaleDateString(i18n.language, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  const closedPct = s.cases.total_cases > 0
    ? Math.round((s.cases.closed_cases / s.cases.total_cases) * 100)
    : 0;

  const activityData = (s.daily_activity || []).map(r => ({
    day: r.label,
    events: parseInt(r.events) || 0,
    iocs: parseInt(r.iocs) || 0,
  }));
  const hasActivity = activityData.some(d => d.events > 0 || d.iocs > 0);

  return (
    <div style={{ padding: '20px 24px', background: C.bg, minHeight: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 16, borderBottom: `1px solid ${C.border2}` }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} style={{ color: C.accent }} />
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text, fontFamily: 'monospace', letterSpacing: '-0.01em' }}>Heimdall DFIR</span>
          </div>
          <div style={{ fontSize: 11, color: C.muted, fontFamily: 'monospace', marginTop: 3, textTransform: 'capitalize' }}>{dateStr}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px',
            background: liveFlash ? `${C.accent}12` : C.panel,
            border: `1px solid ${liveFlash ? `${C.accent}40` : C.border}`,
            borderRadius: 7, transition: 'all 0.3s',
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: liveFlash ? C.accent : C.ok, display: 'inline-block', boxShadow: `0 0 5px ${liveFlash ? C.accent : C.ok}80` }} />
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: liveFlash ? C.accent : C.ok }}>
              {liveFlash ? t('dashboard.updating') : t('dashboard.operational')}
            </span>
          </div>
          
          <button onClick={() => navigate('/cases')} style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px',
            background: C.accent, border: 'none', borderRadius: 7,
            color: '#fff', fontSize: 12, fontFamily: 'monospace', fontWeight: 600, cursor: 'pointer',
          }}>
            <Plus size={13} /> {t('dashboard.new_case')}
          </button>
        </div>
      </div>

      {(() => {
        const act  = s.daily_activity || [];
        const iocD = act.length >= 2 ? (parseInt(act[act.length-1]?.iocs)||0) - (parseInt(act[act.length-2]?.iocs)||0) : 0;
        const evtD = act.length >= 2 ? (parseInt(act[act.length-1]?.events)||0) - (parseInt(act[act.length-2]?.events)||0) : 0;
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard icon={Activity}      color={C.accent} label={t('dashboard.kpi_active')}         value={s.cases.active_cases}           onClick={() => navigate('/cases')}
              deltaLabel={evtD !== 0 ? `${evtD > 0 ? '▲' : '▼'} ${Math.abs(evtD)} événements vs hier` : t('dashboard.kpi_total', { n: s.cases.total_cases })} deltaPositive={evtD > 0 ? true : evtD < 0 ? false : null} />
            <StatCard icon={AlertTriangle} color={C.danger} label={t('dashboard.kpi_critical')}       value={s.cases.critical_cases}         onClick={() => navigate('/cases')}
              deltaLabel={s.cases.critical_cases > 0 ? `⚠ ${t('dashboard.kpi_attention')}` : `✓ ${t('dashboard.kpi_none_active')}`} deltaPositive={s.cases.critical_cases === 0} />
            <StatCard icon={Crosshair}     color={C.warn}   label={t('dashboard.kpi_malicious_iocs')} value={s.iocs.malicious_iocs}           onClick={() => navigate('/iocs')}
              deltaLabel={iocD !== 0 ? `${iocD > 0 ? '▲' : '▼'} ${Math.abs(iocD)} vs hier · ${s.iocs.total_iocs} total` : `${s.iocs.total_iocs} total IOCs`} deltaPositive={iocD <= 0} />
            <StatCard icon={FileText}      color={C.purple} label={t('dashboard.kpi_forensic')}       value={fmtBytes(s.evidence.total_size)}
              deltaLabel={t('dashboard.kpi_evidence', { n: s.evidence.total_evidence, h: s.evidence.highlighted_evidence })} deltaPositive={null} />
          </div>
        );
      })()}

      <div className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-3">

        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px 12px', borderBottom: `1px solid ${C.border2}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <FolderOpen size={13} style={{ color: C.sub }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>{t('dashboard.recent_cases')}</span>
            </div>
            <button onClick={() => navigate('/cases')} style={{ fontSize: 11, color: C.accent, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 3 }}>
              {t('dashboard.see_all')} <ChevronRight size={11} />
            </button>
          </div>
          <div style={{ flex: 1, padding: '6px 4px', overflow: 'auto' }}>
            {cases.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '32px 16px', gap: 8 }}>
                <FolderOpen size={28} style={{ color: C.border }} />
                <span style={{ fontSize: 12, color: C.muted, fontFamily: 'monospace' }}>{t('dashboard.no_cases')}</span>
                <button onClick={() => navigate('/cases')} style={{ fontSize: 11, padding: '4px 12px', borderRadius: 6, background: `${C.accent}15`, border: `1px solid ${C.accent}30`, color: C.accent, cursor: 'pointer', fontFamily: 'monospace', marginTop: 4 }}>
                  {t('dashboard.create_case')}
                </button>
              </div>
            ) : (
              cases.map(c => <CaseRow key={c.id} c={c} onClick={() => navigate(`/cases/${c.id}`)} statusMap={STATUS} prioMap={PRIO} />)
            )}
          </div>
        </div>

        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <TrendingUp size={13} style={{ color: C.sub }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>{t('dashboard.activity_title')}</span>
            </div>
            <div style={{ display: 'flex', gap: 14 }}>
              {[[t('dashboard.events'), C.accent], ['IOCs', C.danger]].map(([label, color]) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'monospace', color: C.sub }}>
                  <span style={{ display: 'inline-block', width: 20, height: 2, background: color, borderRadius: 1 }} />
                  {label}
                </div>
              ))}
            </div>
          </div>
          {hasActivity ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={activityData} margin={{ top: 4, right: 4, bottom: 0, left: -14 }}>
                <defs>
                  <linearGradient id="gEv" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={C.accent} stopOpacity={0.2} />
                    <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gIoc" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={C.danger} stopOpacity={0.15} />
                    <stop offset="95%" stopColor={C.danger} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" tick={{ fill: C.muted, fontSize: 10, fontFamily: 'monospace' }} axisLine={{ stroke: C.border2 }} tickLine={false} />
                <YAxis tick={{ fill: C.muted, fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <RechartsTooltip content={<ChartTooltip />} cursor={{ stroke: C.border, strokeDasharray: '3 3' }} />
                <Area type="monotone" dataKey="events" name={t('dashboard.events')} stroke={C.accent} strokeWidth={1.5} fill="url(#gEv)" dot={false} />
                <Area type="monotone" dataKey="iocs"   name="IOCs"       stroke={C.danger} strokeWidth={1.5} fill="url(#gIoc)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 200, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
              <Activity size={24} style={{ color: C.border }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.muted }}>{t('dashboard.no_activity')}</span>
            </div>
          )}
        </div>
      </div>

      {/* F — Activity feed */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '14px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
          <Radio size={13} style={{ color: C.accent }} />
          <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>
            Activité récente
          </span>
          {liveFlash && (
            <span style={{ marginLeft: 4, width: 6, height: 6, borderRadius: '50%', background: C.accent, display: 'inline-block', boxShadow: `0 0 6px ${C.accent}` }} />
          )}
        </div>
        <ActivityFeed items={s.recent_activity || []} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 16 }}>
              <Circle size={13} style={{ color: C.sub }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>{t('dashboard.case_dist')}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                [t('dashboard.status_active'),  s.cases.active_cases,   C.accent],
                [t('dashboard.status_pending'), s.cases.pending_cases,  C.warn],
                [t('dashboard.status_closed'),  s.cases.closed_cases,   C.ok],
              ].map(([label, count, color]) => {
                const total = s.cases.total_cases || 1;
                const pct = Math.round((count / total) * 100);
                return (
                  <div key={label}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.sub }}>{label}</span>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.text, fontWeight: 600 }}>{count} <span style={{ color: C.muted, fontWeight: 400 }}>({pct}%)</span></span>
                    </div>
                    <div style={{ height: 4, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.6s ease' }} />
                    </div>
                  </div>
                );
              })}
              <div style={{ marginTop: 4, paddingTop: 12, borderTop: `1px solid ${C.border2}`, display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 11, fontFamily: 'monospace', color: C.muted }}>{t('dashboard.resolution_rate')}</span>
                <span style={{ fontSize: 11, fontFamily: 'monospace', color: closedPct > 50 ? C.ok : C.sub, fontWeight: 600 }}>{closedPct}%</span>
              </div>
            </div>
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
              <Database size={13} style={{ color: C.sub }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>Artefacts parsés</span>
            </div>
            <ArtifactStats artifacts={s.artifacts} />
          </div>

          <MiniCalendar deadlines={deadlines} onNavigate={navigate} />

        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <TLIcon size={13} style={{ color: C.sub }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>{t('dashboard.threat_state')}</span>
            </div>
            <ThreatKpiCards s={s} deadlines={deadlines} />
            
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              padding: '7px 12px', borderRadius: 7,
              background: `${tl.color}0d`, border: `1px solid ${tl.color}25`,
            }}>
              <TLIcon size={12} style={{ color: tl.color }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: tl.color, fontFamily: 'monospace' }}>{tl.label}</span>
              <span style={{ fontSize: 9, color: C.muted, fontFamily: 'monospace' }}>— {t('dashboard.threat_global')}</span>
            </div>
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Zap size={13} style={{ color: C.gold }} />
                <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>
                  Progression investigators
                </span>
              </div>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.muted }}>
                7 derniers jours
              </span>
            </div>
            <LeaderboardWidget rows={leaderboard} currentUserId={currentUserId} />
          </div>

        </div>

        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>

          {riskDist.length > 0 && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px', flex: '1 1 280px', minWidth: 260 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
                <ShieldAlert size={13} style={{ color: C.danger }} />
                <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>
                  Distribution Risk Score
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {riskDist.map(({ level, count, color }) => {
                  const total = riskDist.reduce((s, d) => s + d.count, 0);
                  const pct   = Math.round((count / total) * 100);
                  return (
                    <div key={level}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color, textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>{level}</span>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.text, fontWeight: 600 }}>{count} <span style={{ color: C.muted, fontWeight: 400 }}>({pct}%)</span></span>
                      </div>
                      <div style={{ height: 4, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.6s ease' }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {topSharedIOCs.length > 0 && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '18px 20px', flex: '2 1 360px', minWidth: 300 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
                <Link2 size={13} style={{ color: C.accent }} />
                <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: C.sub }}>
                  Top 10 IOCs multi-cas
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {topSharedIOCs.slice(0, 10).map((ioc, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 8px', borderRadius: 6, background: ioc.any_malicious ? 'color-mix(in srgb, var(--fl-danger) 5%, transparent)' : 'transparent' }}>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.muted, width: 16, flexShrink: 0 }}>{i + 1}</span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', background: C.border, color: C.sub, padding: '1px 5px', borderRadius: 3, flexShrink: 0, textTransform: 'uppercase' }}>{ioc.ioc_type}</span>
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: ioc.any_malicious ? C.danger : C.text, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                          title={ioc.ioc_value}>{ioc.ioc_value}</span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: C.accent, flexShrink: 0, fontWeight: 700 }}>{ioc.case_count} cas</span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
