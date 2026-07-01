import { AlertTriangle, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

const STATUS_MAP = {
  active:  { key: 'case.status_active',  color: 'var(--fl-accent)' },
  pending: { key: 'case.status_pending', color: 'var(--fl-warn)'   },
  closed:  { key: 'case.status_closed',  color: 'var(--fl-dim)'    },
};

const PRIORITY_MAP = {
  critical: { key: 'cases.prio_critical', color: 'var(--fl-danger)', Icon: AlertTriangle },
  high:     { key: 'cases.prio_high',     color: 'var(--fl-warn)',   Icon: null          },
  medium:   { key: 'cases.prio_medium',   color: 'var(--fl-gold)',   Icon: null          },
  low:      { key: 'cases.prio_low',      color: 'var(--fl-ok)',     Icon: null          },
};

const RISK_MAP = {
  CRITICAL: { color: 'var(--fl-danger)', Icon: ShieldAlert },
  HIGH:     { color: 'var(--fl-warn)',   Icon: null        },
  MEDIUM:   { color: 'var(--fl-accent)', Icon: null        },
  LOW:      { color: 'var(--fl-ok)',     Icon: null        },
};

export function StatusPill({ status }) {
  const { t } = useTranslation();
  const m = STATUS_MAP[status] || { color: 'var(--fl-dim)' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600,
      background: `color-mix(in srgb, ${m.color} 9%, transparent)`, color: m.color,
      border: `1px solid color-mix(in srgb, ${m.color} 21%, transparent)`,
    }}>
      {m.key ? t(m.key) : status}
    </span>
  );
}

export function PriorityPill({ priority }) {
  const { t } = useTranslation();
  const m = PRIORITY_MAP[priority] || { color: 'var(--fl-dim)', Icon: null };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
      background: `color-mix(in srgb, ${m.color} 9%, transparent)`, color: m.color,
      border: `1px solid color-mix(in srgb, ${m.color} 21%, transparent)`,
      textTransform: 'uppercase',
    }}>
      {m.Icon && <m.Icon size={9} />}
      {m.key ? t(m.key) : priority}
    </span>
  );
}

export function RiskPill({ riskLevel, riskScore }) {
  if (!riskLevel) return <span style={{ color: 'var(--fl-dim)', fontSize: 11 }}>—</span>;
  const m = RISK_MAP[riskLevel] || { color: 'var(--fl-dim)', Icon: null };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 7px', borderRadius: 4,
      fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
      background: `color-mix(in srgb, ${m.color} 8%, transparent)`, color: m.color,
      border: `1px solid color-mix(in srgb, ${m.color} 19%, transparent)`,
    }}>
      {m.Icon && <m.Icon size={9} />}
      {riskLevel}{riskScore != null ? ` ${riskScore}` : ''}
    </span>
  );
}

export function fmtDuration(seconds) {
  if (!seconds || seconds < 60) return seconds > 0 ? `${seconds}s` : '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m > 0 ? `${m}m` : ''}`.trim();
  return `${m}m`;
}

export function TimePill({ totalSeconds, analystCount, compact = false }) {
  const { t } = useTranslation();
  if (!totalSeconds) return null;
  const analystLabel = t((analystCount || 1) > 1 ? 'common.analyst_count_pl' : 'common.analyst_count', { count: analystCount || 1 });
  return (
    <span title={`${analystLabel} · ${fmtDuration(totalSeconds)}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 7px', borderRadius: 4,
        fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        background: 'var(--fl-card)', color: 'var(--fl-dim)',
        border: '1px solid var(--fl-border)',
      }}>
      ⏱ {fmtDuration(totalSeconds)}
      {!compact && analystCount > 0 && (
        <span style={{ color: 'var(--fl-subtle)', fontSize: 9 }}>· {analystCount}</span>
      )}
    </span>
  );
}
