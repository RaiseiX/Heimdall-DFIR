import { AlertTriangle, ShieldAlert } from 'lucide-react';

const STATUS_MAP = {
  active:  { label: 'Actif',        color: 'var(--fl-accent)' },
  pending: { label: 'En attente',   color: 'var(--fl-warn)'   },
  closed:  { label: 'Fermé',        color: 'var(--fl-dim)'    },
};

const PRIORITY_MAP = {
  critical: { label: 'Critique', color: 'var(--fl-danger)', Icon: AlertTriangle },
  high:     { label: 'Haut',     color: 'var(--fl-warn)',   Icon: null          },
  medium:   { label: 'Moyen',    color: 'var(--fl-gold)',   Icon: null          },
  low:      { label: 'Faible',   color: 'var(--fl-ok)',     Icon: null          },
};

const RISK_MAP = {
  CRITICAL: { color: 'var(--fl-danger)', Icon: ShieldAlert },
  HIGH:     { color: 'var(--fl-warn)',   Icon: null        },
  MEDIUM:   { color: 'var(--fl-accent)', Icon: null        },
  LOW:      { color: 'var(--fl-ok)',     Icon: null        },
};

export function StatusPill({ status }) {
  const m = STATUS_MAP[status] || { label: status, color: 'var(--fl-dim)' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: 'monospace', fontWeight: 600,
      background: `${m.color}18`, color: m.color, border: `1px solid ${m.color}35`,
    }}>
      {m.label}
    </span>
  );
}

export function PriorityPill({ priority }) {
  const m = PRIORITY_MAP[priority] || { label: priority, color: 'var(--fl-dim)', Icon: null };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
      background: `${m.color}18`, color: m.color, border: `1px solid ${m.color}35`,
      textTransform: 'uppercase',
    }}>
      {m.Icon && <m.Icon size={9} />}
      {m.label}
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
      fontSize: 11, fontFamily: 'monospace', fontWeight: 700,
      background: `${m.color}15`, color: m.color, border: `1px solid ${m.color}30`,
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
  if (!totalSeconds) return null;
  return (
    <span title={`${analystCount || 1} analyste${analystCount > 1 ? 's' : ''} · ${fmtDuration(totalSeconds)}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '2px 7px', borderRadius: 4,
        fontSize: 10, fontFamily: 'monospace',
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
