
import { AlertTriangle, CheckCircle2, XCircle, Info, X } from 'lucide-react';
import { mix } from '../../utils/colorUtils';

const VARIANTS = {
  danger:  { color: 'var(--fl-danger)', Icon: XCircle       },
  warn:    { color: 'var(--fl-warn)',   Icon: AlertTriangle },
  ok:      { color: 'var(--fl-ok)',     Icon: CheckCircle2  },
  accent:  { color: 'var(--fl-accent)', Icon: Info          },
};

export default function Alert({ variant = 'danger', message, dismissible = false, onDismiss, style }) {
  if (!message) return null;

  const { color, Icon } = VARIANTS[variant] ?? VARIANTS.danger;

  return (
    <div
      role="alert"
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 8,
        padding: '9px 12px',
        background: mix.bg(color),
        border: `1px solid ${mix.border(color)}`,
        borderRadius: 6,
        fontSize: '0.8125rem',
        color: 'var(--fl-text)',
        lineHeight: 1.4,
        ...style,
      }}
    >
      <Icon size={14} style={{ color, flexShrink: 0, marginTop: 1 }} />
      <span style={{ flex: 1 }}>{message}</span>
      {dismissible && (
        <button
          onClick={onDismiss}
          aria-label="Fermer l'alerte"
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--fl-muted)', padding: 0,
            display: 'flex', alignItems: 'center',
          }}
        >
          <X size={13} />
        </button>
      )}
    </div>
  );
}
