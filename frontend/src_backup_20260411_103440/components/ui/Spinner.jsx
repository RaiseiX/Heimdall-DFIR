import { Loader2 } from 'lucide-react';

export default function Spinner({ size = 16, full = false, text, color = 'var(--fl-dim)' }) {
  const icon = (
    <Loader2
      size={size}
      className="animate-spin"
      style={{ color, flexShrink: 0 }}
    />
  );

  if (full) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        gap: 10, padding: '48px 24px',
        color: 'var(--fl-dim)',
      }}>
        <Loader2 size={size} className="animate-spin" style={{ color }} />
        {text && <span style={{ fontSize: 13 }}>{text}</span>}
      </div>
    );
  }

  if (text) {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color }}>
        {icon}
        <span style={{ fontSize: 13 }}>{text}</span>
      </span>
    );
  }

  return icon;
}
