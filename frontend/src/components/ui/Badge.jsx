
const VARIANT_COLORS = {
  accent:  'var(--fl-accent)',
  danger:  'var(--fl-danger)',
  warn:    'var(--fl-warn)',
  ok:      'var(--fl-ok)',
  purple:  'var(--fl-purple)',
  gold:    'var(--fl-gold)',
  dim:     'var(--fl-dim)',
  pink:    'var(--fl-pink)',
};

import { mix } from '../../utils/colorUtils';

export default function Badge({ children, variant = 'accent', color, mono = true, style }) {
  const c = color ?? VARIANT_COLORS[variant] ?? VARIANT_COLORS.accent;
  return (
    <span
      className="fl-badge"
      style={{
        background: mix.hover(c),
        color: c,
        border: `1px solid ${mix.border(c)}`,

        fontFamily: mono ? undefined : 'inherit',
        ...style,
      }}
    >
      {children}
    </span>
  );
}
