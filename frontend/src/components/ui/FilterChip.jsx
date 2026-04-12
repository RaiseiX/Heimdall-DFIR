export default function FilterChip({
  children,
  active = false,
  color = 'var(--fl-accent)',
  count,
  onClick,
  icon: Icon,
  style,
}) {
  const bg = active
    ? `color-mix(in srgb, ${color} 14%, transparent)`
    : 'transparent';
  const border = active ? color : 'var(--fl-border)';
  const textColor = active ? color : 'var(--fl-dim)';

  return (
    <button
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '3px 10px',
        borderRadius: 'var(--fl-radius-sm)',
        fontSize: 11,
        fontFamily: 'monospace',
        background: bg,
        border: `1px solid ${border}`,
        color: textColor,
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        transition: 'background 0.12s, border-color 0.12s, color 0.12s',
        ...style,
      }}
    >
      {Icon && <Icon size={11} />}
      {children}
      {count !== undefined && (
        <span style={{
          marginLeft: 2,
          opacity: active ? 1 : 0.7,
        }}>
          ({count})
        </span>
      )}
    </button>
  );
}
