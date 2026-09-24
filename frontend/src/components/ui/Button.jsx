import { Loader2 } from 'lucide-react';

export default function Button({
  children,
  variant = 'secondary',
  size = 'md',
  loading = false,
  disabled = false,
  icon: Icon,
  className = '',
  type = 'button',
  onClick,
  title,
  style,
}) {
  const base = 'fl-btn';
  const v = variant === 'primary'   ? 'fl-btn-primary'
          : variant === 'danger'    ? 'fl-btn-danger'
          : variant === 'ghost'     ? 'fl-btn-ghost'
          : 'fl-btn-secondary';
  const s = size === 'sm' ? 'fl-btn-sm'
          : size === 'xs' ? 'fl-btn-xs'
          : '';

  return (
    <button
      type={type}
      className={[base, v, s, className].filter(Boolean).join(' ')}
      disabled={disabled || loading}
      onClick={onClick}
      title={title}
      style={style}
    >
      {loading
        ? <Loader2 size={size === 'xs' ? 11 : size === 'sm' ? 12 : 14} className="animate-spin" />
        : Icon && <Icon size={size === 'xs' ? 11 : size === 'sm' ? 12 : 14} />}
      {children}
    </button>
  );
}
