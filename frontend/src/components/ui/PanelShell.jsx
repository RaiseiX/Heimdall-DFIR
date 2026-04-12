export default function PanelShell({
  icon: Icon,
  title,
  subtitle,
  actions,
  children,
  style,
  bodyStyle,
  noPadding = false,
}) {
  return (
    <div
      className="fl-card"
      style={{ overflow: 'hidden', ...style }}
    >
      {(title || actions) && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '10px 14px',
          borderBottom: '1px solid var(--fl-border)',
          background: 'var(--fl-bg)',
        }}>
          {Icon && <Icon size={15} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />}
          <div style={{ flex: 1, minWidth: 0 }}>
            {title && (
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'monospace' }}>
                {title}
              </span>
            )}
            {subtitle && (
              <span style={{ fontSize: 11, color: 'var(--fl-dim)', marginLeft: 10 }}>
                {subtitle}
              </span>
            )}
          </div>
          {actions && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
              {actions}
            </div>
          )}
        </div>
      )}
      <div style={noPadding ? bodyStyle : { padding: '10px 14px', ...bodyStyle }}>
        {children}
      </div>
    </div>
  );
}
