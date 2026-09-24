
export function Segment({ options, active, onChange, label }) {
  return (
    <span
      role="tablist"
      aria-label={label}
      style={{ display: 'flex', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}
    >
      {options.map(o => {
        const on = o.id === active;
        return (
          <button
            key={o.id}
            type="button"
            role="tab"
            aria-selected={on}
            title={o.title}
            onClick={() => onChange(o.id)}
            style={{
              padding: '3px 10px', background: 'none', border: 0, font: 'inherit', cursor: 'pointer',
              borderBottom: `1px solid ${on ? 'var(--fl-accent)' : 'transparent'}`,
              color: on ? 'var(--fl-text)' : 'var(--fl-muted)',
              whiteSpace: 'nowrap',
            }}
          >{o.label}</button>
        );
      })}
    </span>
  );
}

export function Action({ children, onClick, active = null, title, disabled = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      disabled={disabled}
      {...(active === null ? {} : { 'aria-pressed': active })}
      style={{
        padding: '3px 4px', background: 'none', border: 0,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
        cursor: disabled ? 'default' : 'pointer',
        color: disabled ? 'var(--fl-subtle)' : active ? 'var(--fl-text)' : 'var(--fl-muted)',
        borderBottom: `1px solid ${active ? 'var(--fl-accent)' : 'transparent'}`,
        whiteSpace: 'nowrap',
      }}
    >{children}</button>
  );
}
