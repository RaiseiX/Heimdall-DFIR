// Shared building blocks for the Settings page sections (Observatory charter).
export const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
export const UI   = 'var(--f-ui, "Inter", sans-serif)';

export function Row({ label, desc, children, last }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 24, padding: '16px 0', borderBottom: last ? 'none' : '1px solid var(--fl-border2)' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: 'var(--fl-text)', fontFamily: UI, fontWeight: 500 }}>{label}</div>
        {desc && <div style={{ fontSize: 11.5, color: 'var(--fl-muted)', fontFamily: UI, marginTop: 3, lineHeight: 1.5 }}>{desc}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{children}</div>
    </div>
  );
}

export function Toggle({ on, onClick }) {
  return (
    <button onClick={onClick} style={{ width: 38, height: 22, borderRadius: 99, padding: 2, border: 'none', cursor: 'pointer',
      background: on ? 'var(--fl-accent)' : 'var(--fl-surface-active)', transition: 'background 0.15s', display: 'flex', alignItems: 'center' }}>
      <span style={{ width: 18, height: 18, borderRadius: '50%', background: '#fff', transform: on ? 'translateX(16px)' : 'translateX(0)', transition: 'transform 0.15s' }} />
    </button>
  );
}

export function SegToggle({ value, options, onChange }) {
  return (
    <div style={{ display: 'inline-flex', border: '1px solid var(--fl-border)', borderRadius: 6, overflow: 'hidden' }}>
      {options.map(o => (
        <button key={o.value} onClick={() => onChange(o.value)}
          style={{ padding: '5px 12px', fontSize: 11, fontFamily: MONO, cursor: 'pointer', border: 'none',
            background: value === o.value ? 'var(--fl-accent)' : 'transparent',
            color: value === o.value ? '#fff' : 'var(--fl-muted)' }}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function SectionHead({ title, desc }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <h2 style={{ fontSize: 20, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{title}</h2>
      {desc && <p style={{ fontSize: 12.5, color: 'var(--fl-muted)', fontFamily: UI, margin: '4px 0 0' }}>{desc}</p>}
    </div>
  );
}

export function Btn({ children, onClick, variant = 'default', disabled, title }) {
  const styles = {
    primary: { background: 'var(--fl-accent)', color: '#fff', border: '1px solid var(--fl-accent)' },
    danger:  { background: 'color-mix(in srgb, var(--fl-danger) 9%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 21%, transparent)' },
    ok:      { background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 21%, transparent)' },
    default: { background: 'var(--fl-card)', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)' },
  }[variant];
  return (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{ padding: '6px 12px', borderRadius: 6, fontSize: 11.5, fontFamily: MONO, fontWeight: 600,
        cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.5 : 1, display: 'inline-flex', alignItems: 'center', gap: 6, ...styles }}>
      {children}
    </button>
  );
}

export function Input(props) {
  return (
    <input {...props}
      style={{ padding: '7px 10px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)',
        color: 'var(--fl-text)', fontFamily: MONO, fontSize: 12, width: props.width || 220, ...props.style }} />
  );
}

const TH = { textAlign: 'left', padding: '7px 10px', fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', fontWeight: 600, whiteSpace: 'nowrap' };
const TD = { padding: '0 10px', height: 40, borderBottom: '1px solid var(--fl-border2)', verticalAlign: 'middle', fontSize: 11.5, fontFamily: UI, color: 'var(--fl-text)' };

export function Table({ cols, children }) {
  return (
    <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginTop: 16 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)' }}>
            {cols.map(([label, w]) => <th key={label} style={{ ...TH, width: w || undefined }}>{label}</th>)}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
export const tdStyle = TD;

export function Skeletons({ n = 4, h = 40 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
      {Array.from({ length: n }, (_, i) => <div key={i} className="fl-skeleton" style={{ height: h, borderRadius: 6, background: 'var(--fl-card)' }} />)}
    </div>
  );
}

export function Empty({ text }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: '40px 16px' }}>
      <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>{text}</span>
    </div>
  );
}

export function Msg({ msg }) {
  if (!msg) return null;
  return <span style={{ fontSize: 12, fontFamily: MONO, color: msg.startsWith('✓') ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>{msg}</span>;
}
