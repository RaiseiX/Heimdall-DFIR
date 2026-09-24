export const FS_CONTROL = 10.5;

export const controlStyle = (isActive) => ({
  display: 'inline-flex', alignItems: 'baseline', gap: 4,
  padding: '0 0 3px', alignSelf: 'center',
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: FS_CONTROL,
  fontWeight: isActive ? 600 : 400,
  background: 'none', border: 'none', outline: 'none', cursor: 'pointer',
  borderBottom: `1px solid ${isActive ? 'var(--fl-accent)' : 'transparent'}`,
  color: isActive ? 'var(--fl-text)' : 'var(--fl-muted)',
  textDecoration: 'none', whiteSpace: 'nowrap', flexShrink: 0,
  transition: 'color 0.12s, border-color 0.12s',
});

const isCurrent = (el, isActive) => isActive || el.getAttribute?.('aria-current') === 'page';

export const controlHover = (isActive) => ({
  onMouseEnter: (e) => { if (!isCurrent(e.currentTarget, isActive)) e.currentTarget.style.color = 'var(--fl-dim)'; },
  onMouseLeave: (e) => { if (!isCurrent(e.currentTarget, isActive)) e.currentTarget.style.color = 'var(--fl-muted)'; },
});

export const fieldStyle = () => ({
  display: 'flex', alignItems: 'center', gap: 9, flex: 1,
  background: 'none',
  borderBottom: '1px solid var(--fl-border)',
  padding: '6px 0',
});

export const separatorStyle = {
  width: 1, height: 13, background: 'var(--fl-border2)', alignSelf: 'center', flexShrink: 0,
};
