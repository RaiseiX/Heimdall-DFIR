const FS_TABLE = 11;
const FS_HEAD = 10;

export const TABLE_DENSITY = '6px 10px';

export const STATUS_TONES = {
  ok:     'var(--fl-ok)',
  warn:   'var(--fl-warn)',
  danger: 'var(--fl-danger)',
  accent: 'var(--fl-accent)',
  muted:  'var(--fl-muted)',
};

export const tableStyle = {
  width: '100%',
  borderCollapse: 'collapse',
  fontSize: FS_TABLE,
};

export const headStyle = (isSorted) => ({
  padding: TABLE_DENSITY,
  textAlign: 'left',
  fontSize: FS_HEAD,
  fontWeight: 400,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  color: isSorted ? 'var(--fl-accent)' : 'var(--fl-muted)',
  borderBottom: '1px solid var(--fl-border)',
  whiteSpace: 'nowrap',
});

export const cellStyle = ({ numeric = false } = {}) => ({
  padding: TABLE_DENSITY,
  textAlign: numeric ? 'right' : 'left',
  borderBottom: '1px solid var(--fl-border)',
  color: 'var(--fl-text)',
});

export const statusStyle = (tone) => ({
  fontSize: FS_HEAD,
  color: STATUS_TONES[tone] ?? STATUS_TONES.muted,
});

export const markStyle = (color, size = FS_HEAD) => ({
  display: 'inline-flex',
  alignItems: 'baseline',
  gap: 3,
  whiteSpace: 'nowrap',
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  fontSize: size,
  color,
});
