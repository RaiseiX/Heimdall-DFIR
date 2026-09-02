import { ChevronRight, ChevronDown } from 'lucide-react';

const LEVEL_COLORS = ['var(--fl-accent)', 'var(--fl-purple)', 'var(--fl-ok)', 'var(--fl-warn)'];

export function GroupRow({ field, value, count, level, isOpen, onClick, height, span, locale }) {
  const accent   = LEVEL_COLORS[level % LEVEL_COLORS.length];
  const indent   = level * 16;
  const bgNormal = level === 0 ? '#08101e' : 'var(--fl-bg)';

  const fmt = ms => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
  const rangeLabel = span
    ? (span.first === span.last ? fmt(span.first) : `${fmt(span.first)} → ${fmt(span.last)}`)
    : null;

  return (
    <div onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 5,
        paddingLeft: 10 + indent, paddingRight: 10,
        height: height ?? (level === 0 ? 28 : 24),
        background: bgNormal,
        borderBottom: '1px solid var(--fl-panel)',
        borderLeft: `1px solid ${accent}`,
        cursor: 'pointer', userSelect: 'none',
      }}
      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
      onMouseLeave={e => { e.currentTarget.style.background = bgNormal; }}>

      {level > 0 && (
        <span style={{ color: accent, fontSize: 9, opacity: 0.55, flexShrink: 0, marginRight: 1, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          └─
        </span>
      )}

      {isOpen
        ? <ChevronDown  size={10} style={{ color: accent, flexShrink: 0 }} />
        : <ChevronRight size={10} style={{ color: accent, flexShrink: 0 }} />}

      <span style={{ fontSize: 8, color: accent, textTransform: 'uppercase',
        letterSpacing: '0.08em', fontWeight: 700, flexShrink: 0, opacity: 0.75,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        {field}
      </span>

      <span style={{ fontSize: level === 0 ? 11 : 10, color: 'var(--fl-on-dark)', fontWeight: 600,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        {String(value ?? '—')}
      </span>

      {rangeLabel && (
        <span style={{ fontSize: 9, color: 'var(--fl-muted)', flexShrink: 0, marginLeft: 10,
          whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          {rangeLabel}
        </span>
      )}

      <span style={{ flex: 1 }} />

      <span style={{ fontSize: 9, color: accent,
        flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700 }}>
        {(count ?? 0).toLocaleString(locale)}
      </span>
    </div>
  );
}

export function ClusterRow({ startTs, endTs, host, count, typeBreakdown, isOpen, onClick }) {
  const label = [
    startTs ? startTs.slice(0, 16).replace('T', ' ') : '—',
    endTs && endTs !== startTs ? `–${endTs.slice(11, 16)}` : '',
    host ? ` · ${host}` : '',
    ` · ${count ?? 0} event${(count ?? 0) !== 1 ? 's' : ''}`,
    typeBreakdown?.length ? ` · ${typeBreakdown.map(([t, n]) => `${t} x${n}`).join(', ')}` : '',
  ].join('');

  return (
    <div onClick={onClick}
      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px',
        background: '#060d16', borderBottom: '1px solid var(--fl-panel)', borderTop: '1px solid var(--fl-panel)',
        cursor: 'pointer', userSelect: 'none' }}
      onMouseEnter={e => { e.currentTarget.style.background = '#0a1020'; }}
      onMouseLeave={e => { e.currentTarget.style.background = '#060a12'; }}>
      <span style={{ fontSize: 9, color: '#3a5a7a' }}>{isOpen ? '▼' : '▶'}</span>
      <span style={{ fontSize: 9, color: '#4a6a8a', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </span>
    </div>
  );
}

export default GroupRow;
