import { ChevronRight, ChevronDown } from 'lucide-react';

// One accent color per nesting level
const LEVEL_COLORS = ['var(--fl-accent)', 'var(--fl-purple)', 'var(--fl-ok)', 'var(--fl-warn)'];

export function GroupRow({ field, value, count, level, isOpen, onClick }) {
  const accent   = LEVEL_COLORS[level % LEVEL_COLORS.length];
  const indent   = level * 16;
  const bgNormal = level === 0 ? '#08101e' : 'var(--fl-bg)';

  return (
    <div onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 5,
        paddingLeft: 10 + indent, paddingRight: 10,
        height: level === 0 ? 28 : 24,
        background: bgNormal,
        borderBottom: '1px solid var(--fl-panel)',
        borderLeft: `3px solid ${accent}`,
        cursor: 'pointer', userSelect: 'none',
      }}
      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
      onMouseLeave={e => { e.currentTarget.style.background = bgNormal; }}>

      {/* Tree connector for nested levels */}
      {level > 0 && (
        <span style={{ color: accent, fontSize: 9, opacity: 0.55, flexShrink: 0, marginRight: 1, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          └─
        </span>
      )}

      {isOpen
        ? <ChevronDown  size={10} style={{ color: accent, flexShrink: 0 }} />
        : <ChevronRight size={10} style={{ color: accent, flexShrink: 0 }} />}

      {/* Field label */}
      <span style={{ fontSize: 8, color: accent, textTransform: 'uppercase',
        letterSpacing: '0.08em', fontWeight: 700, flexShrink: 0, opacity: 0.75,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        {field}
      </span>

      {/* Value */}
      <span style={{ fontSize: level === 0 ? 11 : 10, color: '#8ab4cc', fontWeight: 600,
        flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        {String(value ?? '—')}
      </span>

      {/* Count badge */}
      <span style={{ fontSize: 9, color: accent, background: `color-mix(in srgb, ${accent} 8%, transparent)`,
        border: `1px solid color-mix(in srgb, ${accent} 19%, transparent)`, borderRadius: 3, padding: '1px 6px',
        flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700 }}>
        {(count ?? 0).toLocaleString()}
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
