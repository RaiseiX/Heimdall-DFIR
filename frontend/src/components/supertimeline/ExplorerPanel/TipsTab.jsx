import { useState } from 'react';
import { ChevronRight, ChevronDown } from 'lucide-react';

const S = {
  section: { borderBottom: '1px solid var(--fl-panel)', paddingBottom: 8, marginBottom: 2 },
  heading: {
    fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
    letterSpacing: '0.08em', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
    display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer',
    padding: '6px 12px 4px',
    userSelect: 'none',
  },
  body: { padding: '0 12px 4px' },
  row: { display: 'flex', alignItems: 'flex-start', gap: 7, marginBottom: 7 },
  badge: {
    flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, fontWeight: 700,
    padding: '1px 5px', borderRadius: 3, whiteSpace: 'nowrap', marginTop: 1,
  },
  desc: { fontSize: 10, color: '#7a8ba0', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1.5 },
  code: {
    display: 'inline-block', background: 'var(--fl-panel)', color: '#6aabdb',
    border: '1px solid var(--fl-raised)', borderRadius: 3,
    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, padding: '0px 4px', marginTop: 2,
  },
  kbd: {
    display: 'inline-block', background: 'var(--fl-panel)', color: 'var(--fl-dim)',
    border: '1px solid var(--fl-subtle)', borderRadius: 3,
    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, padding: '0px 5px',
  },
};

function Section({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={S.section}>
      <div style={S.heading} onClick={() => setOpen(v => !v)}>
        {open
          ? <ChevronDown size={9} style={{ color: 'var(--fl-accent)' }} />
          : <ChevronRight size={9} />}
        {title}
      </div>
      {open && <div style={S.body}>{children}</div>}
    </div>
  );
}

function Row({ badge, badgeColor = 'var(--fl-accent)', badgeBg = 'var(--fl-card)', badgeBorder = 'var(--fl-raised)', children }) {
  return (
    <div style={S.row}>
      <span style={{ ...S.badge, color: badgeColor, background: badgeBg, border: `1px solid ${badgeBorder}` }}>
        {badge}
      </span>
      <span style={S.desc}>{children}</span>
    </div>
  );
}

const OPS = [
  { op: 'contains',     color: 'var(--fl-accent)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: 'The value appears anywhere in the field.' },
  { op: 'not contains', color: 'var(--fl-purple)', bg: '#1a1030', border: '#2a1a50', desc: 'Excludes rows containing the value.' },
  { op: 'equals',       color: 'var(--fl-ok)', bg: '#0e2218', border: '#1a3520', desc: 'Exact match, case-insensitive.' },
  { op: 'not equals',   color: 'var(--fl-danger)', bg: '#2a0f0f', border: '#3a1818', desc: 'Excludes the exact match.' },
  { op: 'starts with',  color: 'var(--fl-gold)', bg: '#1a1808', border: '#3a3010', desc: 'The field starts with the value.' },
  { op: 'ends with',    color: 'var(--fl-gold)', bg: '#1a1808', border: '#3a3010', desc: 'The field ends with the value.' },
  { op: 'regex',        color: 'var(--fl-purple)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: <>PostgreSQL regex. Ex: <span style={S.code}>^cmd\.exe$</span></> },
  { op: 'is empty',     color: 'var(--fl-muted)', bg: 'var(--fl-bg)', border: 'var(--fl-raised)', desc: 'Field empty or NULL. No value required.' },
  { op: 'is not empty', color: 'var(--fl-dim)', bg: 'var(--fl-bg)', border: 'var(--fl-raised)', desc: 'Non-empty field.' },
];

const PREFIXES = [
  { prefix: 'host:',   color: 'var(--fl-purple)', bg: '#1a1030', border: '#2a1a50', desc: <>Filter by machine. Ex: <span style={S.code}>host:DC01</span></> },
  { prefix: 'user:',   color: 'var(--fl-pink)', bg: '#1a1030', border: '#2a1a50', desc: <>Filter by user. Ex: <span style={S.code}>user:Administrator</span></> },
  { prefix: 'type:',   color: 'var(--fl-ok)', bg: '#0e2218', border: '#1a3520', desc: <>Artifact type. Ex: <span style={S.code}>type:evtx</span></> },
  { prefix: 'tool:',   color: 'var(--fl-accent)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: <>Parsing tool. Ex: <span style={S.code}>tool:Hayabusa</span></> },
  { prefix: 'eid:',    color: 'var(--fl-dim)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: <>Event ID. Ex: <span style={S.code}>eid:4624</span></> },
  { prefix: 'ext:',    color: 'var(--fl-dim)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: <>Extension. Ex: <span style={S.code}>ext:ps1</span></> },
  { prefix: 'tag:',    color: 'var(--fl-purple)', bg: 'var(--fl-card)', border: 'var(--fl-raised)', desc: <>YARA/detection tag. Ex: <span style={S.code}>tag:T1059</span></> },
  { prefix: 'sev:',    color: 'var(--fl-danger)', bg: '#2a0f0f', border: '#3a1818', desc: <>Severity. Ex: <span style={S.code}>sev:critical</span></> },
  { prefix: 'after:',  color: 'var(--fl-gold)', bg: '#1a1808', border: '#3a3010', desc: <>Start date. Ex: <span style={S.code}>after:2024-01-15</span></> },
  { prefix: 'before:', color: 'var(--fl-gold)', bg: '#1a1808', border: '#3a3010', desc: <>End date. Ex: <span style={S.code}>before:2024-06-01</span></> },
];

export default function TipsTab() {
  return (
    <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', paddingTop: 4 }}>

      <Section title="Search bar" defaultOpen>
        <div style={{ ...S.desc, marginBottom: 8 }}>
          Type free text to filter on <b style={{ color: 'var(--fl-dim)' }}>description</b>,{' '}
          <b style={{ color: 'var(--fl-dim)' }}>source</b> and{' '}
          <b style={{ color: 'var(--fl-dim)' }}>artifact_type</b> at the same time.
        </div>
        <div style={{ ...S.desc, marginBottom: 8 }}>
          Prefix <span style={S.code}>-</span> to exclude:{' '}
          <span style={S.code}>-Logon</span> filters out rows that do not contain "Logon".
        </div>
        <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
          letterSpacing: '0.06em', marginBottom: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          Keys
        </div>
        <div style={S.row}>
          <span style={S.kbd}>/</span>
          <span style={S.desc}>Focus the search bar</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>Ctrl+K</span>
          <span style={S.desc}>Focus the search bar</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>Enter</span>
          <span style={S.desc}>Apply the filter</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>Esc</span>
          <span style={S.desc}>Cancel input</span>
        </div>
      </Section>

      <Section title="Quick search prefixes" defaultOpen>
        <div style={{ ...S.desc, marginBottom: 8 }}>
          Type a prefix directly in the search bar to target a specific field.
        </div>
        {PREFIXES.map(p => (
          <Row key={p.prefix} badge={p.prefix} badgeColor={p.color} badgeBg={p.bg} badgeBorder={p.border}>
            {p.desc}
          </Row>
        ))}
      </Section>

      <Section title="Column filters" defaultOpen>
        <div style={{ ...S.desc, marginBottom: 8 }}>
          Hover a column header, then click the filter icon (⊟) to open the popover.
          The blue dot indicates an active filter on that column.
        </div>
        <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
          letterSpacing: '0.06em', marginBottom: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          Filterable columns
        </div>
        <div style={{ ...S.desc, marginBottom: 8, lineHeight: 1.7 }}>
          <span style={{ color: 'var(--fl-dim)' }}>Description</span> ·{' '}
          <span style={{ color: 'var(--fl-purple)' }}>Host</span> ·{' '}
          <span style={{ color: 'var(--fl-pink)' }}>User</span> ·{' '}
          <span style={{ color: 'var(--fl-accent)' }}>Tool</span> ·{' '}
          <span style={{ color: 'var(--fl-dim)' }}>Ext</span>
        </div>
        <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
          letterSpacing: '0.06em', marginBottom: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          Available operators
        </div>
        {OPS.map(o => (
          <Row key={o.op} badge={o.op} badgeColor={o.color} badgeBg={o.bg} badgeBorder={o.border}>
            {o.desc}
          </Row>
        ))}
      </Section>

      <Section title="Keyboard shortcuts">
        <div style={S.row}>
          <span style={S.kbd}>E</span>
          <span style={S.desc}>Open / close this panel</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>←&nbsp;→</span>
          <span style={S.desc}>Previous / next page</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>Shift+clic</span>
          <span style={S.desc}>Multi-column sorting (up to 3 columns)</span>
        </div>
        <div style={S.row}>
          <span style={S.kbd}>Ctrl+C</span>
          <span style={S.desc}>Copy the selected row</span>
        </div>
      </Section>

    </div>
  );
}
