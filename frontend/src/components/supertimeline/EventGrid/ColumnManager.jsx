// frontend/src/components/supertimeline/EventGrid/ColumnManager.jsx
import { useEffect, useRef } from 'react';

export default function ColumnManager({ allCols, hiddenCols, onToggle, onReset, onClose }) {
  const ref = useRef(null);

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) onClose();
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  const baseCols    = allCols.filter(c => !c.meta?.dynamic);
  const dynamicCols = allCols.filter(c =>  c.meta?.dynamic);

  function ColRow({ col }) {
    const visible = !hiddenCols.has(col.key);
    return (
      <label
        style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 12px', cursor: 'pointer', background: 'none' }}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-panel)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
      >
        <input
          type="checkbox"
          checked={visible}
          onChange={() => onToggle(col.key)}
          style={{ accentColor: 'var(--fl-accent)', cursor: 'pointer' }}
        />
        <span style={{ fontSize: 10, color: visible ? 'var(--fl-dim)' : 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
          {col.label}
        </span>
      </label>
    );
  }

  return (
    <div
      ref={ref}
      onMouseDown={e => e.stopPropagation()}
      style={{
        position: 'absolute', top: '100%', right: 0, zIndex: 3000, marginTop: 2,
        background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 6,
        padding: '6px 0', width: 200, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, maxHeight: '60vh', overflowY: 'auto',
      }}
    >
      <div style={{ padding: '2px 12px 6px', fontSize: 8, color: 'var(--fl-subtle)',
        textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700,
        borderBottom: '1px solid var(--fl-card)' }}>
        Columns
      </div>
      {baseCols.map(col => <ColRow key={col.key} col={col} />)}
      {dynamicCols.length > 0 && (
        <>
          <div style={{ padding: '6px 12px 3px', fontSize: 8, color: 'var(--fl-raised)',
            textTransform: 'uppercase', letterSpacing: '0.08em', borderTop: '1px solid var(--fl-card)' }}>
            CSV Fields
          </div>
          {dynamicCols.map(col => <ColRow key={col.key} col={col} />)}
        </>
      )}
      <div style={{ borderTop: '1px solid var(--fl-card)', padding: '6px 12px 2px' }}>
        <button
          onClick={onReset}
          style={{
            width: '100%', padding: '4px', borderRadius: 4, background: 'transparent',
            border: '1px solid var(--fl-raised)', color: 'var(--fl-muted)', cursor: 'pointer',
            fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-dim)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
        >
          Reset to default
        </button>
      </div>
    </div>
  );
}
