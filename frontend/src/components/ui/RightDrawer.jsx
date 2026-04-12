import { X } from 'lucide-react';

export default function RightDrawer({ open, onClose, title, children, width = 440 }) {
  return (
    <>
      
      <div
        aria-hidden="true"
        style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.25)',
          zIndex: 490,
          opacity: open ? 1 : 0,
          pointerEvents: 'none',
          transition: 'opacity 0.2s ease',
        }}
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-label={title || 'Détails'}
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          height: '100vh',
          width: `min(${width}px, 92vw)`,
          background: 'var(--fl-panel, #161b22)',
          borderLeft: '1px solid var(--fl-border, var(--fl-border))',
          boxShadow: '-8px 0 32px rgba(0,0,0,0.5)',
          zIndex: 500,
          transform: open ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.25s ease',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 14px',
          borderBottom: '1px solid var(--fl-border, var(--fl-border))',
          flexShrink: 0,
          background: 'var(--fl-surface, #0d1117)',
        }}>
          <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: 'var(--fl-text, #e6edf3)', letterSpacing: '0.04em' }}>
            {title || 'Détails'}
          </span>
          <button
            onClick={onClose}
            aria-label="Fermer"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--fl-muted, #7d8590)', display: 'flex', alignItems: 'center',
              padding: 4, borderRadius: 4,
            }}
          >
            <X size={14} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>
          {children}
        </div>
      </div>
    </>
  );
}
