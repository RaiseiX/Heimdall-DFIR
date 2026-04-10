
import { createContext, useContext, useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';
import { mix } from '../../utils/colorUtils';

const ToastContext = createContext(null);

export const TOAST_VARIANTS = {
  success: { color: 'var(--fl-ok)',     Icon: CheckCircle2  },
  error:   { color: 'var(--fl-danger)', Icon: XCircle       },
  warn:    { color: 'var(--fl-warn)',   Icon: AlertTriangle },
  info:    { color: 'var(--fl-accent)', Icon: Info          },
};

const DEFAULT_DURATION = 4000;
const MAX_TOASTS       = 5;

function ToastItem({ id, variant, message, duration, onRemove }) {
  const { color, Icon } = TOAST_VARIANTS[variant] ?? TOAST_VARIANTS.info;
  const [visible, setVisible]     = useState(false);
  const autoTimerRef              = useRef(null);
  const dismissTimerRef           = useRef(null);

  const dismissRef = useRef(null);
  dismissRef.current = useCallback(() => {
    setVisible(false);
    dismissTimerRef.current = setTimeout(() => onRemove(id), 250);
  }, [id, onRemove]);

  const dismiss = useCallback(() => dismissRef.current(), []);

  useEffect(() => {

    const rafId = requestAnimationFrame(() => setVisible(true));
    autoTimerRef.current = setTimeout(dismiss, duration);
    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(autoTimerRef.current);
      clearTimeout(dismissTimerRef.current);
    };
  }, []);

  return (
    <div
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        padding: '10px 14px',
        background: 'var(--fl-card)',
        border: `1px solid ${mix.strong(color)}`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 6,
        boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
        minWidth: 260,
        maxWidth: 380,
        transition: 'opacity 0.2s, transform 0.2s',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(8px)',
        pointerEvents: 'auto',
      }}
    >
      <Icon size={15} style={{ color, flexShrink: 0, marginTop: 1 }} />
      <span style={{ flex: 1, fontSize: '0.8125rem', color: 'var(--fl-text)', lineHeight: 1.4 }}>
        {message}
      </span>
      <button
        onClick={dismiss}
        aria-label="Fermer la notification"
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--fl-muted)', padding: 0,
          display: 'flex', alignItems: 'center', flexShrink: 0,
        }}
      >
        <X size={13} />
      </button>
    </div>
  );
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const remove = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const add = useCallback((variant, message, duration = DEFAULT_DURATION) => {
    const id = crypto.randomUUID();
    setToasts(prev => {
      const next = [...prev, { id, variant, message, duration }];
      return next.length > MAX_TOASTS ? next.slice(next.length - MAX_TOASTS) : next;
    });
  }, []);

  const toast = useMemo(() => ({
    success: (msg, duration) => add('success', msg, duration),
    error:   (msg, duration) => add('error',   msg, duration),
    warn:    (msg, duration) => add('warn',    msg, duration),
    info:    (msg, duration) => add('info',    msg, duration),
  }), [add]);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div
        aria-live="polite"
        style={{
          position: 'fixed', bottom: 24, right: 24,
          display: 'flex', flexDirection: 'column', gap: 8,
          zIndex: 9999, pointerEvents: 'none',
        }}
      >
        {toasts.map(t => (
          <ToastItem key={t.id} {...t} onRemove={remove} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
