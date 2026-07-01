import { useEffect } from 'react';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

const SIZES = {
  sm:  480,
  md:  640,
  lg:  800,
  xl: 1000,
};

function Modal({ open, title, onClose, size = 'md', accentColor, children }) {
  const { t } = useTranslation();

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;

  const maxWidth = typeof size === 'number' ? size : (SIZES[size] ?? SIZES.md);

  return (
    <div
      className="fl-modal-overlay"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="fl-modal"
        style={{
          maxWidth,
          ...(accentColor ? { borderColor: `color-mix(in srgb, ${accentColor} 25%, transparent)`, boxShadow: `0 20px 60px rgba(0,0,0,0.4), 0 0 40px color-mix(in srgb, ${accentColor} 8%, transparent)` } : {}),
        }}
      >
        <div className="fl-modal-header" style={accentColor ? { color: accentColor } : {}}>
          {title}
          <button
            className="fl-btn fl-btn-ghost"
            style={{ padding: '2px 6px', marginLeft: 'auto', color: 'var(--fl-dim)' }}
            onClick={onClose}
            title={t('common.close')}
          >
            <X size={16} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

Modal.Body = function ModalBody({ children, style }) {
  return <div className="fl-modal-body" style={style}>{children}</div>;
};

Modal.Footer = function ModalFooter({ children }) {
  return <div className="fl-modal-footer">{children}</div>;
};

export default Modal;
