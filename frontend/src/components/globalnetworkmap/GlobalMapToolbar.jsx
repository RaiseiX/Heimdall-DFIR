// frontend/src/components/globalnetworkmap/GlobalMapToolbar.jsx
import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

export const EVIDENCE_COLORS = [
  'var(--fl-accent)','var(--fl-purple)','var(--fl-gold)','var(--fl-danger)',
  '#3da34d','#c0784d','#4dc0b5','#c04d8b',
];

const NODE_TYPES = ['internal', 'external', 'domain', 'url', 'suspicious'];

const btnStyle = {
  background: 'rgba(10,15,26,0.9)',
  border: '1px solid #1e293b',
  borderRadius: 4,
  padding: '3px 10px',
  fontSize: 11,
  color: '#8899aa',
  cursor: 'pointer',
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
};

const dropdownStyle = {
  position: 'absolute',
  top: 'calc(100% + 4px)',
  right: 0,
  background: '#0a0f1a',
  border: '1px solid #1e293b',
  borderRadius: 4,
  padding: '6px 0',
  minWidth: 170,
  zIndex: 30,
};

const rowStyle = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  padding: '4px 12px',
  fontSize: 11,
  color: '#8899aa',
  cursor: 'pointer',
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  userSelect: 'none',
};

function useClickOutside(ref, onClose) {
  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [ref, onClose]);
}

export default function GlobalMapToolbar({
  evidenceSources,
  activeTypes,
  activeEvidenceIds,
  onTypeToggle,
  onEvidenceToggle,
  search,
  onSearch,
}) {
  const { t } = useTranslation();
  const [typeOpen,     setTypeOpen]     = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const typeRef     = useRef(null);
  const evidenceRef = useRef(null);

  useClickOutside(typeRef,     () => setTypeOpen(false));
  useClickOutside(evidenceRef, () => setEvidenceOpen(false));
  const nodeTypeLabel = type => t(`networkMap.node_type_${type}`);

  return (
    <div style={{
      position: 'absolute', top: 12, right: 12,
      display: 'flex', gap: 6, zIndex: 10, alignItems: 'center',
    }}>
      {/* Node type filter */}
      <div ref={typeRef} style={{ position: 'relative' }}>
        <button style={btnStyle} onClick={() => setTypeOpen(o => !o)}>
          {t('networkMap.type_filter')} ▾
        </button>
        {typeOpen && (
          <div style={dropdownStyle}>
            {NODE_TYPES.map(t => (
              <label key={t} style={rowStyle}>
                <input
                  type="checkbox"
                  checked={activeTypes.has(t)}
                  onChange={() => onTypeToggle(t)}
                  style={{ accentColor: 'var(--fl-purple)', cursor: 'pointer' }}
                />
                {nodeTypeLabel(t)}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Evidence filter (only shown when there are multiple evidences) */}
      {evidenceSources.length > 1 && (
        <div ref={evidenceRef} style={{ position: 'relative' }}>
          <button style={btnStyle} onClick={() => setEvidenceOpen(o => !o)}>
            {t('networkMap.evidence_filter')} ▾
          </button>
          {evidenceOpen && (
            <div style={dropdownStyle}>
              {evidenceSources.map((ev, i) => {
                const color = EVIDENCE_COLORS[i % EVIDENCE_COLORS.length];
                return (
                  <label key={ev.id} style={rowStyle}>
                    <input
                      type="checkbox"
                      checked={activeEvidenceIds.has(ev.id)}
                      onChange={() => onEvidenceToggle(ev.id)}
                      style={{ accentColor: color, cursor: 'pointer' }}
                    />
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: color, display: 'inline-block', flexShrink: 0,
                    }} />
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 110 }}>
                      {ev.name}
                    </span>
                  </label>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Search */}
      <input
        type="text"
        value={search}
        onChange={e => onSearch(e.target.value)}
        placeholder={t('networkMap.search_node_ph')}
        style={{
          background: 'rgba(10,15,26,0.9)',
          border: '1px solid #1e293b',
          borderRadius: 4,
          padding: '3px 8px',
          fontSize: 11,
          color: '#8899aa',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          outline: 'none',
          width: 130,
        }}
      />
    </div>
  );
}
