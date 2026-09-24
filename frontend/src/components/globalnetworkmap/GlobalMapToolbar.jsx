import { useState, useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export const EVIDENCE_COLORS = [
  'var(--fl-accent)','var(--fl-purple)','var(--fl-gold)','var(--fl-danger)',
  '#3da34d','#c0784d','#4dc0b5','#c04d8b',
];

const NODE_TYPES = ['internal', 'external', 'collection', 'domain', 'url', 'suspicious'];

const btnStyle = {
  background: 'none',
  border: 0,
  padding: '3px 4px',
  fontSize: 11,
  color: 'var(--fl-muted)',
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

const inputStyle = {
  width: '100%', background: 'var(--fl-card)', border: '1px solid var(--fl-raised)',
  borderRadius: 3, color: 'var(--fl-dim)', fontSize: 11,
  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
  padding: '3px 5px', outline: 'none', boxSizing: 'border-box',
};

export default function GlobalMapToolbar({
  evidenceSources,
  activeTypes,
  activeEvidenceIds,
  onTypeToggle,
  onEvidenceToggle,
  search,
  onSearch,
  subnetRules = [],
  onSubnetRuleAdd,
  onSubnetRuleDelete,
}) {
  const { t } = useTranslation();
  const [typeOpen,     setTypeOpen]     = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [subnetOpen,   setSubnetOpen]   = useState(false);
  const typeRef     = useRef(null);
  const evidenceRef = useRef(null);
  const subnetRef   = useRef(null);

  const [rCidr,  setRCidr]  = useState('');
  const [rLabel, setRLabel] = useState('');
  const [rColor, setRColor] = useState('#8b7fff');

  useClickOutside(typeRef,     () => setTypeOpen(false));
  useClickOutside(evidenceRef, () => setEvidenceOpen(false));
  useClickOutside(subnetRef,   () => setSubnetOpen(false));
  const nodeTypeLabel = type => t(`networkMap.node_type_${type}`);

  const ruleReady = rCidr.trim() && rLabel.trim();
  function handleAddRule() {
    if (!ruleReady) return;
    onSubnetRuleAdd?.({ id: `sr-${Date.now()}`, cidr: rCidr.trim(), label: rLabel.trim(), color: rColor });
    setRCidr(''); setRLabel(''); setRColor('#8b7fff');
  }

  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
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

      {onSubnetRuleAdd && (
        <div ref={subnetRef} style={{ position: 'relative' }}>
          <button style={btnStyle} onClick={() => setSubnetOpen(o => !o)}>
            {t('networkMap.subnet.title')}{subnetRules.length > 0 ? ` ${subnetRules.length}` : ''} ▾
          </button>
          {subnetOpen && (
            <div style={{ ...dropdownStyle, minWidth: 250, padding: '9px 12px' }}>
              <div style={{ fontSize: 11, color: 'var(--fl-muted)', lineHeight: 1.5, marginBottom: 7 }}>
                {t('networkMap.subnet.hint')}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <input type="text" value={rCidr} onChange={e => setRCidr(e.target.value)}
                  placeholder={t('networkMap.subnet.cidr_ph')} style={inputStyle} />
                <input type="text" value={rLabel} onChange={e => setRLabel(e.target.value)}
                  placeholder={t('networkMap.subnet.label_ph')} style={inputStyle} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <label style={{ position: 'relative', cursor: 'pointer', flexShrink: 0 }}>
                    <div style={{ width: 16, height: 16, borderRadius: 3, background: rColor, border: '1px solid var(--fl-border3)' }} />
                    <input type="color" value={rColor} onChange={e => setRColor(e.target.value)}
                      style={{ position: 'absolute', opacity: 0, width: 0, height: 0, top: 0, left: 0 }} />
                  </label>
                  <button
                    onClick={handleAddRule}
                    disabled={!ruleReady}
                    style={{
                      ...btnStyle, flex: 1, textAlign: 'left',
                      color: ruleReady ? 'var(--fl-accent)' : 'var(--fl-subtle)',
                      cursor: ruleReady ? 'pointer' : 'default',
                      borderBottom: `1px solid ${ruleReady ? 'var(--fl-accent)' : 'transparent'}`,
                    }}
                  >{t('networkMap.subnet.add')}</button>
                </div>
              </div>

              {subnetRules.length > 0 ? (
                <div style={{ marginTop: 8, paddingTop: 7, borderTop: '1px solid var(--fl-border2)', display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {subnetRules.map(rule => (
                    <div key={rule.id} style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 2, background: rule.color, flexShrink: 0, alignSelf: 'center' }} />
                      <span style={{ flex: 1, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {rule.label}
                        <span style={{ color: 'var(--fl-muted)', fontSize: 9, marginLeft: 6 }}>{rule.cidr}</span>
                      </span>
                      <button
                        onClick={() => onSubnetRuleDelete?.(rule.id)}
                        style={{ ...btnStyle, flexShrink: 0, padding: '0 2px' }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                      ><X size={11} /></button>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {t('networkMap.subnet.empty')}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <input
        type="text"
        value={search}
        onChange={e => onSearch(e.target.value)}
        placeholder={t('networkMap.search_node_ph')}
        style={{
          background: 'none',
          border: 0,
          borderBottom: '1px solid var(--fl-border2)',
          padding: '3px 2px',
          fontSize: 11,
          color: 'var(--fl-dim)',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          outline: 'none',
          width: 130,
        }}
      />
    </div>
  );
}
