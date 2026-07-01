// frontend/src/components/supertimeline/EventGrid/GroupPanel.jsx
import { useState } from 'react';
import { useTimelineStore } from '../store/useTimelineStore';

export default function GroupPanel() {
  const { groupByFields, addGroupByField, removeGroupByField, setGroupByFields } = useTimelineStore();
  const [dragOver, setDragOver]       = useState(false);
  const [chipDragIdx, setChipDragIdx] = useState(null);

  function onDragOver(e) {
    e.preventDefault();
    setDragOver(true);
  }
  function onDragLeave() { setDragOver(false); }
  function onDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const raw = e.dataTransfer.getData('groupField');
    if (!raw) return;
    try {
      const field = JSON.parse(raw);
      addGroupByField(field);
    } catch { /* invalid data */ }
  }

  function onChipDragStart(e, idx) {
    e.stopPropagation();
    e.dataTransfer.setData('chipIdx', String(idx));
    setChipDragIdx(idx);
  }
  function onChipDragOver(e, idx) {
    e.preventDefault();
    e.stopPropagation();
  }
  function onChipDrop(e, targetIdx) {
    e.preventDefault();
    e.stopPropagation();
    const srcIdx = parseInt(e.dataTransfer.getData('chipIdx'), 10);
    if (isNaN(srcIdx) || srcIdx === targetIdx) return;
    const next = [...groupByFields];
    const [item] = next.splice(srcIdx, 1);
    next.splice(targetIdx, 0, item);
    setGroupByFields(next);
    setChipDragIdx(null);
  }
  function onChipDragEnd() { setChipDragIdx(null); }

  const hasGroups = groupByFields.length > 0;

  return (
    <div
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      style={{
        height: 32,
        flexShrink: 0,
        background: 'var(--fl-bg)',
        borderBottom: `1px solid ${dragOver ? 'var(--fl-accent)' : 'var(--fl-card)'}`,
        display: 'flex',
        alignItems: 'center',
        padding: '0 10px',
        gap: 5,
        transition: 'border-color 0.1s',
        outline: dragOver ? '1px dashed color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'none',
        outlineOffset: -2,
      }}
    >
      {!hasGroups && (
        <span style={{
          fontSize: 9, color: 'var(--fl-raised)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          letterSpacing: '0.06em', userSelect: 'none', pointerEvents: 'none',
        }}>
          ⊕ Drag a column header here to group
        </span>
      )}
      {hasGroups && (
        <>
          <span style={{ fontSize: 8, color: 'var(--fl-raised)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            textTransform: 'uppercase', letterSpacing: '0.08em', flexShrink: 0 }}>
            Group by:
          </span>
          {groupByFields.map((f, idx) => (
            <div
              key={f.key}
              draggable
              onDragStart={e => onChipDragStart(e, idx)}
              onDragOver={e => onChipDragOver(e, idx)}
              onDrop={e => onChipDrop(e, idx)}
              onDragEnd={onChipDragEnd}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '2px 7px 2px 8px', borderRadius: 4,
                background: chipDragIdx === idx ? '#0a1830' : 'var(--fl-card)',
                border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', color: 'var(--fl-accent)',
                fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
                cursor: 'grab', userSelect: 'none',
                opacity: chipDragIdx === idx ? 0.5 : 1,
              }}
            >
              {idx > 0 && (
                <span style={{ color: 'var(--fl-raised)', marginRight: 2, fontSize: 8 }}>›</span>
              )}
              {f.label}
              <span
                onClick={e => { e.stopPropagation(); removeGroupByField(f.key); }}
                style={{
                  opacity: 0.5, cursor: 'pointer', fontSize: 12, lineHeight: 1,
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  width: 12, height: 12, borderRadius: 2, userSelect: 'none',
                }}
                onMouseEnter={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.background = 'rgba(255,255,255,0.1)'; }}
                onMouseLeave={e => { e.currentTarget.style.opacity = '0.5'; e.currentTarget.style.background = 'none'; }}
              >
                x
              </span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}
