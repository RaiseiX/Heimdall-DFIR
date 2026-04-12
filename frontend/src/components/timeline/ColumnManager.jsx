
import { useState, useEffect, useCallback } from 'react';
import { X, GripVertical, Eye, EyeOff, RotateCcw, Columns } from 'lucide-react';

const PRESETS = {
  minimal: {
    visible: ['timestamp', 'description'],
    widths: {},
  },
  standard: {
    visible: ['timestamp', 'artifact_type', 'timestamp_column', 'description', 'source'],
    widths: {},
  },
  full: {
    visible: null,
    widths: {},
  },
};

export default function ColumnManager({
  open,
  onClose,
  caseId,
  columns = [],
  hiddenCols = new Set(),
  colWidths = new Map(),
  colOrder = [],
  onHiddenChange = () => {},
  onWidthChange = () => {},
  onOrderChange = () => {},
}) {

  const [draggingFromIdx, setDraggingFromIdx] = useState(null);
  const [dragOverIdx, setDragOverIdx] = useState(null);
  const [localHidden, setLocalHidden] = useState(new Set(hiddenCols));
  const [localWidths, setLocalWidths] = useState(new Map(colWidths));
  const [localOrder, setLocalOrder] = useState([...colOrder]);

  useEffect(() => {
    setLocalHidden(new Set(hiddenCols));
  }, [hiddenCols]);

  useEffect(() => {
    setLocalWidths(new Map(colWidths));
  }, [colWidths]);

  useEffect(() => {
    setLocalOrder([...colOrder]);
  }, [colOrder]);

  const orderedKeys = localOrder.length > 0 ? localOrder : columns.map(c => c.key);

  const visibleCount = orderedKeys.filter(k => !localHidden.has(k)).length;

  const storageKey = `heimdall_col_prefs_${caseId}`;

  const loadPrefs = useCallback(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || '{}');
      if (saved.hidden && Array.isArray(saved.hidden)) {
        setLocalHidden(new Set(saved.hidden));
      }
      if (saved.widths && typeof saved.widths === 'object') {
        setLocalWidths(new Map(Object.entries(saved.widths)));
      }
      if (saved.order && Array.isArray(saved.order)) {
        setLocalOrder(saved.order);
      }
    } catch {}
  }, [storageKey]);

  const savePrefs = useCallback(() => {
    try {
      const data = {
        hidden: Array.from(localHidden),
        widths: Object.fromEntries(localWidths),
        order: localOrder,
      };
      localStorage.setItem(storageKey, JSON.stringify(data));
    } catch {}
  }, [storageKey, localHidden, localWidths, localOrder]);

  useEffect(() => {
    savePrefs();
    onHiddenChange(localHidden);
    onWidthChange(localWidths);
    onOrderChange(localOrder);
  }, [localHidden, localWidths, localOrder, savePrefs, onHiddenChange, onWidthChange, onOrderChange]);

  function toggleColumnVis(key) {
    setLocalHidden(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  function handleWidthChange(key, value) {
    const num = parseInt(value, 10);
    if (!isNaN(num) && num > 0) {
      setLocalWidths(prev => {
        const next = new Map(prev);
        next.set(key, num);
        return next;
      });
    }
  }

  function handleGripMouseDown(idx) {
    setDraggingFromIdx(idx);
  }

  function handleRowMouseEnter(idx) {
    if (draggingFromIdx !== null && draggingFromIdx !== idx) {
      setDragOverIdx(idx);
    }
  }

  function handleRowMouseLeave() {
    setDragOverIdx(null);
  }

  function handleMouseUp() {
    if (draggingFromIdx !== null && dragOverIdx !== null) {

      const newOrder = [...localOrder];
      [newOrder[draggingFromIdx], newOrder[dragOverIdx]] = [newOrder[dragOverIdx], newOrder[draggingFromIdx]];
      setLocalOrder(newOrder);
    }
    setDraggingFromIdx(null);
    setDragOverIdx(null);
  }

  function applyPreset(presetName) {
    const preset = PRESETS[presetName];
    if (!preset) return;

    if (preset.visible === null) {

      setLocalHidden(new Set());
    } else {

      const allKeys = new Set(orderedKeys);
      const hidden = new Set([...allKeys].filter(k => !preset.visible.includes(k)));
      setLocalHidden(hidden);
    }

    setLocalWidths(new Map(Object.entries(preset.widths || {})));
  }

  function handleReset() {
    setLocalHidden(new Set());
    setLocalWidths(new Map());
    setLocalOrder([...columns.map(c => c.key)]);
  }

  if (!open) return null;

  return (
    <div
      onMouseUp={handleMouseUp}
      style={{
        position: 'fixed',
        left: 0,
        top: 0,
        width: 460,
        height: '100vh',
        background: 'var(--fl-bg)',
        borderRight: '1px solid var(--fl-border)',
        zIndex: 10000,
        display: 'flex',
        flexDirection: 'column',
        fontFamily: 'monospace',
        color: 'var(--fl-text)',
      }}
    >
      
      <div
        style={{
          padding: '12px 14px',
          borderBottom: '1px solid var(--fl-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Columns size={14} style={{ color: 'var(--fl-accent)' }} />
          <span
            style={{
              fontSize: 12,
              fontWeight: 700,
              color: '#8aa0bc',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}
          >
            Colonnes
          </span>
          <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>
            ({visibleCount} visibles)
          </span>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--fl-dim)',
            padding: 0,
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <X size={14} />
        </button>
      </div>

      <div
        style={{
          padding: '8px 14px',
          borderBottom: '1px solid var(--fl-border)',
          display: 'flex',
          gap: 4,
        }}
      >
        <button
          onClick={() => applyPreset('minimal')}
          style={{
            flex: 1,
            padding: '4px 10px',
            borderRadius: 4,
            fontSize: 10,
            fontFamily: 'monospace',
            background: 'var(--fl-panel)',
            border: '1px solid var(--fl-border)',
            color: 'var(--fl-dim)',
            cursor: 'pointer',
          }}
        >
          Minimal
        </button>
        <button
          onClick={() => applyPreset('standard')}
          style={{
            flex: 1,
            padding: '4px 10px',
            borderRadius: 4,
            fontSize: 10,
            fontFamily: 'monospace',
            background: 'var(--fl-panel)',
            border: '1px solid var(--fl-border)',
            color: 'var(--fl-dim)',
            cursor: 'pointer',
          }}
        >
          Standard
        </button>
        <button
          onClick={() => applyPreset('full')}
          style={{
            flex: 1,
            padding: '4px 10px',
            borderRadius: 4,
            fontSize: 10,
            fontFamily: 'monospace',
            background: 'var(--fl-panel)',
            border: '1px solid var(--fl-border)',
            color: 'var(--fl-dim)',
            cursor: 'pointer',
          }}
        >
          Complet
        </button>
      </div>

      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '8px 0',
        }}
      >
        {orderedKeys.map((key, idx) => {
          const col = columns.find(c => c.key === key);
          if (!col) return null;

          const isHidden = localHidden.has(key);
          const customWidth = localWidths.get(key);
          const isFlex = col.flex === true;
          const isDragging = draggingFromIdx === idx;
          const isDragOver = dragOverIdx === idx;

          return (
            <div
              key={key}
              onMouseEnter={() => handleRowMouseEnter(idx)}
              onMouseLeave={handleRowMouseLeave}
              style={{
                padding: '8px 10px',
                borderTop: isDragOver ? '2px solid var(--fl-accent)' : '1px solid transparent',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: isDragging ? 'var(--fl-sep)' : 'transparent',
                cursor: isDragging ? 'grabbing' : 'default',
              }}
            >
              
              <button
                onMouseDown={() => handleGripMouseDown(idx)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'grab',
                  color: isDragging ? 'var(--fl-accent)' : 'var(--fl-subtle)',
                  padding: 0,
                  display: 'flex',
                  alignItems: 'center',
                  flexShrink: 0,
                }}
              >
                <GripVertical size={12} />
              </button>

              <button
                onClick={() => toggleColumnVis(key)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: isHidden ? 'var(--fl-subtle)' : 'var(--fl-accent)',
                  padding: 0,
                  display: 'flex',
                  alignItems: 'center',
                  flexShrink: 0,
                }}
              >
                {isHidden ? <EyeOff size={12} /> : <Eye size={12} />}
              </button>

              <span
                style={{
                  fontSize: 11,
                  flex: 1,
                  color: isHidden ? 'var(--fl-subtle)' : 'var(--fl-on-dark)',
                }}
              >
                {col.label}
              </span>

              <input
                type="number"
                value={customWidth || col.width || 100}
                onChange={e => handleWidthChange(key, e.target.value)}
                disabled={isFlex}
                placeholder="px"
                style={{
                  width: 50,
                  padding: '3px 5px',
                  borderRadius: 3,
                  border: '1px solid var(--fl-border)',
                  background: isFlex ? '#0a0f18' : 'var(--fl-panel)',
                  color: isFlex ? '#2a3a4a' : 'var(--fl-on-dark)',
                  fontSize: 10,
                  fontFamily: 'monospace',
                  cursor: isFlex ? 'not-allowed' : 'text',
                  textAlign: 'center',
                }}
              />
            </div>
          );
        })}
      </div>

      <div
        style={{
          padding: '10px 14px',
          borderTop: '1px solid var(--fl-border)',
          display: 'flex',
          gap: 6,
        }}
      >
        <button
          onClick={handleReset}
          style={{
            flex: 1,
            padding: '6px 10px',
            borderRadius: 4,
            fontSize: 11,
            fontFamily: 'monospace',
            background: 'var(--fl-panel)',
            border: '1px solid var(--fl-border)',
            color: 'var(--fl-dim)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 4,
          }}
        >
          <RotateCcw size={12} /> Réinitialiser
        </button>
        <button
          onClick={onClose}
          style={{
            flex: 1,
            padding: '6px 10px',
            borderRadius: 4,
            fontSize: 11,
            fontFamily: 'monospace',
            background: '#1a3a5a',
            border: '1px solid #2a5080',
            color: 'var(--fl-accent)',
            cursor: 'pointer',
          }}
        >
          Fermer
        </button>
      </div>
    </div>
  );
}
