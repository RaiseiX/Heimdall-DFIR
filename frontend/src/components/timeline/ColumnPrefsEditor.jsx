import React, { useState, useRef } from 'react';
import { Star, Check, X, GripVertical, RotateCcw, Save, Globe, Briefcase } from 'lucide-react';

function ColumnPrefsEditor({
  open,
  onClose,
  caseId,
  artifactType = null,
  availableColumns = [],
  currentPrefs = { pinned: [], visible: [], hidden: [], order: [], widths: {} },
  onSave,
}) {
  const [localPrefs, setLocalPrefs] = useState(currentPrefs);
  const [draggedItem, setDraggedItem] = useState(null);
  const [dragSource, setDragSource] = useState(null);
  const containerRef = useRef(null);

  const pinned = localPrefs.pinned || [];
  const visible = localPrefs.visible || [];
  const hidden = localPrefs.hidden || [];

  const allItems = availableColumns || [];

  const handleDragStart = (e, column, sourceZone) => {
    setDraggedItem(column);
    setDragSource(sourceZone);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = (e, targetZone) => {
    e.preventDefault();
    if (!draggedItem || !dragSource) return;

    const newPrefs = { ...localPrefs };

    if (dragSource === 'pinned') {
      newPrefs.pinned = newPrefs.pinned.filter((c) => c.key !== draggedItem.key);
    } else if (dragSource === 'visible') {
      newPrefs.visible = newPrefs.visible.filter((c) => c.key !== draggedItem.key);
    } else if (dragSource === 'hidden') {
      newPrefs.hidden = newPrefs.hidden.filter((c) => c.key !== draggedItem.key);
    }

    if (targetZone === 'pinned') {
      newPrefs.pinned = [...newPrefs.pinned, draggedItem];
    } else if (targetZone === 'visible') {
      newPrefs.visible = [...newPrefs.visible, draggedItem];
    } else if (targetZone === 'hidden') {
      newPrefs.hidden = [...newPrefs.hidden, draggedItem];
    }

    setLocalPrefs(newPrefs);
    setDraggedItem(null);
    setDragSource(null);
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
    setDragSource(null);
  };

  const handleReset = () => {
    setLocalPrefs({
      pinned: [],
      visible: availableColumns || [],
      hidden: [],
      order: [],
      widths: {},
    });
  };

  const handleSave = (scope) => {
    if (onSave) {
      onSave(localPrefs, scope);
    }
    onClose();
  };

  const renderColumnItem = (column, zone) => (
    <div
      key={column.key}
      draggable
      onDragStart={(e) => handleDragStart(e, column, zone)}
      onDragEnd={handleDragEnd}
      className="flex items-center gap-2 px-3 py-2 bg-[#161b22] border border-[#30363d] rounded cursor-move hover:border-[#4d82c0] transition-colors"
    >
      <GripVertical size={16} className="text-[#8b949e]" />
      <span className="flex-1 text-sm text-[#c9d1d9]">{column.label}</span>
      <span className="text-xs text-[#8b949e]">{column.key}</span>
    </div>
  );

  const renderZone = (title, icon, items, zoneKey, color) => (
    <div className="flex-1 flex flex-col">
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <h3 className="text-xs font-semibold text-[#c9d1d9] uppercase tracking-wide">{title}</h3>
      </div>
      <div
        onDragOver={handleDragOver}
        onDrop={(e) => handleDrop(e, zoneKey)}
        className="flex-1 p-3 bg-[#0d1117] border-2 border-dashed border-[#30363d] rounded min-h-[200px] flex flex-col gap-2 transition-colors hover:border-[#4d82c0]"
      >
        {items.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[#8b949e] text-xs">
            Glissez colonnes ici
          </div>
        ) : (
          items.map((col) => renderColumnItem(col, zoneKey))
        )}
      </div>
    </div>
  );

  if (!open) return null;

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 z-50 bg-black/50"
      onClick={onClose}
    >
      
      <div
        className="fixed right-0 top-0 h-full w-[460px] bg-[#0d1117] border-l border-[#30363d] shadow-lg flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        
        <div className="px-6 py-4 border-b border-[#30363d]">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-bold text-[#c9d1d9]">Personnaliser colonnes</h2>
            <button
              onClick={onClose}
              className="p-1 hover:bg-[#161b22] rounded text-[#8b949e] transition-colors"
            >
              <X size={20} />
            </button>
          </div>
          {artifactType && (
            <div className="text-xs text-[#8b949e]">
              Profil: <span className="text-[#4d82c0] font-medium">{artifactType}</span>
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4">
          <div className="space-y-4">
            
            {renderZone(
              '★ Always',
              <Star size={16} className="text-yellow-500" fill="currentColor" />,
              pinned,
              'pinned',
              'yellow'
            )}

            {renderZone(
              '✓ Visible',
              <Check size={16} className="text-green-500" />,
              visible,
              'visible',
              'green'
            )}

            {renderZone(
              '✗ Never',
              <X size={16} className="text-red-500" />,
              hidden,
              'hidden',
              'red'
            )}
          </div>
        </div>

        <div className="px-6 py-4 border-t border-[#30363d] space-y-2">
          <div className="flex gap-2">
            <button
              onClick={() => handleSave('case')}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-[#238636] hover:bg-[#2ea043] text-white text-sm font-medium rounded transition-colors"
            >
              <Briefcase size={16} />
              Cas
            </button>
            <button
              onClick={() => handleSave('global')}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-[#4d82c0] hover:bg-[#5a96f1] text-white text-sm font-medium rounded transition-colors"
            >
              <Globe size={16} />
              Global
            </button>
          </div>
          <button
            onClick={handleReset}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] text-[#c9d1d9] text-sm font-medium rounded transition-colors"
          >
            <RotateCcw size={16} />
            Réinitialiser
          </button>
        </div>
      </div>
    </div>
  );
}

export default ColumnPrefsEditor;
