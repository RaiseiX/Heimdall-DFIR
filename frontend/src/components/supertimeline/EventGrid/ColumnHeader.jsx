import { ArrowUp, ArrowDown, ArrowUpDown, Filter, Pin, PinOff } from 'lucide-react';
import { useRef, useState } from 'react';
import FilterPopover, { isColFilterActive } from './FilterPopover';
import { useTimelineStore } from '../store/useTimelineStore';

export function ColumnHeader({ col, sortState, multiSort, onSort, onPin, isPinned, pinnedOffset, onResize, onReorder, scrollLeftRef, clientSort }) {
  const serverEntry = multiSort?.find(s => s.col === col.key);
  const clientEntry = !serverEntry && clientSort?.col === col.key ? { col: col.key, dir: clientSort.dir } : null;
  const sortEntry   = serverEntry || clientEntry;
  const sortOrder   = multiSort?.length > 1 && serverEntry ? multiSort.findIndex(s => s.col === col.key) + 1 : null;
  const isSortable  = true;
  const isClientSort = !!clientEntry;
  const isResizable = true;
  const isGroupable = col.key !== '_verdict';
  const dragRef = useRef(null);

  const [showFilter, setShowFilter] = useState(false);
  const [hovered,    setHovered]    = useState(false);
  const [focused,    setFocused]    = useState(false);
  const [dropTarget, setDropTarget] = useState(false);
  const headerRef = useRef(null);
  const storeState   = useTimelineStore();
  const filterActive = isColFilterActive(col.key, storeState);

  const SortIcon = !sortEntry ? ArrowUpDown
    : sortEntry.dir === 'desc' ? ArrowDown : ArrowUp;

  function startResize(e) {
    e.preventDefault();
    e.stopPropagation();
    const startX   = e.clientX;
    const startW   = col.size ?? 120;
    dragRef.current = true;

    function onMove(ev) {
      const delta = ev.clientX - startX;
      const newW  = Math.max(40, startW + delta);
      onResize?.(col.key, newW);
    }
    function onUp() {
      dragRef.current = false;
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }

  return (
    <div
      ref={headerRef}
      tabIndex={0}
      {...(pinnedOffset != null ? { 'data-sticky-left': '' } : {})}
      draggable
      onDragStart={e => {
        e.dataTransfer.setData('columnKey', col.key);
        if (isGroupable) e.dataTransfer.setData('groupField', JSON.stringify({ key: col.key, label: col.label }));
        e.dataTransfer.effectAllowed = 'copyMove';
      }}
      onDragOver={e => {
        if (!onReorder || !e.dataTransfer.types.includes('columnKey')) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        setDropTarget(true);
      }}
      onDragLeave={() => setDropTarget(false)}
      onDrop={e => {
        setDropTarget(false);
        const from = e.dataTransfer.getData('columnKey');
        if (!from || from === col.key) return;
        e.preventDefault();
        e.stopPropagation();
        onReorder?.(from, col.key);
      }}
      onDragEnd={() => setDropTarget(false)}
      onFocus={() => setFocused(true)}
      onBlur={e => { if (!e.currentTarget.contains(e.relatedTarget)) setFocused(false); }}
      onClick={isSortable ? (e => { if (!dragRef.current) onSort(col.key, e.shiftKey); }) : undefined}
      style={{
        padding: '0 8px',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: 4,
        cursor: isSortable ? 'pointer' : isGroupable ? 'grab' : 'default',
        userSelect: 'none',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        position: 'relative',
        zIndex:     pinnedOffset != null ? 3 : undefined,
        background: pinnedOffset != null ? 'var(--fl-bg)' : undefined,
        transform:  pinnedOffset != null ? `translateX(${scrollLeftRef?.current ?? 0}px)` : undefined,
        boxShadow:  pinnedOffset != null ? '3px 0 6px rgba(0,0,0,0.25)' : undefined,
        borderRight: pinnedOffset != null ? '1px solid var(--fl-border)' : undefined,
        borderLeft: dropTarget ? '1px solid var(--fl-accent)' : undefined,
      }}
      onMouseEnter={e => {
        setHovered(true);
        if (isSortable) e.currentTarget.style.background = 'var(--fl-panel)';
      }}
      onMouseLeave={e => {
        setHovered(false);
        e.currentTarget.style.background = pinnedOffset != null ? 'var(--fl-bg)' : 'none';
      }}
    >
      {col.meta?.dynamic && (
        <span title="Artifact-specific field" style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-purple)', flexShrink: 0, display: 'inline-block' }} />
      )}
      <span style={{ fontSize: 9, color: sortEntry ? (isClientSort ? 'var(--fl-purple)' : 'var(--fl-accent)') : col.meta?.dynamic ? 'var(--fl-purple)' : 'var(--fl-muted)',
        textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700,
        overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {col.label}
      </span>
      {isSortable && (
        <SortIcon size={9} style={{ color: sortEntry ? (isClientSort ? 'var(--fl-purple)' : 'var(--fl-accent)') : 'var(--fl-subtle)', flexShrink: 0 }}
          title={isClientSort ? 'Sorted on loaded records (page only)' : undefined} />
      )}
      {sortOrder && sortOrder > 0 && (
        <span style={{ fontSize: 8, color: 'var(--fl-accent)', background: 'var(--fl-card)',
          border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', borderRadius: 2, padding: '0 3px' }}>
          {sortOrder}
        </span>
      )}
      <span
        title={isPinned ? 'Unpin column' : 'Pin column'}
        onClick={e => { e.stopPropagation(); onPin?.(col.key); }}
        style={{ fontSize: 9, color: isPinned ? 'var(--fl-accent)' : 'var(--fl-subtle)', cursor: 'pointer', flexShrink: 0, marginLeft: 2 }}
        onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; }}
        onMouseLeave={e => { e.currentTarget.style.color = isPinned ? 'var(--fl-accent)' : 'var(--fl-subtle)'; }}
      >
        {isPinned ? <PinOff size={9} strokeWidth={1.6} /> : <Pin size={9} strokeWidth={1.6} />}
      </span>
      <div
        onClick={e => e.stopPropagation()}
        style={{
          position: 'relative', flexShrink: 0, marginLeft: 'auto',
          opacity: (hovered || focused || filterActive || showFilter) ? 1 : 0,
          transition: 'opacity 90ms ease-out',
        }}
      >
          <button
            onClick={e => { e.stopPropagation(); setShowFilter(v => !v); }}
            title={`${col.label} — filtrer`}
            style={{
              background: 'none', border: 'none', cursor: 'pointer', padding: '1px 2px',
              display: 'flex', alignItems: 'center',
            }}
          >
            {filterActive
              ? <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fl-accent)', display: 'block' }} />
              : <Filter size={9} style={{ color: 'var(--fl-muted)' }} />
            }
          </button>
          {showFilter && (
            <FilterPopover col={col} onClose={() => setShowFilter(false)} anchorEl={headerRef} />
          )}
      </div>
      {isResizable && (
        <div
          onMouseDown={startResize}
          onClick={e => e.stopPropagation()}
          style={{
            position: 'absolute', right: 0, top: 0, bottom: 0,
            width: 6, cursor: 'col-resize', zIndex: 1,
          }}
          onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 25%, transparent)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
        />
      )}
    </div>
  );
}
