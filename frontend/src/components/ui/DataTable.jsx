import { useMemo, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Link } from 'react-router-dom';

const ROW_HEIGHT = { compact: 25, standard: 33, comfortable: 41 };
const VIRTUALIZE_ROW_THRESHOLD = 100;

export function constantColumns(rows, columns) {
  if (!Array.isArray(rows) || rows.length <= 1) return [];
  if (!Array.isArray(columns) || columns.length === 0) return [];

  const normalize = (value) => (value === undefined || value === null ? null : value);

  const constants = [];
  for (const col of columns) {
    if (!col || col.key == null) continue;
    const key = col.key;
    const first = normalize(rows[0]?.[key]);
    let same = true;
    for (let i = 1; i < rows.length; i++) {
      if (normalize(rows[i]?.[key]) !== first) {
        same = false;
        break;
      }
    }
    if (same) constants.push(key);
  }
  return constants;
}

function defaultRowKey(row, index) {
  return row?.id ?? row?.key ?? index;
}

function DataTableCell({ col, row }) {
  const raw = row ? row[col.key] : undefined;
  const content = col.render
    ? col.render(row)
    : (raw === null || raw === undefined || raw === '' ? '—' : raw);
  const cls = col.mono ? 'dt-cell dt-cell--mono' : 'dt-cell';
  return (
    <div className={cls} data-align={col.align || 'left'} role="cell">
      {content}
    </div>
  );
}

function DataTableRowInner({ row, columns, gridStyle, href }) {
  const cells = columns.map(col => <DataTableCell key={col.key} col={col} row={row} />);
  if (href) {
    return (
      <div className="dt-grid dt-row dt-row--link" style={gridStyle} role="row">
        <Link to={href} className="dt-row-link">{cells}</Link>
      </div>
    );
  }
  return (
    <div className="dt-grid dt-row" style={gridStyle} role="row">
      {cells}
    </div>
  );
}

function DataTableBody({ rows, columns, rowKey, gridStyle, rowHref }) {
  return (
    <div className="dt-body">
      {rows.map((row, index) => (
        <DataTableRowInner
          key={rowKey(row, index)}
          row={row}
          columns={columns}
          gridStyle={gridStyle}
          href={rowHref ? rowHref(row) : null}
        />
      ))}
    </div>
  );
}

function DataTableVirtualBody({ virtualizer, rows, columns, rowKey, gridStyle, rowHref }) {
  const spacerStyle = { height: virtualizer.getTotalSize() };
  const items = virtualizer.getVirtualItems();
  return (
    <div className="dt-vbody" style={spacerStyle}>
      {items.map(item => {
        const row = rows[item.index];
        const posStyle = { position: 'absolute', top: item.start, left: 0, width: '100%' };
        return (
          <div key={rowKey(row, item.index)} className="dt-vrow" style={posStyle}>
            <DataTableRowInner
              row={row}
              columns={columns}
              gridStyle={gridStyle}
              href={rowHref ? rowHref(row) : null}
            />
          </div>
        );
      })}
    </div>
  );
}

export default function DataTable({
  columns,
  rows,
  rowKey = defaultRowKey,
  density = 'compact',
  virtualize,
  emptyState = null,
  className,
  rowHref,
}) {
  const scrollRef = useRef(null);
  const safeColumns = columns ?? [];
  const safeRows = rows ?? [];

  const gridTemplateColumns = useMemo(
    () => safeColumns.map(col => (col.width ? `${col.width}px` : 'minmax(0, 1fr)')).join(' '),
    [safeColumns],
  );
  const gridStyle = useMemo(() => ({ gridTemplateColumns }), [gridTemplateColumns]);

  const shouldVirtualize = virtualize ?? (safeRows.length > VIRTUALIZE_ROW_THRESHOLD);
  const rowHeight = ROW_HEIGHT[density] ?? ROW_HEIGHT.compact;

  const virtualizer = useVirtualizer({
    count: shouldVirtualize ? safeRows.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });

  const rootClass = ['dt-root', `dt-density-${density}`, className].filter(Boolean).join(' ');

  return (
    <div className={rootClass} role="table" aria-rowcount={safeRows.length + 1}>
      <div ref={scrollRef} className="dt-scroll">
        <div className="dt-grid dt-header-row" style={gridStyle} role="row">
          {safeColumns.map(col => (
            <div key={col.key} className="dt-header-cell" data-align={col.align || 'left'} role="columnheader">
              {col.header}
            </div>
          ))}
        </div>

        {safeRows.length === 0 ? (
          emptyState
        ) : shouldVirtualize ? (
          <DataTableVirtualBody
            virtualizer={virtualizer}
            rows={safeRows}
            columns={safeColumns}
            rowKey={rowKey}
            gridStyle={gridStyle}
            rowHref={rowHref}
          />
        ) : (
          <DataTableBody rows={safeRows} columns={safeColumns} rowKey={rowKey} gridStyle={gridStyle} rowHref={rowHref} />
        )}
      </div>
    </div>
  );
}
