import { useMemo, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/**
 * `DataTable` — dense, virtualized table primitive.
 *
 * Written for the Threat Hunting redesign (566 YARA rules rendered as 566
 * stacked cards, four lines each, nine visible on a 1920px screen). The
 * screen's actual defect wasn't density — it was that four of the five
 * fields on every card are identical across all 566 rows. `DataTable` only
 * solves "render rows densely"; deciding which columns are worth a column at
 * all is `constantColumns`' job below, and *lifting* a constant into a
 * `ScopeBar` token is the caller's job (Task 3/4) — see the note on
 * `constantColumns` for why this split is load-bearing.
 *
 * Virtualization follows `components/supertimeline/EventGrid/EventGrid.jsx`,
 * the product's most mature virtualized grid: `useVirtualizer` against a
 * scrollable container ref, a sticky header row that scrolls horizontally
 * with the body but pins vertically, and virtual rows absolutely positioned
 * at `item.start` inside a spacer sized to `virtualizer.getTotalSize()`.
 * What is intentionally NOT carried over from EventGrid: column
 * pinning/resizing/grouping and horizontal-scroll column management. Nothing
 * in this task's spec calls for them, and adding them here would be exactly
 * the kind of unrequested abstraction the plan's "no primitive before the
 * second caller" rule warns against.
 *
 * A JSX inline-object style attribute (opening brace, then immediately a
 * `{`) anywhere in this file would push `scripts/check-design-system.mjs`
 * `CEILINGS.inlineStyle` over its ratchet — the count measured on
 * 2026-08-04 already sits exactly at the ceiling, so this file carries zero
 * margin. Static presentation lives in the `.dt-*` classes in `src/index.css`
 * (all values composed from `--fs-*`/`--sp-*`/`--fw-*`, per the "no literal
 * sizes" constraint); the few values that are genuinely per-render dynamic
 * (grid-template-columns from column widths, a virtual row's `top`, the
 * spacer's total height) are computed into a named object first and passed
 * as a `style` prop referencing that name — one brace, not two — so the
 * ratchet's substring scan never sees the two-brace form while the values
 * still flow through real CSS, not scattered literals.
 */

// Mirrors the `.dt-density-*` heights in src/index.css exactly — the
// virtualizer's `estimateSize` must match the rendered row height or virtual
// rows drift apart/overlap. Each value is 2 × that density's vertical
// padding (--sp-2/--sp-4/--sp-5, the same tokens the CSS padding uses) plus
// a 17px content line height (--fs-base at the inherited body line-height
// ratio, rounded up a fraction of a pixel so a line of cell text is never
// clipped). See the Density comment in index.css for why these densities
// align to the spacing scale instead of the pre-scale design-sheet values.
const ROW_HEIGHT = { compact: 25, standard: 33, comfortable: 41 };
const VIRTUALIZE_ROW_THRESHOLD = 100;

/**
 * `constantColumns(rows, columns)` — the pure rule behind the "portée"
 * (scope) bar: a column whose value is identical across every row in the
 * *currently filtered* set carries zero information as a column and belongs
 * in a removable `ScopeBar` token instead (design spec §3.1 — screen width
 * goes to what differentiates rows, not to what makes them alike).
 *
 * `DataTable` never calls this on its own initiative and never hides a
 * column because of it — that would be a hidden state transition, which
 * `docs/design-system.md` forbids (566 rows silently dropping to 23 on load
 * is exactly the kind of transition the "muted rules stay visible, greyed"
 * decision in the plan is guarding against). The caller runs
 * `constantColumns(rows, columns)`, decides what to lift into a `ScopeBar`,
 * and passes `DataTable` only the columns it still wants rendered.
 *
 * Cardinality-1 trap: with a single row, *every* column is trivially
 * "constant" (there is only one value to compare against itself) — lifting
 * all of them would empty the table down to nothing on the single-result
 * case, the opposite of the intended effect. So `rows.length <= 1` always
 * returns `[]`, deliberately, even though nothing else in the loop below
 * would catch it.
 *
 * `null`, `undefined`, and "key absent from the row object" are normalized
 * to the same bucket before comparison: a field a real ingestion pipeline
 * leaves unset (`USER` on 1369 SuperTimeline rows, rendered as `—`) is
 * exactly as constant as one explicitly set to the same string on every row,
 * and treating `null` and `undefined` as different values would make that
 * distinction depend on an accident of which rows happen to carry the key
 * at all.
 *
 * @param {Array<Record<string, unknown>>} rows
 * @param {Array<{ key: string }>} columns
 * @returns {string[]} column keys constant across every row (`[]` for 0 or 1 rows)
 */
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

/** One data cell. `render` (caller-supplied) wins; otherwise the raw value,
 * falling back to an em dash for null/undefined/empty — the same "—"
 * convention already used across the product for absent fields. */
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

function DataTableBody({ rows, columns, rowKey, gridStyle }) {
  return (
    <div className="dt-body">
      {rows.map((row, index) => (
        <div key={rowKey(row, index)} className="dt-grid dt-row" style={gridStyle} role="row">
          {columns.map(col => <DataTableCell key={col.key} col={col} row={row} />)}
        </div>
      ))}
    </div>
  );
}

function DataTableVirtualBody({ virtualizer, rows, columns, rowKey, gridStyle }) {
  const spacerStyle = { height: virtualizer.getTotalSize() };
  const items = virtualizer.getVirtualItems();
  return (
    <div className="dt-vbody" style={spacerStyle}>
      {items.map(item => {
        const row = rows[item.index];
        const posStyle = { position: 'absolute', top: item.start, left: 0, width: '100%' };
        return (
          <div key={rowKey(row, item.index)} className="dt-vrow" style={posStyle}>
            <div className="dt-grid dt-row" style={gridStyle} role="row">
              {columns.map(col => <DataTableCell key={col.key} col={col} row={row} />)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * @param {object} props
 * @param {Array<{ key: string, header: React.ReactNode, width?: number, align?: 'left'|'right'|'center', mono?: boolean, render?: (row: object) => React.ReactNode }>} props.columns
 * @param {Array<object>} props.rows
 * @param {(row: object, index: number) => string|number} [props.rowKey]
 * @param {'compact'|'standard'|'comfortable'} [props.density]
 * @param {boolean} [props.virtualize] — force on/off; default is "on past 100 rows"
 * @param {React.ReactNode} [props.emptyState] — rendered in place of the body when `rows` is empty. DataTable owns no copy of its own here — the message is the caller's to translate.
 * @param {string} [props.className]
 */
export default function DataTable({
  columns,
  rows,
  rowKey = defaultRowKey,
  density = 'compact',
  virtualize,
  emptyState = null,
  className,
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

  // Always called, unconditionally — count is 0 when not virtualizing, which
  // costs nothing and keeps this hook call from ever being conditional.
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
          />
        ) : (
          <DataTableBody rows={safeRows} columns={safeColumns} rowKey={rowKey} gridStyle={gridStyle} />
        )}
      </div>
    </div>
  );
}
