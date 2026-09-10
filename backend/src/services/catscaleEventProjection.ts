// Decides, row by row, whether a catscale_state object enters the SuperTimeline
// as a dated event or as undated inventory.
//
// The original projection wrote `NULL::timestamptz, 'inventory'` for all 1,744,828
// rows, and the reasoning was right for what it covered: lsof entries, memory
// mappings, installed packages and executable hashes have no date of their own,
// and stamping them with the collection time would render a fabricated burst of
// simultaneous activity at 2026-07-30 14:44.
//
// It was wrong for the artifacts that carry a time. `dmesg -T` writes one on every
// line — 2,110 of them on the reference host, spanning 07:22:07 to 13:56:57, all
// landing in that NULL and therefore invisible in a chronological view.
//
// So the choice moves from the projection to the row. A row that parsed a real
// event time keeps it and names where it came from; a row that has none stays
// exactly as before. NULL remains load-bearing rather than a placeholder.
export function eventTimeSql(alias: string): string {
  return [
    `${alias}.event_time`,
    `CASE WHEN ${alias}.event_time IS NULL THEN 'inventory'`,
    `     ELSE left(COALESCE(${alias}.event_time_kind, 'inventory'), 50) END`,
  ].join('\n');
}
