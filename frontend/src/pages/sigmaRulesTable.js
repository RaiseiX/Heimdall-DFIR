/**
 * Pure logic behind `SigmaRulesTab` (Threat Hunting redesign — the Sigma
 * rules inventory, second caller of `DataTable`/`ScopeBar`; see
 * `docs/superpowers/plans/2026-08-06-threat-hunting-rules-redesign.md`).
 *
 * Same split as `./yaraRulesTable.js`: row-shaping, filtering, sorting and
 * stat-row math extracted so they're testable without mounting React.
 *
 * The severity vocabulary (`SIGMA_LEVEL_RANK`/`COLOR`, `sigmaLevelRank`/
 * `Color`/`Label`, `fmtNum`) lives here rather than duplicated between this
 * tab and `SigmaHuntTab` — both need the exact same "critical is always red,
 * an absent/unrecognised level is dim and sinks to the bottom, never guessed
 * as `low`" rules. `ThreatHuntPage.jsx` imports them from here for both tabs.
 */

// ── Severity vocabulary — the four severity tokens this product already has
// (--fl-danger/--fl-warn/--fl-gold/--fl-ok), no new token introduced.
// `informational` and an unset/unrecognised level both fall through to
// `--fl-dim`: neither is "low severity", so painting either one green
// (--fl-ok, already spoken for by `low`) would overstate them.
export const SIGMA_LEVEL_RANK  = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
export const SIGMA_LEVEL_COLOR = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };

export function sigmaLevelRank(level)  { return SIGMA_LEVEL_RANK[level] ?? 0; }
export function sigmaLevelColor(level) { return SIGMA_LEVEL_COLOR[level] || 'var(--fl-dim)'; }
export function sigmaLevelLabel(level, t) {
  return t(`threat_hunt.sigma.level.${level && SIGMA_LEVEL_RANK[level] ? level : 'unknown'}`);
}

function localeFor(lang) {
  return lang?.startsWith('en') ? 'en-US' : 'fr-FR';
}

// Thousand-separated per locale ("3 999" fr / "3,999" en) — a bare
// `{{count}}` in a translation string has no locale awareness at all.
export function fmtNum(n, lang) {
  if (n === null || n === undefined) return '—';
  try { return new Intl.NumberFormat(localeFor(lang)).format(n); } catch { return String(n); }
}

// The five values `upstream_status` actually carries on the real corpus
// (stable/test/experimental/deprecated/unsupported — see the task report for
// the live counts). Used to decide whether a row's raw value has a
// translation of its own or must fall back to `upstream_status.unknown`,
// the same "never guess" rule `sigmaLevelLabel` applies to `level`.
export const SIGMA_UPSTREAM_STATUSES = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);

/**
 * A Sigma rule marked `deprecated` or `unsupported` upstream still exists
 * and still runs — the corpus carries no local "retire this rule" action —
 * but the plan's decision is "visibly dimmed, never hidden" (design-system.md
 * forbids a row silently disappearing). This predicate is the single source
 * of truth for both the "retired" filter/stat and the render-time dimming
 * decision in `ThreatHuntPage.jsx`, so the two can never drift apart.
 *
 * @param {{ upstream_status?: string | null }} rule
 */
export function isRetiredUpstream(rule) {
  return rule?.upstream_status === 'deprecated' || rule?.upstream_status === 'unsupported';
}

/**
 * Adds `tagsKey`, a stable string join of the rule's tags, purely so
 * `constantColumns` (an array-unaware `!==` comparison — see its doc comment
 * in `components/ui/DataTable.jsx`) has something scalar to compare: two rows
 * with the same tags arrive as two distinct array objects and would never
 * compare equal by reference even when their content is identical. Mirrors
 * `mergeRuleStats`' `tagsKey` computation in `./yaraRulesTable.js`; Sigma
 * rules carry no per-rule match stats to merge, so this is the whole of the
 * row-shaping step.
 *
 * @param {Array<object>} rules
 * @returns {Array<object>}
 */
export function withTagsKey(rules) {
  const safeRules = Array.isArray(rules) ? rules : [];
  return safeRules.map(r => ({ ...r, tagsKey: (r.tags ?? []).join(' ') }));
}

/** Segmented toolbar filter values, in display order. Chosen to mirror the
 * stat row exactly: `critical`/`high`/`retired` are the three non-total,
 * non-platform figures the stats band already surfaces, so the toolbar lets
 * an analyst isolate precisely the slice each stat chip names. The other two
 * severities (`medium`/`low`/`informational`) and the 33 platform values
 * don't get segments of their own — a toolbar with eight-plus buttons stops
 * being scannable, and search-by-name already covers the "find one specific
 * rule" case those would otherwise serve. */
export const SIGMA_RULE_FILTERS = ['all', 'critical', 'high', 'retired'];

/**
 * Applies the toolbar's name search and segmented filter, combined with AND
 * semantics. Never hides a row for any other reason — a `deprecated`/
 * `unsupported` rule passes the "all" filter (it is dimmed by the caller's
 * render, not dropped here; see `isRetiredUpstream`'s doc comment).
 *
 * @param {Array<object>} rows — already shaped via `withTagsKey`
 * @param {{ search?: string, filter?: 'all'|'critical'|'high'|'retired' }} [opts]
 */
export function filterSigmaRules(rows, { search = '', filter = 'all' } = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const term = search.trim().toLowerCase();

  return safeRows.filter(r => {
    if (term && !(r.name ?? '').toLowerCase().includes(term)) return false;
    if (filter === 'critical' && r.level !== 'critical') return false;
    if (filter === 'high' && r.level !== 'high') return false;
    if (filter === 'retired' && !isRetiredUpstream(r)) return false;
    return true;
  });
}

/**
 * Default sort for the table — severity descending (design spec), the same
 * "critical first" rule `SigmaHuntTab`'s results table uses. Sigma rules
 * carry no match count to break ties with (unlike YARA's
 * `sortByMatchCountDesc`), so the tie-breaker is the rule name, ascending —
 * stable and predictable rather than left to array order. A level absent or
 * unrecognised (rank 0) sinks to the bottom rather than folding into `low`:
 * "we don't know this rule's severity" is not the same claim as "this rule
 * is low severity". Returns a new array; the caller's `rows` state is never
 * mutated in place.
 */
export function sortBySeverityDesc(rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  return [...safeRows].sort((a, b) => {
    const r = sigmaLevelRank(b.level) - sigmaLevelRank(a.level);
    if (r !== 0) return r;
    return (a.name || '').localeCompare(b.name || '');
  });
}

/**
 * Client-side aggregates for the stat row — no extra route: total rule
 * count, how many are `critical`/`high` severity, how many are
 * `deprecated`/`unsupported` upstream (`isRetiredUpstream`), and how many
 * distinct `logsource_product` values are represented (a `null` product —
 * 182 rules on the real corpus — counts as its own "none" bucket, exactly
 * like the platform breakdown the task spec quotes).
 */
export function computeSigmaRuleStats(rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const total = safeRows.length;
  const critical = safeRows.filter(r => r.level === 'critical').length;
  const high = safeRows.filter(r => r.level === 'high').length;
  const retired = safeRows.filter(isRetiredUpstream).length;
  const platforms = new Set(safeRows.map(r => r.logsource_product ?? null)).size;
  return { total, critical, high, retired, platforms };
}

/**
 * Columns handed to `constantColumns` (see `components/ui/DataTable.jsx`) to
 * find which fields are constant across the currently-filtered rows and
 * belong in a `ScopeBar` token instead of a column. On the real 3999-row set
 * that is exactly two: `tagsKey` (every rule carries `{github, sigmahq}` —
 * the import source) and `author_username` (every rule was imported under
 * the same account — the importer). Unlike YARA's candidate list, this one
 * omits `description` (varies per rule on this corpus, unlike YARA's
 * imported-in-bulk descriptions) and `created_at` (3999 distinct timestamps,
 * not one shared import instant) — neither is a column this tab renders in
 * the first place, so there's nothing for `constantColumns` to usefully
 * check them against.
 */
export const SIGMA_SCOPE_CANDIDATE_COLUMNS = [
  { key: 'tagsKey' },
  { key: 'author_username' },
];
