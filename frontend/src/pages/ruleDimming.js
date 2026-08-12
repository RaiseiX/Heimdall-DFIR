/**
 * Shared "will this rule not run" predicate behind the `rt-name-muted`
 * dimming class (see `index.css`) on both `YaraRulesTab` and `SigmaRulesTab`
 * in `ThreatHuntPage.jsx`. The two tabs used to each decide dimming their
 * own way — YARA on `match_count === 0`, Sigma on `isRetiredUpstream` — so
 * the same class silently meant two different things depending which tab
 * you were on. Extracted to one predicate so that can't happen again.
 *
 * A rule is dimmed when it is disabled (`is_active === false`, either
 * engine) or retired upstream (`isRetiredUpstream`, Sigma-only — the field
 * it reads, `upstream_status`, simply doesn't exist on a YARA rule, so the
 * check is a harmless no-op there). A YARA rule that is active but has
 * never matched is deliberately NOT dimmed by this predicate — it still
 * runs on every hunt, it just hasn't hit yet; that state is already carried
 * by the `—` in the Correspondances column and the `Muettes` filter.
 *
 * @param {{ is_active?: boolean, upstream_status?: string|null }} rule
 */
import { isRetiredUpstream } from './sigmaRulesTable';

export function isRuleDimmed(rule) {
  return rule?.is_active === false || isRetiredUpstream(rule);
}
