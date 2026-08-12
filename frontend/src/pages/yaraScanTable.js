/**
 * Pure logic behind `YaraScanTab` (Threat Hunting redesign — the case-scoped
 * YARA scan execution tab; see `.superpowers/sdd/yara-scan-runall-ui-
 * report.md`). Same split as `./yaraRulesTable.js`/`./sigmaRulesTable.js`:
 * row-shaping and stat math extracted so they're testable without mounting
 * React.
 */

/**
 * Fallback stat-row aggregates computed from `GET /yara/results/:caseId`
 * (persisted matches only — one row per evidence×rule match) for a page
 * load where no scan has run in this browser session yet. Mirrors
 * `SigmaHuntTab`'s `derivedStats`: `filesScanned`/`filesSkipped`/
 * `rulesChecked` are NOT derivable from this table at all (only actual
 * matches persist — see the `DELETE ... ; INSERT ... WHERE matched` shape of
 * `POST /yara/scan-case/:caseId` in backend/src/routes/threatHunting.ts), so
 * this deliberately returns only what the persisted match rows can honestly
 * support: how many distinct evidence files were flagged, how many distinct
 * rules matched at least once, and the total number of evidence×rule match
 * pairs. Everything else stays `null` (rendered "unknown" by the caller),
 * never guessed as 0.
 *
 * @param {Array<{ evidence_id: string, rule_id: string }>} results
 */
export function deriveYaraScanStats(results) {
  const safeResults = Array.isArray(results) ? results : [];
  const filesFlagged = new Set(safeResults.map(r => r.evidence_id)).size;
  const rulesMatched = new Set(safeResults.map(r => r.rule_id)).size;
  return { filesFlagged, rulesMatched, totalMatches: safeResults.length };
}

/**
 * Hover title for a match row's "matched strings" cell — every matched
 * string, not just the count, without building a second expandable
 * mini-table (the interaction `SigmaHuntTab`'s own report already retired in
 * favour of a real pivot; YARA matches have nowhere to pivot to — no
 * evidence-detail route exists in this app — so the detail stays reachable
 * via `title`, the same "hover for the full list" pattern this file's
 * MITRE-technique column already uses). Caps at 20 lines so one match with
 * an unusually large string table doesn't produce a tooltip nobody can
 * actually read.
 *
 * @param {Array<{ identifier?: string, offset?: number, data?: string }>} matchedStrings
 */
export function matchedStringsTitle(matchedStrings) {
  const safe = Array.isArray(matchedStrings) ? matchedStrings : [];
  if (safe.length === 0) return '';
  const CAP = 20;
  const lines = safe.slice(0, CAP).map(s => {
    const offset = typeof s.offset === 'number' ? `0x${s.offset.toString(16)}` : '?';
    return `${s.identifier ?? '?'} @ ${offset}: ${s.data ?? ''}`;
  });
  if (safe.length > CAP) lines.push(`… (${safe.length - CAP} more)`);
  return lines.join('\n');
}
