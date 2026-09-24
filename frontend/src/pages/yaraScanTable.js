
export function deriveYaraScanStats(results) {
  const safeResults = Array.isArray(results) ? results : [];
  const filesFlagged = new Set(safeResults.map(r => r.evidence_id)).size;
  const rulesMatched = new Set(safeResults.map(r => r.rule_id)).size;
  return { filesFlagged, rulesMatched, totalMatches: safeResults.length };
}

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
