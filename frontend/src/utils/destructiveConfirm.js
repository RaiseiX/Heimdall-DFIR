/**
 * Shared gate in front of irreversible destruction (DoD 5220.22-M erasure).
 *
 * The analyst must retype a canonical value before the action unlocks: the case
 * number for a single case, the number of selected cases for a bulk destroy.
 *
 * Case-sensitive on purpose — a case number is an identifier, not a password
 * hint, and loosening it would let `case-2026-014` destroy `CASE-2026-014`.
 *
 * The empty-expected guard matters more than it looks: a plain `typed === expected`
 * unlocks the button whenever the expected value is still undefined (case loading,
 * empty selection) and the input happens to be empty too.
 *
 * @param {string} typed    what the analyst typed
 * @param {string|null|undefined} expected  the canonical value to match
 * @returns {boolean} true only when there is something to confirm and it matches
 */
export function isDestructionConfirmed(typed, expected) {
  const target = String(expected ?? '').trim();
  if (!target) return false;
  return String(typed ?? '').trim() === target;
}
