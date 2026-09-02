export function isDestructionConfirmed(typed, expected) {
  const target = String(expected ?? '').trim();
  if (!target) return false;
  return String(typed ?? '').trim() === target;
}
