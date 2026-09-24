
const SELF_RENDERED = new Set(['network', 'auth', 'hayabusa', 'cyberchef', 'threathunt', 'processes']);

export function resolveCollectionPane(tab) {
  if (tab === 'evidence') return 'overview';
  if (SELF_RENDERED.has(tab)) return tab;
  return 'outlet';
}
