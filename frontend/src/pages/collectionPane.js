
const SELF_RENDERED = new Set(['network', 'hayabusa', 'cyberchef', 'threathunt']);

export function resolveCollectionPane(tab) {
  if (tab === 'evidence') return 'overview';
  if (SELF_RENDERED.has(tab)) return tab;
  return 'outlet';
}
