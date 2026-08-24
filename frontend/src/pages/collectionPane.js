// Which pane CollectionLayout should render for a given :tab route param.
//
// The collection routes mix two kinds of child: specialised tabs that arrive as
// a `:tab` param, and static child routes (`timeline`, `logs`) that React Router
// prefers over `:tab` — so for those, `:tab` is undefined and their component
// comes from <Outlet />.
//
// Defaulting an absent tab to 'evidence' is therefore wrong, and was the bug:
// navigating to the Super Timeline or the parser logs changed the URL but
// rendered the collection overview, because the outlet branch was never reached.
// An undefined tab cannot mean "no tab chosen" — the index route already
// redirects to `evidence` — it can only mean a static child route matched.

/** Panes CollectionLayout renders itself rather than delegating to the outlet. */
const SELF_RENDERED = new Set(['network', 'auth', 'hayabusa', 'cyberchef', 'threathunt']);

/**
 * @param {string|undefined} tab the `:tab` route param, absent on static child routes
 * @returns {'overview'|'network'|'auth'|'hayabusa'|'cyberchef'|'threathunt'|'outlet'}
 */
export function resolveCollectionPane(tab) {
  if (tab === 'evidence') return 'overview';
  if (SELF_RENDERED.has(tab)) return tab;
  return 'outlet';
}
