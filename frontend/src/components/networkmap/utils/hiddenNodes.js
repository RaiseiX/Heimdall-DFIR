export const HIDDEN_CLASS = 'analyst-hidden';

const NON_GRAPH = '.manual, .zone, .zone-label, .band-rule, .band-label';

export function toggleHidden(hidden, id) {
  const next = new Set(hidden instanceof Set ? hidden : []);
  if (!id) return next;
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export function hiddenEntries(elements, hidden) {
  if (!Array.isArray(elements) || !(hidden instanceof Set) || hidden.size === 0) return [];
  return elements
    .filter(e => e?.data?.id && !e.data.source && hidden.has(e.data.id))
    .map(e => ({ id: e.data.id, label: e.data.label || e.data.id }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

export function applyHidden(cy, hidden) {
  if (!cy) return;
  const set = hidden instanceof Set ? hidden : new Set();
  cy.batch(() => {
    cy.nodes().not(NON_GRAPH).forEach(n => n.toggleClass(HIDDEN_CLASS, set.has(n.id())));
  });
}
