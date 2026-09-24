export const VERDICT_CHOICES = [
  { status: 'in_review',      label: 'En revue' },
  { status: 'confirmed',      label: 'Confirmé' },
  { status: 'false_positive', label: 'Faux positif' },
];

const LABELS = Object.fromEntries(VERDICT_CHOICES.map(c => [c.status, c.label]));

const COLORS = {
  in_review:      'var(--fl-warn)',
  confirmed:      'var(--fl-danger)',
  false_positive: 'var(--fl-muted)',
};

export function verdictLabel(status) {
  return LABELS[status] ?? null;
}

export function verdictColor(status) {
  return COLORS[status] ?? null;
}

export function isFaded(status) {
  return status === 'false_positive';
}

export function parseEvents(v) {
  if (Array.isArray(v)) return v;
  if (typeof v !== 'string') return [];
  try {
    const parsed = JSON.parse(v);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
