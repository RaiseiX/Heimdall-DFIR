export const DENSITES = ['compact', 'normal', 'relaxed'];

export const LARGEUR_PANNEAU = { min: 280, max: 720, defaut: 340 };

export function classeDensite(d) {
  return DENSITES.includes(d) ? `fl-dense-${d}` : 'fl-dense-normal';
}

export function largeurPanneauValide(v) {
  if (v === null || v === undefined || v === '' || typeof v === 'boolean') return LARGEUR_PANNEAU.defaut;
  const n = Number(v);
  if (!Number.isFinite(n)) return LARGEUR_PANNEAU.defaut;
  return Math.round(Math.min(LARGEUR_PANNEAU.max, Math.max(LARGEUR_PANNEAU.min, n)));
}
