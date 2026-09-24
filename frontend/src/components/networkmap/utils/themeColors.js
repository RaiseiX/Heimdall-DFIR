const HEX6 = /^#[0-9a-fA-F]{6}$/;

const JETONS = {
  accent:        '--fl-accent',
  danger:        '--fl-danger',
  warn:          '--fl-warn',
  ok:            '--fl-ok',
  gold:          '--fl-gold',
  purple:        '--fl-purple',
  bg:            '--fl-bg',
  text:          '--fl-text',
  muted:         '--fl-muted',
  surfaceActive: '--fl-surface-active',
};

export const REPLIS_CANVAS = Object.freeze({
  accent:        '#8b7fff',
  danger:        '#e0556d',
  warn:          '#e69654',
  ok:            '#6abf8e',
  gold:          '#c9a86a',
  purple:        '#6b8ccf',
  bg:            '#0a0c11',
  text:          '#dde0e8',
  muted:         '#7e8697',
  surfaceActive: '#222a3a',
});

function lectureParDefaut(nom) {
  if (typeof document === 'undefined' || !document.documentElement) return '';
  try {
    return getComputedStyle(document.documentElement).getPropertyValue(nom);
  } catch {
    return '';
  }
}

export function couleursDuTheme(lire) {
  const source = typeof lire === 'function' ? lire : lectureParDefaut;
  const sortie = {};
  for (const [cle, jeton] of Object.entries(JETONS)) {
    const brut = String(source(jeton) || '').trim();
    sortie[cle] = HEX6.test(brut) ? brut : REPLIS_CANVAS[cle];
  }
  return sortie;
}

export function avecAlpha(couleur, suffixe) {
  const c = typeof couleur === 'string' ? couleur : '';
  return HEX6.test(c) ? c + suffixe : c;
}
