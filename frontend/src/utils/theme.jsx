import { createContext, useContext, useState, useEffect } from 'react';

/**
 * Source de vérité des couleurs : `src/index.css` (`:root` + `body.theme-light`).
 *
 * Ce module ne définit AUCUNE valeur de couleur. Il expose des alias vers les
 * custom properties afin que les styles inline JSX (`style={{ color: T.text }}`)
 * et les feuilles CSS lisent exactement les mêmes tokens.
 *
 * Historique : ce provider injectait auparavant 15 hex en style inline sur
 * <html>. L'inline battant `:root` mais perdant contre `body.theme-light`,
 * le mode sombre était servi par theme.jsx et le mode clair par index.css.
 * D'où deux régressions : `--fl-border` opaque en sombre (au lieu du hairline
 * translucide de la charte Observatory) et `--fl-purple` confondu avec
 * `--fl-accent` sur 204 occurrences. L'injection est supprimée.
 *
 * Contrainte : ne jamais concaténer un suffixe alpha sur ces valeurs
 * (`${T.accent}22` produirait `var(--fl-accent)22`, invalide). Utiliser
 * `color-mix(in srgb, ${T.accent} 13%, transparent)`.
 *
 * Contrainte : ne pas passer ces valeurs à un canvas (Cytoscape, D3) — ces
 * moteurs écrivent des attributs et ne résolvent pas `var()`. Ils gardent
 * leur propre palette d'hex Observatory.
 */
const TOKENS = {
  bg:         'var(--fl-bg)',
  panel:      'var(--fl-panel)',
  card:       'var(--fl-card)',
  border:     'var(--fl-border)',
  accent:     'var(--fl-accent)',
  accentDark: 'var(--fl-accent-dark)',
  warn:       'var(--fl-warn)',
  danger:     'var(--fl-danger)',
  ok:         'var(--fl-ok)',
  gold:       'var(--fl-gold)',
  purple:     'var(--fl-purple)',
  pink:       'var(--fl-pink)',
  text:       'var(--fl-text)',
  dim:        'var(--fl-dim)',
  muted:      'var(--fl-muted)',
  inputBg:    'var(--fl-input-bg)',
  tableBg:    'var(--fl-panel)',
  headerBg:   'var(--fl-bg)',
};

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [mode, setMode] = useState(() => {

    try {
      const raw = localStorage.getItem('heimdall_preferences');
      if (raw) {
        const p = JSON.parse(raw);
        if (p.theme === 'dark' || p.theme === 'light') return p.theme;
      }
    } catch (_e) {}
    return localStorage.getItem('heimdall_theme') || 'dark';
  });

  useEffect(() => {
    localStorage.setItem('heimdall_theme', mode);

    try {
      const raw = localStorage.getItem('heimdall_preferences');
      const p = raw ? JSON.parse(raw) : {};
      p.theme = mode;
      localStorage.setItem('heimdall_preferences', JSON.stringify(p));
    } catch (_e) {}

    // La classe est le seul signal : index.css fait le reste.
    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add('theme-' + mode);
  }, [mode]);

  const toggle = () => setMode(m => m === 'dark' ? 'light' : 'dark');
  const value  = { ...TOKENS, mode, toggle };

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}
