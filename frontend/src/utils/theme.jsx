import { createContext, useContext, useState, useEffect } from 'react';

const themes = {
  dark: {
    bg: '#0a0c11', panel: '#0e1118', card: '#131722', border: '#1c2334',
    accent: '#8b7fff', accentDark: '#6c5be8', warn: '#e69654', danger: '#e0556d',
    ok: '#6abf8e', gold: '#c9a86a', purple: '#8b7fff', pink: '#c96898',
    text: '#dde0e8', dim: '#a5acba', muted: '#6e7689',
    inputBg: '#0a0c11', tableBg: '#0e1118', headerBg: '#0a0c11',
  },
  light: {
    bg: '#f4f6fb', panel: '#ffffff', card: '#f8fafd', border: '#d4dae8',
    accent: '#6c5df5', accentDark: '#5246e8', warn: '#c4721e', danger: '#cc3355',
    ok: '#2d9e6e', gold: '#9a7a30', purple: '#6c5df5', pink: '#a63878',
    text: '#111827', dim: '#4a5568', muted: '#718096',
    inputBg: '#f4f6fb', tableBg: '#f8fafd', headerBg: '#f4f6fb',
  },
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
    const t = themes[mode];

    document.body.style.background = t.bg;
    document.body.style.color      = t.text;

    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add('theme-' + mode);

    const FL_MAP = {
      bg: '--fl-bg', panel: '--fl-panel', card: '--fl-card',
      border: '--fl-border', text: '--fl-text', dim: '--fl-dim', muted: '--fl-muted',
      accent: '--fl-accent', danger: '--fl-danger', warn: '--fl-warn',
      ok: '--fl-ok', gold: '--fl-gold', purple: '--fl-purple', pink: '--fl-pink',
      inputBg: '--fl-input-bg',
    };
    const root = document.documentElement;
    Object.entries(t).forEach(([key, val]) => {
      if (FL_MAP[key]) root.style.setProperty(FL_MAP[key], val);
    });
  }, [mode]);

  const toggle = () => setMode(m => m === 'dark' ? 'light' : 'dark');
  const value  = { ...themes[mode], mode, toggle };

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}
