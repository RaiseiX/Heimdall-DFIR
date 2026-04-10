import { createContext, useContext, useState, useEffect } from 'react';

const themes = {
  dark: {
    bg: '#0d1117', panel: '#161b22', card: '#1c2333', border: '#30363d',
    accent: '#4d82c0', accentDark: '#3a6aaa', warn: '#d97c20', danger: '#da3633',
    ok: '#3fb950', gold: '#c89d1d', purple: '#8b72d6', pink: '#c96898',
    text: '#e6edf3', dim: '#8b9ab4', muted: '#6b7a8a',
    inputBg: '#0d1117', tableBg: '#161b22', headerBg: '#0d1117',
  },
  light: {
    bg: '#f6f8fa', panel: '#ffffff', card: '#ffffff', border: '#d0d7de',
    accent: '#0969da', accentDark: '#0550ae', warn: '#bf8700', danger: '#cf222e',
    ok: '#1a7f37', gold: '#9a6700', purple: '#6639ba', pink: '#bf3989',
    text: '#1f2328', dim: '#57606a', muted: '#818b98',
    inputBg: '#f6f8fa', tableBg: '#f6f8fa', headerBg: '#f6f8fa',
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
    } catch  }
    return localStorage.getItem('heimdall_theme') || 'dark';
  });

  useEffect(() => {
    localStorage.setItem('heimdall_theme', mode);

    try {
      const raw = localStorage.getItem('heimdall_preferences');
      const p = raw ? JSON.parse(raw) : {};
      p.theme = mode;
      localStorage.setItem('heimdall_preferences', JSON.stringify(p));
    } catch  }
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
