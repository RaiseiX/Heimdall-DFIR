import { createContext, useContext, useState, useEffect } from 'react';

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
