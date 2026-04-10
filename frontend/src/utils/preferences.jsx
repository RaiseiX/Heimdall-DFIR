
import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { usersAPI } from './api';
import i18n from '../i18n/index.js';

export const DEFAULT_PREFS = {
  language:      'fr',
  timezone:      'utc',
  theme:         'dark',
  chat_color:    '#4d82c0',
  table_density: 'standard',
  display_name:  null,
};

const STORAGE_KEY = 'heimdall_preferences';

function readFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    return { ...DEFAULT_PREFS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

function writeToStorage(prefs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch  }
}

const PreferencesContext = createContext(null);

export function PreferencesProvider({ children }) {

  const [prefs, setPrefs] = useState(() => readFromStorage());

  const debounceRef = useRef(null);
  const pendingPatch = useRef({});

  useEffect(() => {

    localStorage.setItem('heimdall_theme', prefs.theme);

    document.body.classList.remove('fl-density-compact', 'fl-density-standard', 'fl-density-comfortable');
    document.body.classList.add(`fl-density-${prefs.table_density}`);
  }, [prefs.theme, prefs.table_density]);

  useEffect(() => {
    if (prefs.language && i18n.language !== prefs.language) {
      i18n.changeLanguage(prefs.language);
    }
  }, [prefs.language]);

  const updatePref = useCallback((key, value) => {
    setPrefs(prev => {
      const next = { ...prev, [key]: value };
      writeToStorage(next);

      pendingPatch.current[key] = value;
      return next;
    });

    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const patch = { ...pendingPatch.current };
      pendingPatch.current = {};
      if (Object.keys(patch).length > 0) {
        usersAPI.updatePreferences(patch).catch(() =>  });
      }
    }, 600);
  }, []);

  const loadFromBackend = useCallback((backendPrefs) => {
    if (!backendPrefs || typeof backendPrefs !== 'object') return;
    setPrefs(prev => {
      const merged = { ...DEFAULT_PREFS, ...prev, ...backendPrefs };
      writeToStorage(merged);
      return merged;
    });
  }, []);

  return (
    <PreferencesContext.Provider value={{ prefs, updatePref, loadFromBackend }}>
      {children}
    </PreferencesContext.Provider>
  );
}

export function usePreferences() {
  const ctx = useContext(PreferencesContext);
  if (!ctx) throw new Error('usePreferences must be used inside PreferencesProvider');
  return ctx;
}
