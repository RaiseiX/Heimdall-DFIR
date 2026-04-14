import { usePreferences } from '../utils/preferences';

export function useDateFormat() {
  const { prefs } = usePreferences();
  const locale  = prefs.language === 'en' ? 'en-GB' : 'fr-FR';
  const tzOpts  = prefs.timezone === 'utc' ? { timeZone: 'UTC' } : {};

  return {
    fmtDateTime: (ts) => {
      if (!ts) return '—';
      try { return new Date(ts).toLocaleString(locale, tzOpts); } catch { return String(ts); }
    },
    fmtDate: (ts) => {
      if (!ts) return '—';
      try { return new Date(ts).toLocaleDateString(locale, tzOpts); } catch { return String(ts); }
    },
    fmtTime: (ts) => {
      if (!ts) return '—';
      try { return new Date(ts).toLocaleTimeString(locale, tzOpts); } catch { return String(ts); }
    },
    isUTC: prefs.timezone === 'utc',
    tzLabel: prefs.timezone === 'utc' ? ' UTC' : ' (local)',
  };
}
