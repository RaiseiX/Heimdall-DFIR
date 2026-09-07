export const C = {
  yara:    'var(--fl-accent)',
  sigma:   'var(--fl-purple)',
  warn:    'var(--fl-warn)',
  surface: 'var(--fl-card)',
  border:  'var(--fl-border)',
};

export function localeFor(lang) {
  return lang?.startsWith('en') ? 'en-US' : 'fr-FR';
}

export function fmtDate(d, lang = 'fr') {
  if (!d) return '—';
  return new Date(d).toLocaleDateString(localeFor(lang), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
