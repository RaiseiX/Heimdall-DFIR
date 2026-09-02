import i18n from '../i18n';

const ABSENT = '—';

export function formatCountIn(value, locale) {
  if (value === null || value === undefined || value === '') return ABSENT;
  const n = Number(value);
  if (!Number.isFinite(n)) return ABSENT;
  try {
    return n.toLocaleString(locale);
  } catch {
    return n.toLocaleString('en');
  }
}

export function formatCount(value) {
  return formatCountIn(value, i18n.language);
}
