// Correspondance réponse HTTP → clé i18n. Fonction pure, testable hors React.
// Le backend renvoie un `code` machine ; la phrase est choisie côté client, seul
// endroit qui connaît la langue de l'utilisateur.
const BY_CODE = {
  account_locked:      { key: 'login.error_locked',        tone: 'warn' },
  account_disabled:    { key: 'login.error_disabled',      tone: 'warn' },
  rate_limited:        { key: 'login.error_rate_limited',  tone: 'warn' },
  invalid_credentials: { key: 'login.error_credentials',   tone: 'danger' },
  missing_fields:      { key: 'login.error_credentials',   tone: 'danger' },
};

// No entry for 429 here on purpose: it's the one status shared by two
// unrelated events (the per-username account lockout and the IP-based
// `authLimiter` throttle in backend/src/routes/auth.js), so it cannot be
// resolved from the status code alone. See the dedicated 429 branch below.
const BY_STATUS = {
  403: { key: 'login.error_disabled',    tone: 'warn' },
  401: { key: 'login.error_credentials', tone: 'danger' },
};

export function resolveLoginError(err) {
  if (!err?.response) {
    return { key: 'login.error_network', vars: {}, tone: 'danger', net: true };
  }
  const { status, data = {} } = err.response;

  // Account lockout (POST /login's own check) always sends `windowMin`;
  // the `authLimiter` rate-limit middleware (which can respond before that
  // check even runs) never does. When no explicit `code` narrows it down,
  // use that to tell the two 429 sources apart instead of defaulting to
  // `error_locked` — a lockout message on an IP throttle, or vice versa,
  // would misdescribe what actually happened.
  const status429Fallback = status === 429
    ? (data.windowMin != null
      ? { key: 'login.error_locked', tone: 'warn' }
      : { key: 'login.error_rate_limited', tone: 'warn' })
    : null;

  const hit = BY_CODE[data.code] || status429Fallback || BY_STATUS[status]
    || (status >= 500 ? { key: 'login.error_server', tone: 'danger' } : null)
    || { key: 'login.error', tone: 'danger' };

  const vars = {};
  // `windowMin` feeds the {{windowMin}} interpolation kept for compatibility;
  // `count` is what i18next actually reads to pick the _one/_other plural
  // form of login.error_locked (CLDR pluralisation keys off `count`, not an
  // arbitrary var name).
  if (data.windowMin != null) {
    vars.windowMin = data.windowMin;
    vars.count = data.windowMin;
  }
  return { key: hit.key, vars, tone: hit.tone, net: false };
}
