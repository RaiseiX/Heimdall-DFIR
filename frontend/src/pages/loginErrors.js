const BY_CODE = {
  account_locked:      { key: 'login.error_locked',        tone: 'warn' },
  account_disabled:    { key: 'login.error_disabled',      tone: 'warn' },
  rate_limited:        { key: 'login.error_rate_limited',  tone: 'warn' },
  invalid_credentials: { key: 'login.error_credentials',   tone: 'danger' },
  missing_fields:      { key: 'login.error_credentials',   tone: 'danger' },
};

const BY_STATUS = {
  403: { key: 'login.error_disabled',    tone: 'warn' },
  401: { key: 'login.error_credentials', tone: 'danger' },
};

export function resolveLoginError(err) {
  if (!err?.response) {
    return { key: 'login.error_network', vars: {}, tone: 'danger', net: true };
  }
  const { status, data = {} } = err.response;

  const status429Fallback = status === 429
    ? (data.windowMin != null
      ? { key: 'login.error_locked', tone: 'warn' }
      : { key: 'login.error_rate_limited', tone: 'warn' })
    : null;

  const hit = BY_CODE[data.code] || status429Fallback || BY_STATUS[status]
    || (status >= 500 ? { key: 'login.error_server', tone: 'danger' } : null)
    || { key: 'login.error', tone: 'danger' };

  const vars = {};
  if (data.windowMin != null) {
    vars.windowMin = data.windowMin;
    vars.count = data.windowMin;
  }
  return { key: hit.key, vars, tone: hit.tone, net: false };
}
