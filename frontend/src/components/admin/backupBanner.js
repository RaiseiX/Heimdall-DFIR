function utc(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export function backupBanner(status) {
  if (status && status.state === 'ok') return null;
  if (status && status.state === 'disabled') return { key: 'dashboard.backups_disabled', params: {} };
  if (status && status.state === 'stale') {
    return { key: 'dashboard.backups_stale', params: { date: utc(status.last_success_at), hours: status.max_age_hours } };
  }
  return { key: 'dashboard.backups_unknown', params: {} };
}
