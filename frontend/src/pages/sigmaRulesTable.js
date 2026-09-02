
export const SIGMA_LEVEL_RANK  = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
export const SIGMA_LEVEL_COLOR = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };

export function sigmaLevelRank(level)  { return SIGMA_LEVEL_RANK[level] ?? 0; }
export function sigmaLevelColor(level) { return SIGMA_LEVEL_COLOR[level] || 'var(--fl-dim)'; }
export function sigmaLevelLabel(level, t) {
  return t(`threat_hunt.sigma.level.${level && SIGMA_LEVEL_RANK[level] ? level : 'unknown'}`);
}

function localeFor(lang) {
  return lang?.startsWith('en') ? 'en-US' : 'fr-FR';
}

export function fmtNum(n, lang) {
  if (n === null || n === undefined) return '—';
  try { return new Intl.NumberFormat(localeFor(lang)).format(n); } catch { return String(n); }
}

export const SIGMA_UPSTREAM_STATUSES = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);

export function isRetiredUpstream(rule) {
  return rule?.upstream_status === 'deprecated' || rule?.upstream_status === 'unsupported';
}

export function withTagsKey(rules) {
  const safeRules = Array.isArray(rules) ? rules : [];
  return safeRules.map(r => ({ ...r, tagsKey: (r.tags ?? []).join(' ') }));
}

export const SIGMA_RULE_FILTERS = ['all', 'critical', 'high', 'retired'];

export function filterSigmaRules(rows, { search = '', filter = 'all' } = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const term = search.trim().toLowerCase();

  return safeRows.filter(r => {
    if (term && !(r.name ?? '').toLowerCase().includes(term)) return false;
    if (filter === 'critical' && r.level !== 'critical') return false;
    if (filter === 'high' && r.level !== 'high') return false;
    if (filter === 'retired' && !isRetiredUpstream(r)) return false;
    return true;
  });
}

export function sortBySeverityDesc(rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  return [...safeRows].sort((a, b) => {
    const r = sigmaLevelRank(b.level) - sigmaLevelRank(a.level);
    if (r !== 0) return r;
    return (a.name || '').localeCompare(b.name || '');
  });
}

export function computeSigmaRuleStats(rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const total = safeRows.length;
  const critical = safeRows.filter(r => r.level === 'critical').length;
  const high = safeRows.filter(r => r.level === 'high').length;
  const retired = safeRows.filter(isRetiredUpstream).length;
  const platforms = new Set(safeRows.map(r => r.logsource_product ?? null)).size;
  return { total, critical, high, retired, platforms };
}

export const SIGMA_SCOPE_CANDIDATE_COLUMNS = [
  { key: 'tagsKey' },
  { key: 'author_username' },
];
