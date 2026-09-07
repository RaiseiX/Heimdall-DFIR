import { sigmaLevelRank, sigmaLevelColor, isRetiredUpstream } from '../pages/sigmaRulesTable';

export const PICKER_RENDER_CAP = 50;

export const LEVEL_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

export const levelColor = sigmaLevelColor;

function logsourceLabel(rule) {
  const product = rule.logsource_product || '';
  const category = rule.logsource_category || '';
  if (product && category) return `${product}/${category}`;
  return product || category || '';
}

export function ruleSubline(rule) {
  if (!rule) return '';
  return [rule.level || '', logsourceLabel(rule), rule.mitre_techniques?.[0] || '']
    .filter(Boolean)
    .join(' · ');
}

function haystack(rule) {
  return [
    rule.name || '',
    rule.logsource_product || '',
    rule.logsource_category || '',
    ...(rule.mitre_techniques || []),
  ].join(' ').toLowerCase();
}

export function facetCounts(rules) {
  const rows = Array.isArray(rules) ? rules : [];
  const levels = {};
  const byProduct = new Map();
  let retired = 0;

  for (const r of rows) {
    if (r.level) levels[r.level] = (levels[r.level] || 0) + 1;
    if (r.logsource_product) byProduct.set(r.logsource_product, (byProduct.get(r.logsource_product) || 0) + 1);
    if (isRetiredUpstream(r)) retired += 1;
  }

  const products = [...byProduct.entries()]
    .map(([product, count]) => ({ product, count }))
    .sort((a, b) => b.count - a.count || a.product.localeCompare(b.product));

  return { levels, products, retired, total: rows.length };
}

export function pickerItems(rules, facets = {}) {
  const rows = Array.isArray(rules) ? rules : [];
  const { search = '', levels = [], products = [], hideRetired = false } = facets || {};
  const term = search.trim().toLowerCase();
  const wantedLevels = new Set(levels);
  const wantedProducts = new Set(products);

  const matched = rows.filter(r => {
    if (hideRetired && isRetiredUpstream(r)) return false;
    if (wantedLevels.size && !wantedLevels.has(r.level)) return false;
    if (wantedProducts.size && !wantedProducts.has(r.logsource_product)) return false;
    if (term && !haystack(r).includes(term)) return false;
    return true;
  });

  const ordered = [...matched].sort((a, b) => {
    const rank = sigmaLevelRank(b.level) - sigmaLevelRank(a.level);
    if (rank !== 0) return rank;
    return (a.name || '').localeCompare(b.name || '');
  });

  const items = ordered.slice(0, PICKER_RENDER_CAP).map(r => ({
    id: r.id,
    label: r.name,
    sub: ruleSubline(r),
    level: r.level || null,
    retired: isRetiredUpstream(r),
  }));

  return { items, matched: matched.length, hidden: matched.length - items.length, total: rows.length };
}
