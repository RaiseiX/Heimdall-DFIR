import { artifactFamily, FAMILY_ORDER } from '../../../constants/artifactColors';
import { rankTypes } from './timelineUtils';

export const OTHER_FAMILY = 'autres';
export const WINDOWS_FAMILY = 'windows';
export const NO_TYPE = '__NONE__';

const SECTION_ORDER = [...FAMILY_ORDER, OTHER_FAMILY, WINDOWS_FAMILY];

const LABELS = {
  [WINDOWS_FAMILY]: 'hôte Windows',
  [OTHER_FAMILY]: 'autres',
};

export function familyLabel(family) {
  return LABELS[family] ?? family;
}

function sectionOf(type) {
  if (!type.startsWith('catscale_')) return WINDOWS_FAMILY;
  return artifactFamily(type) ?? OTHER_FAMILY;
}

function byCountThenName(a, b) {
  if (a.count === null && b.count === null) return a.type.localeCompare(b.type);
  if (a.count === null) return 1;
  if (b.count === null) return -1;
  return b.count - a.count || a.type.localeCompare(b.type);
}

export function groupArtifactTypes(availTypes, typeCounts, search = '') {
  const list = Array.isArray(availTypes) ? availTypes : [];
  const counts = typeCounts && typeof typeCounts === 'object' ? typeCounts : {};
  const term = String(search ?? '').trim().toLowerCase();

  const buckets = new Map();
  for (const type of list) {
    if (typeof type !== 'string') continue;
    if (term && !type.toLowerCase().includes(term)) continue;
    const section = sectionOf(type);
    if (!buckets.has(section)) buckets.set(section, []);
    buckets.get(section).push({
      type,
      count: Number.isFinite(counts[type]) ? counts[type] : null,
    });
  }

  return SECTION_ORDER
    .filter(family => buckets.has(family))
    .map(family => {
      const types = buckets.get(family).sort(byCountThenName);
      const rowCount = types.some(t => t.count === null)
        ? null
        : types.reduce((sum, t) => sum + t.count, 0);
      return { family, label: familyLabel(family), types, typeCount: types.length, rowCount };
    });
}

export function countTypes(groups) {
  if (!Array.isArray(groups)) return 0;
  return groups.reduce((sum, g) => sum + g.types.length, 0);
}

export function sumRows(types, counts) {
  const list = Array.isArray(types) ? types : [];
  const table = counts && typeof counts === 'object' ? counts : {};
  let total = 0;
  for (const type of list) {
    if (!Number.isFinite(table[type])) return null;
    total += table[type];
  }
  return total;
}

function includedCount(list, selected) {
  const wanted = Array.isArray(selected) ? selected : [];
  if (wanted.length === 0) return list.length;
  if (wanted.length === 1 && wanted[0] === NO_TYPE) return 0;
  const known = new Set(list);
  return wanted.filter(type => known.has(type)).length;
}

export function stripTypes({ availTypes, typeCounts, family = null, search = '', selected = [], visible = 12 } = {}) {
  const list = Array.isArray(availTypes) ? availTypes.filter(Boolean) : [];
  const counts = typeCounts && typeof typeCounts === 'object' ? typeCounts : {};
  const term = String(search ?? '').trim().toLowerCase();
  const filtering = Boolean(family) || term.length > 0;

  if (!list.length) {
    return { shown: [], hidden: [], matched: 0, total: 0, filtering: false, included: 0, restricting: false };
  }

  const included = includedCount(list, selected);
  const restricting = included !== list.length;

  if (!filtering) {
    const { shown, hidden } = rankTypes(list, counts, visible, selected);
    return { shown, hidden, matched: list.length, total: list.length, filtering: false, included, restricting };
  }

  const order = (a, b) => {
    const na = Number.isFinite(counts[a]) ? counts[a] : -1;
    const nb = Number.isFinite(counts[b]) ? counts[b] : -1;
    return nb - na || a.localeCompare(b);
  };

  const matched = list
    .filter(type => (!family || sectionOf(type) === family) && (!term || type.toLowerCase().includes(term)))
    .sort(order);

  return {
    shown: matched,
    hidden: [],
    matched: matched.length,
    total: list.length,
    filtering: true,
    included,
    restricting,
  };
}
