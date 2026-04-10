
import yaml from 'js-yaml';

export interface SigmaRule {
  title:       string;
  description?: string;
  logsource?:  { category?: string; product?: string; service?: string };
  detection:   Record<string, unknown>;
  tags?:       string[];
}

export interface BuildQueryResult {
  where:  string;
  params: unknown[];
}

export function parseRule(content: string): {
  valid:   boolean;
  parsed?: SigmaRule;
  error?:  string;
  logsourceCategory?: string;
  logsourceProduct?:  string;
} {
  let doc: unknown;
  try {
    doc = yaml.load(content);
  } catch (e: any) {
    return { valid: false, error: `YAML invalide : ${e.message}` };
  }

  if (typeof doc !== 'object' || doc === null) {
    return { valid: false, error: 'Le document YAML doit être un objet' };
  }
  const rule = doc as Record<string, unknown>;

  if (typeof rule['title'] !== 'string' || !rule['title']) {
    return { valid: false, error: 'Le champ "title" est requis' };
  }
  if (typeof rule['detection'] !== 'object' || rule['detection'] === null) {
    return { valid: false, error: 'Le champ "detection" est requis' };
  }
  const detection = rule['detection'] as Record<string, unknown>;
  if (!detection['condition']) {
    return { valid: false, error: 'detection.condition est requis' };
  }

  const ls = (rule['logsource'] as Record<string, string> | undefined) ?? {};
  return {
    valid:              true,
    parsed:             doc as SigmaRule,
    logsourceCategory:  ls['category'],
    logsourceProduct:   ls['product'],
  };
}

function splitField(key: string): { field: string; mods: string[] } {
  const parts = key.split('|');
  return { field: parts[0], mods: parts.slice(1) };
}

function fieldCondition(
  field:  string,
  mods:   string[],
  values: unknown[],
  params: unknown[],
): string {
  const conditions: string[] = [];

  for (const val of values) {
    const idx = params.length + 1;
    let sqlVal: unknown = val;
    let op    = '=';
    let cast  = `raw->>'${field}'`;

    if (mods.includes('contains')) {
      op     = 'ILIKE';
      sqlVal = `%${val}%`;
    } else if (mods.includes('startswith')) {
      op     = 'ILIKE';
      sqlVal = `${val}%`;
    } else if (mods.includes('endswith')) {
      op     = 'ILIKE';
      sqlVal = `%${val}`;
    } else if (mods.includes('re')) {
      op = '~*';
    }

    params.push(sqlVal);
    conditions.push(`${cast} ${op} $${idx}`);
  }

  return conditions.length === 1
    ? conditions[0]
    : `(${conditions.join(' OR ')})`;
}

function buildGroup(
  groupKey:  string,
  groupVal:  unknown,
  params:    unknown[],
): string {

  if (groupKey === 'keywords') {
    const terms = Array.isArray(groupVal) ? groupVal : [groupVal];
    const clauses: string[] = [];
    for (const term of terms) {
      const idx = params.length + 1;
      params.push(`%${term}%`);
      clauses.push(`description ILIKE $${idx}`);
    }
    return clauses.length === 1 ? clauses[0] : `(${clauses.join(' OR ')})`;
  }

  if (typeof groupVal === 'object' && groupVal !== null && !Array.isArray(groupVal)) {
    const map = groupVal as Record<string, unknown>;
    const fieldClauses: string[] = [];
    for (const [key, val] of Object.entries(map)) {
      const { field, mods } = splitField(key);
      const values = Array.isArray(val) ? val : [val];
      fieldClauses.push(fieldCondition(field, mods, values, params));
    }
    if (fieldClauses.length === 0) return 'TRUE';
    return fieldClauses.length === 1
      ? fieldClauses[0]
      : `(${fieldClauses.join(' AND ')})`;
  }

  return 'TRUE';
}

export function buildQuery(rule: SigmaRule): BuildQueryResult {
  const detection = rule.detection;
  const condition = String(detection['condition'] ?? '').trim().toLowerCase();
  const params: unknown[] = [];

  const groupSql: Record<string, string> = {};
  for (const [key, val] of Object.entries(detection)) {
    if (key === 'condition') continue;
    groupSql[key] = buildGroup(key, val, params);
  }

  let where: string;

  if (condition === 'selection') {
    where = groupSql['selection'] ?? 'TRUE';
  } else if (condition === 'keywords') {
    where = groupSql['keywords'] ?? 'TRUE';
  } else if (condition === 'selection and not filter') {
    const sel = groupSql['selection'] ?? 'TRUE';
    const flt = groupSql['filter']    ?? 'FALSE';
    where = `(${sel}) AND NOT (${flt})`;
  } else if (condition === 'selection or keywords') {
    const sel = groupSql['selection'] ?? 'FALSE';
    const kw  = groupSql['keywords']  ?? 'FALSE';
    where = `(${sel}) OR (${kw})`;
  } else {

    const parts = Object.values(groupSql);
    where = parts.length > 0 ? parts.join(' AND ') : 'TRUE';
  }

  return { where, params };
}
