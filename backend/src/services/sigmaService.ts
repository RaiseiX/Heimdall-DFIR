
import yaml from 'js-yaml';

export interface SigmaRule {
  title:       string;
  description?: string;
  logsource?:  { category?: string; product?: string; service?: string };
  detection:   Record<string, unknown>;
  tags?:       string[];
  level?:      string;
  status?:     string;
}

export interface BuildQueryResult {
  where:  string;
  params: unknown[];
}

// Sigma's `level:` field. A value outside this set (typo, or absent) is
// reported as `undefined` by parseRule — never guessed or defaulted — so it
// lands as SQL NULL on sigma_rules.level.
const SIGMA_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'informational']);

// Sigma's own `status:` field (upstream lifecycle, not import provenance).
// Same non-guessing rule as SIGMA_LEVELS.
const SIGMA_STATUSES = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);

function normalizeEnum(value: unknown, allowed: Set<string>): string | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim().toLowerCase();
  return allowed.has(v) ? v : undefined;
}

// A Sigma rule's `tags:` list mixes four unrelated ATT&CK reference kinds
// under one `attack.` prefix:
//   attack.t1546.004    -> sub-technique   (KEEP)
//   attack.t1546        -> technique       (KEEP)
//   attack.persistence   -> tactic          (discard)
//   attack.s0003         -> software/tool   (discard — Sigma numbers these s\d+)
//   attack.g0007         -> intrusion group (discard — g\d+)
//   attack.c0001         -> campaign        (discard — c\d+)
// Only `attack.t####` / `attack.t####.###` matches a technique or
// sub-technique, so anchoring on that prefix separates techniques from the
// other three kinds without needing a tactic/software denylist that would
// go stale as SigmaHQ's tag vocabulary grows.
//
// For a sub-technique, BOTH the sub-technique and its parent are returned
// (uppercased 'T' form) so a query scoped to the parent technique also finds
// rules tagged only with a sub-technique of it.
const TECHNIQUE_TAG_RE = /^attack\.t(\d{4})(?:\.(\d{3}))?$/i;

export function extractMitreTechniques(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  const result: string[] = [];
  const seen = new Set<string>();
  for (const tag of tags) {
    if (typeof tag !== 'string') continue;
    const m = tag.trim().match(TECHNIQUE_TAG_RE);
    if (!m) continue;
    const base = `T${m[1]}`;
    const sub  = m[2] ? `${base}.${m[2]}` : null;
    if (sub && !seen.has(sub)) { seen.add(sub); result.push(sub); }
    if (!seen.has(base)) { seen.add(base); result.push(base); }
  }
  return result;
}

export function parseRule(content: string): {
  valid:   boolean;
  parsed?: SigmaRule;
  error?:  string;
  logsourceCategory?: string;
  logsourceProduct?:  string;
  level?:             string;
  mitreTechniques?:   string[];
  upstreamStatus?:    string;
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
    level:              normalizeEnum(rule['level'], SIGMA_LEVELS),
    mitreTechniques:    extractMitreTechniques(rule['tags']),
    upstreamStatus:     normalizeEnum(rule['status'], SIGMA_STATUSES),
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
