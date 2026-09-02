
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
  unsupported: string | null;
  fields: string[];
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

const EVENT_DATA_CONTAINER = 'AllFieldInfo';
const SAFE_FIELD = /^[A-Za-z0-9_.-]+$/;

export function isSafeFieldName(field: string): boolean {
  return typeof field === 'string' && field.length > 0 && SAFE_FIELD.test(field);
}

export function fieldExpr(field: string): string {
  return `COALESCE(raw->>'${field}', raw->'${EVENT_DATA_CONTAINER}'->>'${field}')`;
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
    let cast  = fieldExpr(field);

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
  fields?:   Set<string>,
): string | null {

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

  if (Array.isArray(groupVal) && groupVal.length > 0
      && groupVal.every(v => typeof v === 'object' && v !== null && !Array.isArray(v))) {
    const variantes: string[] = [];
    for (const variante of groupVal) {
      const sql = buildGroup(groupKey, variante, params, fields);
      if (sql === null) return null;
      variantes.push(`(${sql})`);
    }
    return variantes.length === 1 ? variantes[0] : `(${variantes.join(' OR ')})`;
  }

  if (typeof groupVal === 'object' && groupVal !== null && !Array.isArray(groupVal)) {
    const map = groupVal as Record<string, unknown>;
    const fieldClauses: string[] = [];
    for (const [key, val] of Object.entries(map)) {
      const { field, mods } = splitField(key);
      if (!isSafeFieldName(field)) return null;
      fields?.add(field);
      const values = Array.isArray(val) ? val : [val];
      fieldClauses.push(fieldCondition(field, mods, values, params));
    }
    if (fieldClauses.length === 0) return null;
    return fieldClauses.length === 1
      ? fieldClauses[0]
      : `(${fieldClauses.join(' AND ')})`;
  }

  return null;
}


type CondNode =
  | { k: 'group'; name: string }
  | { k: 'quant'; mode: 'all' | 'one'; pattern: string }
  | { k: 'not'; on: CondNode }
  | { k: 'and'; left: CondNode; right: CondNode }
  | { k: 'or'; left: CondNode; right: CondNode };

export interface ConditionSql { sql?: string; error?: string }

function tokenize(condition: string): string[] | null {
  const cleaned = String(condition ?? '').trim().toLowerCase();
  if (!cleaned) return null;
  if (!/^[a-z0-9_*() ]+$/.test(cleaned)) return null;
  const spaced = cleaned.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ');
  const toks = spaced.split(/\s+/).filter(Boolean);
  return toks.length ? toks : null;
}

function parseCondition(toks: string[]): { node: CondNode; rest: string[] } | null {
  const parseOr = (t: string[]): { node: CondNode; rest: string[] } | null => {
    let left = parseAnd(t);
    if (!left) return null;
    while (left.rest[0] === 'or') {
      const right = parseAnd(left.rest.slice(1));
      if (!right) return null;
      left = { node: { k: 'or', left: left.node, right: right.node }, rest: right.rest };
    }
    return left;
  };
  const parseAnd = (t: string[]): { node: CondNode; rest: string[] } | null => {
    let left = parseNot(t);
    if (!left) return null;
    while (left.rest[0] === 'and') {
      const right = parseNot(left.rest.slice(1));
      if (!right) return null;
      left = { node: { k: 'and', left: left.node, right: right.node }, rest: right.rest };
    }
    return left;
  };
  const parseNot = (t: string[]): { node: CondNode; rest: string[] } | null => {
    if (t[0] === 'not') {
      const inner = parseNot(t.slice(1));
      return inner ? { node: { k: 'not', on: inner.node }, rest: inner.rest } : null;
    }
    return parseAtom(t);
  };
  const parseAtom = (t: string[]): { node: CondNode; rest: string[] } | null => {
    if (!t.length) return null;
    if (t[0] === '(') {
      const inner = parseOr(t.slice(1));
      if (!inner || inner.rest[0] !== ')') return null;
      return { node: inner.node, rest: inner.rest.slice(1) };
    }
    if ((t[0] === 'all' || /^\d+$/.test(t[0])) && t[1] === 'of' && t[2]) {
      if (t[0] !== 'all' && t[0] !== '1') return null;
      return { node: { k: 'quant', mode: t[0] === 'all' ? 'all' : 'one', pattern: t[2] }, rest: t.slice(3) };
    }
    if (/^[a-z0-9_]+$/.test(t[0])) return { node: { k: 'group', name: t[0] }, rest: t.slice(1) };
    return null;
  };
  return parseOr(toks);
}

function matchGroups(pattern: string, groups: Record<string, string>): string[] {
  const names = Object.keys(groups);
  if (pattern === 'them') return names;
  if (!pattern.includes('*')) return names.filter(n => n === pattern);
  const re = new RegExp('^' + pattern.split('*').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
  return names.filter(n => re.test(n));
}

function emit(node: CondNode, groups: Record<string, string>): string | null {
  switch (node.k) {
    case 'group':
      return groups[node.name] ?? null;
    case 'not': {
      const on = emit(node.on, groups);
      return on === null ? null : `NOT (${on})`;
    }
    case 'and': {
      const l = emit(node.left, groups); const r = emit(node.right, groups);
      return l === null || r === null ? null : `(${l}) AND (${r})`;
    }
    case 'or': {
      const l = emit(node.left, groups); const r = emit(node.right, groups);
      return l === null || r === null ? null : `(${l}) OR (${r})`;
    }
    case 'quant': {
      const names = matchGroups(node.pattern, groups);
      if (!names.length) return null;
      const parts = names.map(n => groups[n]);
      if (parts.some(p => p == null)) return null;
      return `(${parts.map(p => `(${p})`).join(node.mode === 'all' ? ' AND ' : ' OR ')})`;
    }
  }
}

export function conditionToSql(condition: string, groups: Record<string, string>): ConditionSql {
  const toks = tokenize(condition);
  if (!toks) return { error: `condition illisible : ${condition || '(absente)'}` };
  const parsed = parseCondition(toks);
  if (!parsed || parsed.rest.length) return { error: `condition non analysable : ${condition}` };
  const sql = emit(parsed.node, groups);
  if (sql === null) return { error: `condition « ${condition} » : groupe attendu absent ou non compilable` };
  return { sql };
}

export function buildQuery(rule: SigmaRule): BuildQueryResult {
  const detection = rule?.detection ?? {};
  const condition = String(detection['condition'] ?? '').trim().toLowerCase();
  const params: unknown[] = [];

  const refuse = (reason: string): BuildQueryResult =>
    ({ where: 'FALSE', params: [], unsupported: reason, fields: [] });

  const fields = new Set<string>();

  const groupSql: Record<string, string | null> = {};
  for (const [key, val] of Object.entries(detection)) {
    if (key === 'condition') continue;
    groupSql[key] = buildGroup(key, val, params, fields);
  }

  const unreadable = Object.entries(groupSql).filter(([, sql]) => sql === null).map(([k]) => k);
  if (unreadable.length) return refuse(`groupe non compilable : ${unreadable.join(', ')}`);

  const compilables: Record<string, string> = {};
  for (const [k, v] of Object.entries(groupSql)) if (v !== null) compilables[k] = v;

  const out = conditionToSql(condition, compilables);
  if (out.error || !out.sql) return refuse(out.error || `condition non compilable : ${condition}`);
  const where = out.sql;

  return { where, params, unsupported: null, fields: [...fields] };
}

export function unreachableFields(fields: string[], present: Set<string> | null | undefined): string[] | null {
  if (!fields || fields.length === 0) return null;
  if (!present || present.size === 0) return null;
  if (fields.some(f => present.has(f))) return null;
  return [...fields];
}

export function presentFieldsQuery(caseId: string, perType = 200, nestedRows = 20000): { text: string; values: unknown[] } {
  return {
    text: `WITH par_type AS (
             SELECT raw, row_number() OVER (PARTITION BY artifact_type) AS n
               FROM collection_timeline
              WHERE case_id = $1 AND raw IS NOT NULL
           ),
           imbrique AS (
             SELECT raw->'${EVENT_DATA_CONTAINER}' AS f
               FROM collection_timeline
              WHERE case_id = $1
                AND jsonb_typeof(raw->'${EVENT_DATA_CONTAINER}') = 'object'
              LIMIT $3
           )
           SELECT DISTINCT jsonb_object_keys(raw) AS champ FROM par_type WHERE n <= $2
           UNION
           SELECT DISTINCT jsonb_object_keys(f) AS champ FROM imbrique`,
    values: [caseId, perType, nestedRows],
  };
}
