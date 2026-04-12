
function getFieldValue(record, field) {
  if (field.startsWith('raw.')) {
    const key = field.slice(4);
    return record.raw?.[key] ?? null;
  }
  return record[field] ?? null;
}

function evalCondition(record, condition) {
  const { field, op, value, case_sensitive = false } = condition;
  const raw = getFieldValue(record, field);
  const val = raw === null || raw === undefined ? '' : String(raw);
  const v   = case_sensitive ? val : val.toLowerCase();
  const cmp = case_sensitive ? String(value ?? '') : String(value ?? '').toLowerCase();

  switch (op) {
    case 'contains':     return v.includes(cmp);
    case 'not_contains': return !v.includes(cmp);
    case 'equals':       return v === cmp;
    case 'not_equals':   return v !== cmp;
    case 'starts_with':  return v.startsWith(cmp);
    case 'ends_with':    return v.endsWith(cmp);
    case 'is_null':      return raw === null || raw === undefined || val === '';
    case 'is_not_null':  return raw !== null && raw !== undefined && val !== '';
    case 'in': {
      if (!Array.isArray(value)) return false;
      const items = case_sensitive ? value.map(String) : value.map(s => String(s).toLowerCase());
      return items.includes(v);
    }
    case 'not_in': {
      if (!Array.isArray(value)) return false;
      const items = case_sensitive ? value.map(String) : value.map(s => String(s).toLowerCase());
      return !items.includes(v);
    }
    case 'regex': {
      try {
        const flags = case_sensitive ? '' : 'i';
        return new RegExp(value, flags).test(val);
      } catch { return false; }
    }

    case 'off_hours': {
      if (field !== 'timestamp') return false;
      const h = new Date(raw).getUTCHours();
      return h < 7 || h >= 22;
    }
    default: return false;
  }
}

function evalConditions(record, conditions) {
  if (!conditions?.rules?.length) return false;
  const { operator = 'AND', rules } = conditions;
  if (operator === 'OR')  return rules.some(c  => evalCondition(record, c));
  return rules.every(c => evalCondition(record, c));
}

export function evaluateColorRules(record, rules) {
  for (const rule of rules) {
    if (!rule.is_active) continue;

    if (rule.name === 'Off-Hours Activity') {
      if (record.timestamp) {
        const h = new Date(record.timestamp).getUTCHours();
        if (h < 7 || h >= 22) {
          return { color: rule.color, icon: rule.icon ?? null, ruleName: rule.name, ruleId: rule.id };
        }
      }
      continue;
    }
    if (evalConditions(record, rule.conditions)) {
      return { color: rule.color, icon: rule.icon ?? null, ruleName: rule.name, ruleId: rule.id };
    }
  }
  return null;
}

export function sortRules(rules) {
  return [...rules].sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return new Date(a.created_at) - new Date(b.created_at);
  });
}

export function conditionToString(condition) {
  const { field, op, value } = condition;
  const fieldLabel = field.startsWith('raw.') ? field.slice(4) : field;
  const opLabel = {
    contains: 'contient', not_contains: 'ne contient pas',
    equals: '=', not_equals: '≠',
    starts_with: 'commence par', ends_with: 'finit par',
    regex: '~ regex', in: 'dans', not_in: 'pas dans',
    is_null: 'est vide', is_not_null: 'n\'est pas vide',
    off_hours: 'hors heures (avant 7h / après 22h)',
  }[op] ?? op;

  if (op === 'is_null' || op === 'is_not_null' || op === 'off_hours') {
    return `${fieldLabel} ${opLabel}`;
  }
  const valStr = Array.isArray(value) ? value.join(', ') : String(value ?? '');
  return `${fieldLabel} ${opLabel} "${valStr}"`;
}

export const RULE_FIELDS = [
  { value: 'description',         label: 'Description' },
  { value: 'artifact_type',       label: 'Type d\'artefact' },
  { value: 'source',              label: 'Source' },
  { value: 'host_name',           label: 'Machine (host_name)' },
  { value: 'user_name',           label: 'Utilisateur (user_name)' },
  { value: 'process_name',        label: 'Processus (process_name)' },
  { value: 'mitre_tactic',        label: 'MITRE Tactic' },
  { value: 'mitre_technique_id',  label: 'MITRE Technique ID' },
  { value: 'raw.level',           label: 'Hayabusa Level (raw.level)' },
  { value: 'raw.EventID',         label: 'EventID (raw.EventID)' },
  { value: 'raw.Channel',         label: 'Channel EVTX (raw.Channel)' },
  { value: 'timestamp',           label: 'Timestamp (hors heures)' },
];

export const RULE_OPS = [
  { value: 'contains',     label: 'contient' },
  { value: 'not_contains', label: 'ne contient pas' },
  { value: 'equals',       label: 'égal à' },
  { value: 'not_equals',   label: 'différent de' },
  { value: 'starts_with',  label: 'commence par' },
  { value: 'ends_with',    label: 'finit par' },
  { value: 'regex',        label: 'regex ~' },
  { value: 'in',           label: 'est dans (liste)' },
  { value: 'not_in',       label: 'n\'est pas dans (liste)' },
  { value: 'is_null',      label: 'est vide' },
  { value: 'is_not_null',  label: 'n\'est pas vide' },
  { value: 'off_hours',    label: 'hors horaires (< 7h ou ≥ 22h UTC)' },
];

export const RULE_COLORS = [
  '#EF4444', '#DC2626', '#B91C1C',
  '#F97316', '#EA580C', '#C2410C',
  '#EAB308', '#CA8A04', '#A16207',
  '#22C55E', '#16A34A',
  '#3B82F6', '#2563EB',
  '#A855F7', '#9333EA', '#7C3AED',
  '#06B6D4', '#0891B2',
  '#F43F5E', '#E11D48',
  '#64748B', '#475569',
];
