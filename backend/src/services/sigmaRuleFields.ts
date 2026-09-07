export const RULE_LIST_FIELDS: readonly string[] = [
  'id',
  'name',
  'logsource_category',
  'logsource_product',
  'tags',
  'level',
  'mitre_techniques',
  'upstream_status',
  'is_active',
  'created_at',
  'updated_at',
];

export const RULE_HEAVY_FIELDS: readonly string[] = ['content', 'description'];

export const JOINED_FIELDS: readonly string[] = ['author_username'];

const JOINED_SELECT = 'u.username AS author_username';

export function ruleSelect(withHeavy: boolean): string {
  const columns = withHeavy ? [...RULE_LIST_FIELDS, ...RULE_HEAVY_FIELDS] : RULE_LIST_FIELDS;
  return [...columns.map(c => `r.${c}`), JOINED_SELECT].join(', ');
}
