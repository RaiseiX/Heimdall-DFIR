export const VALID_TEXT_OPS = new Set([
  'contains', 'not_contains', 'equals', 'not_equals',
  'starts_with', 'ends_with', 'regex', 'empty', 'not_empty',
]);

/** `col` must be a trusted compile-time constant — never pass user-supplied column names. */
export function buildTextFilter(
  col: string,
  value: string,
  op: string,
): { sql: string; param: string | null } {
  const safeOp = VALID_TEXT_OPS.has(op) ? op : 'contains';
  const safe   = String(value ?? '').replace(/[%_]/g, '\\$&');
  switch (safeOp) {
    case 'not_contains': return { sql: `${col} NOT ILIKE $N`, param: '%' + safe + '%' };
    case 'equals':       return { sql: `${col} ILIKE $N`,     param: safe              };
    case 'not_equals':   return { sql: `${col} NOT ILIKE $N`, param: safe              };
    case 'starts_with':  return { sql: `${col} ILIKE $N`,     param: safe + '%'        };
    case 'ends_with':    return { sql: `${col} ILIKE $N`,     param: '%' + safe        };
    case 'regex':        return { sql: `${col} ~* $N`,        param: String(value ?? '') };
    case 'empty':        return { sql: `(${col} IS NULL OR ${col} = '')`,               param: null };
    case 'not_empty':    return { sql: `(${col} IS NOT NULL AND ${col} != '')`,         param: null };
    default:             return { sql: `${col} ILIKE $N`,     param: '%' + safe + '%' };
  }
}

/**
 * Multi-column search filter. Covers the free-text columns plus the forensic
 * identity columns analysts search for (event_id, host, user, tool, path…), so
 * typing e.g. "600" finds every EVTX row with event_id 600 even when the
 * description doesn't contain the number.
 * Positive ops use OR; negative ops use AND NOT.
 * `empty`/`not_empty` target `description` only (the primary meaningful field).
 */
const SEARCH_COLS = [
  'description',
  'source',
  'artifact_type',
  'event_id::text',
  'host_name',
  'user_name',
  'tool',
  'details',
  '"path"',
  'ext',
  'process_name',
];

const SEARCH_OR  = (op: string) => SEARCH_COLS.map(c => `${c} ${op} $N`).join(' OR ');
const SEARCH_AND = (op: string) => SEARCH_COLS.map(c => `${c} ${op} $N`).join(' AND ');

export function buildSearchFilter(
  value: string,
  op: string,
): { sql: string; param: string | null } {
  const safeOp = VALID_TEXT_OPS.has(op) ? op : 'contains';
  const safe   = String(value ?? '').replace(/[%_]/g, '\\$&');
  switch (safeOp) {
    case 'not_contains':
      return { sql: `(${SEARCH_AND('NOT ILIKE')})`, param: '%' + safe + '%' };
    case 'not_equals':
      return { sql: `(${SEARCH_AND('NOT ILIKE')})`, param: safe };
    case 'equals':
      return { sql: `(${SEARCH_OR('ILIKE')})`,       param: safe };
    case 'starts_with':
      return { sql: `(${SEARCH_OR('ILIKE')})`,       param: safe + '%' };
    case 'ends_with':
      return { sql: `(${SEARCH_OR('ILIKE')})`,       param: '%' + safe };
    case 'regex':
      return { sql: `(${SEARCH_OR('~*')})`,          param: String(value ?? '') };
    case 'empty':
      return { sql: "(description IS NULL OR description = '')",         param: null };
    case 'not_empty':
      return { sql: "(description IS NOT NULL AND description != '')",   param: null };
    default: // contains
      return { sql: `(${SEARCH_OR('ILIKE')})`,       param: '%' + safe + '%' };
  }
}

export function pushTextFilter(
  col: string,
  value: string,
  op: string,
  pi: number,
  conditions: string[],
  params: unknown[],
): number {
  const { sql, param } = buildTextFilter(col, value, op);
  if (param !== null) {
    conditions.push(sql.replace('$N', `$${pi}`));
    params.push(param);
    return pi + 1;
  }
  conditions.push(sql);
  return pi;
}

export function pushSearchFilter(
  value: string,
  op: string,
  pi: number,
  conditions: string[],
  params: unknown[],
): number {
  const { sql, param } = buildSearchFilter(value, op);
  if (param !== null) {
    conditions.push(sql.replace(/\$N/g, `$${pi}`));
    params.push(param);
    return pi + 1;
  }
  conditions.push(sql);
  return pi;
}
