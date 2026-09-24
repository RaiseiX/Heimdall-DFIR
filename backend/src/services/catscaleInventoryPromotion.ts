export const PROMOTED_COLUMNS = ['"path"', 'sha1', 'file_size', 'ext'];

export function promotionSql(alias: string): string {
  return [
    `NULLIF(${alias}.raw->>'path', '')`,
    `CASE WHEN ${alias}.raw->>'sha1' ~ '^[0-9a-fA-F]{40}$' THEN lower(${alias}.raw->>'sha1') END`,
    `CASE WHEN ${alias}.raw->>'file_size' ~ '^[0-9]+$' THEN (${alias}.raw->>'file_size')::bigint END`,
    `NULLIF(left(lower(${alias}.raw->>'ext'), 16), '')`,
  ].join(',\n');
}
