import { buildTextFilter, buildSearchFilter, pushTextFilter, pushSearchFilter } from '../../../src/utils/textFilter';

describe('buildTextFilter', () => {
  const col = 'host_name';

  test.each([
    ['contains',     'foo', { sql: 'host_name ILIKE $N',     param: '%foo%' }],
    ['not_contains', 'foo', { sql: 'host_name NOT ILIKE $N', param: '%foo%' }],
    ['equals',       'foo', { sql: 'host_name ILIKE $N',     param: 'foo'   }],
    ['not_equals',   'foo', { sql: 'host_name NOT ILIKE $N', param: 'foo'   }],
    ['starts_with',  'foo', { sql: 'host_name ILIKE $N',     param: 'foo%'  }],
    ['ends_with',    'foo', { sql: 'host_name ILIKE $N',     param: '%foo'  }],
    ['regex',        'foo', { sql: 'host_name ~* $N',        param: 'foo'   }],
  ])('op=%s produces correct sql+param', (op, value, expected) => {
    expect(buildTextFilter(col, value, op)).toEqual(expected);
  });

  test('empty returns null param', () => {
    expect(buildTextFilter(col, '', 'empty')).toEqual({
      sql: "(host_name IS NULL OR host_name = '')",
      param: null,
    });
  });

  test('not_empty returns null param', () => {
    expect(buildTextFilter(col, '', 'not_empty')).toEqual({
      sql: "(host_name IS NOT NULL AND host_name != '')",
      param: null,
    });
  });

  test('unknown op falls back to contains', () => {
    expect(buildTextFilter(col, 'x', 'badop')).toEqual({
      sql: 'host_name ILIKE $N',
      param: '%x%',
    });
  });

  test('escapes SQL wildcards in value', () => {
    const { param } = buildTextFilter(col, 'foo%bar_baz', 'contains');
    expect(param).toBe('%foo\\%bar\\_baz%');
  });
});

describe('buildSearchFilter', () => {
  test('contains wraps in OR across 3 columns', () => {
    const { sql, param } = buildSearchFilter('admin', 'contains');
    expect(sql).toBe('(description ILIKE $N OR source ILIKE $N OR artifact_type ILIKE $N)');
    expect(param).toBe('%admin%');
  });

  test('not_contains uses AND NOT across 3 columns', () => {
    const { sql, param } = buildSearchFilter('admin', 'not_contains');
    expect(sql).toBe('(description NOT ILIKE $N AND source NOT ILIKE $N AND artifact_type NOT ILIKE $N)');
    expect(param).toBe('%admin%');
  });

  test('not_equals uses AND NOT across 3 columns', () => {
    const { sql, param } = buildSearchFilter('Logon', 'not_equals');
    expect(sql).toBe('(description NOT ILIKE $N AND source NOT ILIKE $N AND artifact_type NOT ILIKE $N)');
    expect(param).toBe('Logon');
  });

  test('ends_with produces correct param', () => {
    const { param } = buildSearchFilter('.exe', 'ends_with');
    expect(param).toBe('%.exe');
  });

  test('empty targets description only, null param', () => {
    const { sql, param } = buildSearchFilter('', 'empty');
    expect(sql).toBe("(description IS NULL OR description = '')");
    expect(param).toBeNull();
  });

  test('not_empty targets description only, null param', () => {
    const { sql, param } = buildSearchFilter('', 'not_empty');
    expect(sql).toBe("(description IS NOT NULL AND description != '')");
    expect(param).toBeNull();
  });

  test('regex uses ~* operator', () => {
    const { sql, param } = buildSearchFilter('^cmd', 'regex');
    expect(sql).toBe('(description ~* $N OR source ~* $N OR artifact_type ~* $N)');
    expect(param).toBe('^cmd');
  });
});

describe('pushTextFilter', () => {
  test('increments pi and appends condition + param for value-bearing ops', () => {
    const conditions: string[] = [];
    const params: unknown[] = [];
    const newPi = pushTextFilter('host_name', 'CORP', 'starts_with', 2, conditions, params);
    expect(newPi).toBe(3);
    expect(conditions).toEqual(['host_name ILIKE $2']);
    expect(params).toEqual(['CORP%']);
  });

  test('does NOT increment pi for empty op (no param)', () => {
    const conditions: string[] = [];
    const params: unknown[] = [];
    const newPi = pushTextFilter('host_name', '', 'empty', 2, conditions, params);
    expect(newPi).toBe(2);
    expect(conditions).toEqual(["(host_name IS NULL OR host_name = '')"]);
    expect(params).toHaveLength(0);
  });
});

describe('pushSearchFilter', () => {
  test('replaces all $N occurrences with the same pi', () => {
    const conditions: string[] = [];
    const params: unknown[] = [];
    const newPi = pushSearchFilter('cmd.exe', 'contains', 3, conditions, params);
    expect(newPi).toBe(4);
    expect(conditions[0]).toBe('(description ILIKE $3 OR source ILIKE $3 OR artifact_type ILIKE $3)');
    expect(params).toEqual(['%cmd.exe%']);
  });

  test('not_empty adds condition without consuming pi', () => {
    const conditions: string[] = [];
    const params: unknown[] = [];
    const newPi = pushSearchFilter('', 'not_empty', 2, conditions, params);
    expect(newPi).toBe(2);
    expect(conditions[0]).toBe("(description IS NOT NULL AND description != '')");
    expect(params).toHaveLength(0);
  });
});
