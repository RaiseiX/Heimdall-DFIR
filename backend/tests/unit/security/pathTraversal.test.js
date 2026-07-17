const path = require('path');
const { safeBasename } = require('../../../src/services/uploadService');
const BASE = '/app/collections/case-1';

function underBase(base, name) {
  const resolvedBase = path.resolve(base);
  const p = path.resolve(base, safeBasename(name));
  return p === resolvedBase || p.startsWith(resolvedBase + path.sep);
}

const attacks = ['../../../etc/passwd', '../../secret', '..', '.', '/etc/shadow', 'foo/../../bar', 'a/b/c.txt'];

test('collection upload: safeBasename(originalname) stays under the collection dir', () => {
  for (const a of attacks) expect(underBase(BASE, a)).toBe(true);
});
test('evidence multi-file + volweb: safeBasename(userName) stays confined', () => {
  for (const a of attacks) {
    const staged = `1234-${safeBasename(a)}`;          // the "${suffix}-${basename}" pattern
    expect(path.resolve(BASE, staged).startsWith(path.resolve(BASE) + path.sep)).toBe(true);
  }
});
test('WITHOUT safeBasename, the raw pattern escapes (proves the fix matters)', () => {
  const p = path.resolve(BASE, '../../../etc/passwd');
  expect(p.startsWith(path.resolve(BASE) + path.sep)).toBe(false);   // vulnerable pattern escapes
});
