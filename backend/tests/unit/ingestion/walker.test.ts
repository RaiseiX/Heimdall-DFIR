// backend/tests/unit/ingestion/walker.test.ts
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { walk } from '../../../src/services/ingestion/walker';

it('walks recursively and hashes each file', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'walk-'));
  fs.mkdirSync(path.join(root, 'sub'));
  fs.writeFileSync(path.join(root, 'sub', 'a.txt'), 'hello');
  const seen: Record<string, string> = {};
  for await (const f of walk(root)) seen[f.relativePath] = f.sha256;
  // sha256('hello')
  expect(seen['sub/a.txt']).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
});
