// parserService.ts transitively imports uploadService.ts, which registers an
// unref'd-nothing setInterval at module scope for upload-session cleanup.
// Fake timers keep that interval from ever becoming a real Node timer, so it
// can't hold the process open after this suite's tests complete (same
// pattern as parserWorkerState.test.ts / runParserUnknown.test.ts).
jest.useFakeTimers();

import fs from 'fs';
import os from 'os';
import path from 'path';
import { buildPythonCommands, PYTHON_PARSERS, runParser } from '../../../src/services/parserService';

afterAll(() => {
  jest.useRealTimers();
});

test('dir-mode builds one python3 command with -d and the registry csvf', () => {
  const cmds = buildPythonCommands(PYTHON_PARSERS['syslog'], '/stage/syslog', '/out');
  expect(cmds).toEqual([{ binary: 'python3', args: ['/app/parsers/parse_syslog.py', '-d', '/stage/syslog', '--csv', '/out', '--csvf', 'syslog_results.csv'] }]);
});

test('pcap and bash_history are dir-mode', () => {
  expect(buildPythonCommands(PYTHON_PARSERS['pcap'], '/s', '/o')[0].args).toContain('-d');
  expect(buildPythonCommands(PYTHON_PARSERS['bash_history'], '/s', '/o')[0].args[0]).toBe('/app/parsers/parse_bash_history.py');
});

test('a genuinely unknown parser still throws on the ingestion path', async () => {
  await expect(runParser({ parser: 'definitely_not_a_parser', evidenceId: 'e', caseId: 'c', userId: 'u', socketId: 's', extraArgs: { ingestionFileIds: '["x"]' } } as any, { to: () => ({ emit() {} }) } as any, { query: async () => ({ rows: [] }) } as any)).rejects.toThrow(/inconnu/);
});

test('webcache file-mode builds one -f command per staged file with distinct --csvf', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wc-'));
  fs.writeFileSync(path.join(dir, 'WebCacheV01.dat'), 'x');
  fs.writeFileSync(path.join(dir, 'host2.dat'), 'y');
  const cmds = buildPythonCommands(PYTHON_PARSERS['webcache'], dir, '/out');
  expect(cmds.length).toBe(2);
  for (const c of cmds) { expect(c.args).toContain('-f'); expect(c.args[c.args.indexOf('--csvf') + 1]).toMatch(/-webcache_results\.csv$/); }
  const csvfs = cmds.map(c => c.args[c.args.indexOf('--csvf') + 1]);
  expect(new Set(csvfs).size).toBe(2);   // distinct per file
  fs.rmSync(dir, { recursive: true, force: true });
});
