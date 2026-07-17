jest.mock('../../../src/config/queue', () => ({
  createRedisConnection: jest.fn(() => ({})),
  parserQueue: { add: jest.fn() },
  ingestionQueue: { add: jest.fn() },
}));

import { processIngestion } from '../../../src/workers/ingestionWorker';

it('enqueues one parser job per parser for new files, skips duplicates and unknowns', async () => {
  const enqueued: any[] = [];
  const deps = {
    isArchive: () => false,
    extractZip: async () => ({ entries: 0, bytes: 0 }),
    walk: async function* () {
      yield { relativePath: '$MFT',   absPath: '/x/$MFT',  size: 1, sha256: 'a'.repeat(64), header: Buffer.from('FILE0') };
      yield { relativePath: 'dup.pf', absPath: '/x/dup.pf',size: 1, sha256: 'b'.repeat(64), header: Buffer.alloc(0) };
      yield { relativePath: 'junk',   absPath: '/x/junk',  size: 1, sha256: 'c'.repeat(64), header: Buffer.from('\x00\x00') };
    },
    classify: (i: any) => i.relativePath === '$MFT' ? { detectedType: 'mft', parser: 'mft', parserVersion: '1', confidence: 95, reasons: [] }
      : i.relativePath === 'dup.pf' ? { detectedType: 'prefetch', parser: 'prefetch', parserVersion: '1', confidence: 80, reasons: [] }
      : { detectedType: 'unknown', parser: null, parserVersion: null, confidence: 10, reasons: [] },
    checkAndRecord: async (_p: any, input: any) => ({ ingestionFileId: 'id-' + input.relativePath, isDuplicate: input.relativePath === 'dup.pf', quarantined: input.parserName === null }),
    parserEnqueue: async (data: any) => { enqueued.push(data); },
    finalize: async () => true,
    pool: { query: async () => ({ rows: [] }) } as any,
    stageFile: async () => {},
  };
  await processIngestion({ evidenceId: 'ev', caseId: 'cs', userId: 'u', uploadPath: '/x', evidenceType: 'windows', socketId: 's' }, deps as any);
  expect(enqueued).toHaveLength(1);                 // only mft; prefetch was duplicate, junk quarantined
  expect(enqueued[0].parser).toBe('mft');
  expect(enqueued[0].extraArgs.ingestionFileIds).toContain('id-$MFT');
});

// FIX E: extraction/walk failures must never leave the evidence stuck
// non-terminal. On failure, processIngestion must record ONE error
// ingestion_files row and call finalize, instead of letting the error
// propagate out of the job with zero rows recorded.
describe('extraction/walk failure path', () => {
  function baseDeps(overrides: Partial<Record<string, any>> = {}) {
    const queries: any[] = [];
    const finalizeCalls: any[] = [];
    return {
      isArchive: () => true,
      extractZip: async () => { throw new Error('cannot open zip: bad archive'); },
      walk: async function* () { /* not reached in the extractZip-throws case */ },
      classify: () => ({ detectedType: 'unknown', parser: null, parserVersion: null, confidence: 0, reasons: [] }),
      checkAndRecord: async () => ({ ingestionFileId: 'unused', isDuplicate: false, quarantined: false }),
      parserEnqueue: async () => { throw new Error('parserEnqueue should not be called on the failure path'); },
      finalize: async (_p: any, evidenceId: string, caseId: string) => { finalizeCalls.push({ evidenceId, caseId }); return true; },
      pool: { query: async (sql: string, params: any[]) => { queries.push({ sql, params }); return { rows: [] }; } } as any,
      stageFile: async () => {},
      __queries: queries,
      __finalizeCalls: finalizeCalls,
      ...overrides,
    };
  }

  it('records an error ingestion_files row and finalizes when extractZip throws', async () => {
    const deps = baseDeps();
    await processIngestion(
      { evidenceId: 'ev1', caseId: 'cs1', userId: 'u', uploadPath: '/x/upload.zip', evidenceType: 'other', socketId: 's' },
      deps as any,
    );

    const insertCall = deps.__queries.find((q: any) => /INSERT INTO ingestion_files/.test(q.sql));
    expect(insertCall).toBeDefined();
    expect(insertCall.sql).toMatch(/status_detail/);
    expect(insertCall.sql).toMatch(/'error'/);   // status is a literal in the SQL, not a bound param
    expect(insertCall.params.some((p: any) => typeof p === 'string' && p.includes('cannot open zip'))).toBe(true);

    expect(deps.__finalizeCalls).toEqual([{ evidenceId: 'ev1', caseId: 'cs1' }]);
  });

  it('records an error row and finalizes when the walk loop throws', async () => {
    const deps = baseDeps({
      isArchive: () => false,
      // eslint-disable-next-line require-yield
      walk: async function* () { throw new Error('ENOTDIR: not a directory'); },
    });
    await processIngestion(
      { evidenceId: 'ev2', caseId: 'cs2', userId: 'u', uploadPath: '/x/upload', evidenceType: 'other', socketId: 's' },
      deps as any,
    );

    const insertCall = deps.__queries.find((q: any) => /INSERT INTO ingestion_files/.test(q.sql));
    expect(insertCall).toBeDefined();
    expect(insertCall.sql).toMatch(/'error'/);
    expect(insertCall.params.some((p: any) => typeof p === 'string' && p.includes('ENOTDIR'))).toBe(true);
    expect(deps.__finalizeCalls).toEqual([{ evidenceId: 'ev2', caseId: 'cs2' }]);
  });

  it('never leaves the evidence with zero ingestion_files rows on failure (terminal-state guarantee)', async () => {
    const deps = baseDeps();
    await processIngestion(
      { evidenceId: 'ev3', caseId: 'cs3', userId: 'u', uploadPath: '/x/upload.zip', evidenceType: 'other', socketId: 's' },
      deps as any,
    );
    const inserts = deps.__queries.filter((q: any) => /INSERT INTO ingestion_files/.test(q.sql));
    expect(inserts.length).toBeGreaterThanOrEqual(1);
  });
});
