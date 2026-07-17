// parserService.ts transitively imports uploadService.ts, which registers an
// unref'd-nothing setInterval at module scope for upload-session cleanup.
// Fake timers keep that interval from ever becoming a real Node timer, so it
// can't hold the process open after this suite's tests complete (same
// pattern as parserWorkerState.test.ts).
jest.useFakeTimers();

import { runParser } from '../../../src/services/parserService';

afterAll(() => {
  jest.useRealTimers();
});

function fakeIo() {
  const events: Array<{ socketId: string; event: string; data: unknown }> = [];
  return {
    events,
    io: {
      to: (socketId: string) => ({
        emit: (event: string, data: unknown) => { events.push({ socketId, event, data }); },
      }),
    } as any,
  };
}

describe('runParser — unhandled parser name', () => {
  it('throws (signals failure) on the ingestion path when extraArgs.ingestionFileIds is present', async () => {
    const { io } = fakeIo();
    const pool = { query: jest.fn() } as any;

    await expect(
      runParser(
        {
          // pcap/webcache/bash_history/syslog are classifier-emitted (see
          // ingestion/signals.ts) AND now registered in PYTHON_PARSERS
          // (parserService.ts), so they no longer exercise this guard — use a
          // name that stays genuinely unknown to both ZIMMERMAN_TOOLS and
          // PYTHON_PARSERS.
          parser: 'definitely_not_a_parser',
          evidenceId: 'ev1',
          caseId: 'cs1',
          userId: 'u1',
          socketId: 's1',
          extraArgs: { ingestionFileIds: JSON.stringify(['if1']), stagingDir: '/tmp/staged' },
        },
        io,
        pool,
      ),
    ).rejects.toThrow(/Parseur inconnu/);

    // Must fail BEFORE touching the DB (no evidence lookup, no parser_results insert).
    expect(pool.query).not.toHaveBeenCalled();
  });

  it('returns 0 (unchanged legacy behavior) on the non-ingestion path (no extraArgs.ingestionFileIds)', async () => {
    const { io } = fakeIo();
    // Existing collection flow never calls runParser with an unknown parser
    // name, but this guards the byte-for-byte-unchanged contract regardless.
    // Must stay genuinely unknown (see comment above) — pool.query must NOT
    // be called, since a truly-unknown parser returns at the guard before
    // any DB lookup.
    const pool = { query: jest.fn() } as any;

    await expect(
      runParser(
        {
          parser: 'definitely_not_a_parser',
          evidenceId: 'ev1',
          caseId: 'cs1',
          userId: 'u1',
          socketId: 's1',
          extraArgs: {},
        },
        io,
        pool,
      ),
    ).resolves.toBe(0);
    expect(pool.query).not.toHaveBeenCalled();
  });
});
