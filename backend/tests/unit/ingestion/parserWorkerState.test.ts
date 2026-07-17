jest.mock('../../../src/config/queue', () => ({
  createRedisConnection: jest.fn(() => ({})),
  parserQueue: { add: jest.fn() },
  ingestionQueue: { add: jest.fn() },
}));

jest.mock('../../../src/services/soarService', () => ({
  runSoarAsync: jest.fn(),
}));

// parserService.ts transitively imports uploadService.ts, which registers an
// unref'd-nothing setInterval at module scope for upload-session cleanup.
// Fake timers keep that interval from ever becoming a real Node timer, so it
// can't hold the process open after this suite's tests complete.
jest.useFakeTimers();

import { mapOutcomeToStatus } from '../../../src/workers/parserWorker';

afterAll(() => {
  jest.useRealTimers();
});

describe('mapOutcomeToStatus', () => {
  it('maps a clean parse with records to parsed', () => expect(mapOutcomeToStatus(1200, false)).toBe('parsed'));
  it('maps zero records to empty', () => expect(mapOutcomeToStatus(0, false)).toBe('empty'));
  it('maps a failed run to error', () => expect(mapOutcomeToStatus(0, true)).toBe('error'));
  it('maps records + failure flag to degraded', () => expect(mapOutcomeToStatus(50, true)).toBe('degraded'));
});
