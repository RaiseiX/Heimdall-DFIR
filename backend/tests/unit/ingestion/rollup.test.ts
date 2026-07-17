process.env.JWT_SECRET = 'test-secret-for-unit-tests';

jest.mock('../../../src/config/queue', () => ({
  createRedisConnection: jest.fn(() => ({})),
  parserQueue: { add: jest.fn() },
  ingestionQueue: { add: jest.fn() },
}));
jest.mock('../../../src/config/database', () => ({
  pool: { query: jest.fn().mockResolvedValue({ rows: [] }) },
}));
jest.mock('../../../src/services/parserService', () => ({
  getAvailableTools: jest.fn(() => ({})),
}));

import { rollupCounts } from '../../../src/routes/parsers-stream';

it('keeps degraded/empty/quarantined distinct (no green-washing)', () => {
  const r = rollupCounts([{ status: 'parsed', n: 3 }, { status: 'degraded', n: 1 }, { status: 'quarantined', n: 2 }, { status: 'skipped_duplicate', n: 5 }]);
  expect(r).toEqual({ parsed: 3, degraded: 1, quarantined: 2, skipped_duplicate: 5 });
  expect(r.degraded).not.toBe(0);
});
