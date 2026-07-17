process.env.JWT_SECRET = 'test-secret-for-unit-tests';

// Mock heavy/side-effecting dependencies so upload.ts loads without DB/Redis/socket side effects
jest.mock('../../../src/config/database', () => ({
  pool: { query: jest.fn().mockResolvedValue({ rows: [] }) },
}));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: jest.fn(),
  requireRole: jest.fn(() => jest.fn()),
}));
jest.mock('../../../src/config/logger', () => ({
  default: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
}));
jest.mock('../../../src/services/uploadService', () => ({
  initUpload: jest.fn(),
  receiveChunk: jest.fn(),
  completeUpload: jest.fn(),
  getSessionStatus: jest.fn(),
}));
jest.mock('../../../src/services/clamavService', () => ({
  scanFile: jest.fn(),
}));

const added: any[] = [];
jest.mock('../../../src/config/queue', () => ({
  ingestionQueue: { add: jest.fn(async (_n: string, d: any) => { added.push(d); }) },
}));

import { enqueueIngestion } from '../../../src/routes/upload';

it('queues an ingestion job scoped to the evidence and case', async () => {
  await enqueueIngestion({ evidenceId: 'ev1', caseId: 'cs1', userId: 'u1', uploadPath: '/data/cs1/x.zip', evidenceType: 'windows', socketId: 's1' });
  expect(added[0]).toMatchObject({ evidenceId: 'ev1', caseId: 'cs1', uploadPath: '/data/cs1/x.zip', evidenceType: 'windows' });
});
