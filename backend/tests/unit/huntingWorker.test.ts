process.env.JWT_SECRET = 'test-secret-for-unit-tests';

jest.mock('../../src/config/queue', () => ({
  createRedisConnection: jest.fn(() => ({})),
  huntingQueue: { add: jest.fn() },
}));

import { processHunt } from '../../src/workers/huntingWorker';

it('runs the engine orchestration for the job', async () => {
  const calls: any[] = [];
  const deps = { runAllEngines: async (_p: any, caseId: string, userId: string, huntRunId: string) => { calls.push({ caseId, userId, huntRunId }); }, pool: {} as any };
  await processHunt({ caseId: 'c1', userId: 'u1', trigger: 'auto', huntRunId: 'hr-1' }, deps as any);
  expect(calls).toEqual([{ caseId: 'c1', userId: 'u1', huntRunId: 'hr-1' }]);
});
