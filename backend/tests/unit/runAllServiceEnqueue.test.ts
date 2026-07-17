process.env.JWT_SECRET = 'test-secret-for-unit-tests';

const added: any[] = [];
const huntingQueueAdd = jest.fn(async (_n: string, d: any) => { added.push(d); });
jest.mock('../../src/config/queue', () => ({ huntingQueue: { add: huntingQueueAdd } }));
jest.mock('../../src/config/database', () => ({ pool: { query: jest.fn() } }));
const finishHuntRun = jest.fn(async () => {});
jest.mock('../../src/services/huntRuns', () => ({
  startHuntRun: jest.fn(async () => ({ started: true, huntRunId: 'hr-1' })),
  getHuntRun: jest.fn(async () => ({ caseId: 'c1', status: 'running', trigger: 'auto', steps: [] })),
  finishHuntRun,
}));
const { triggerHunt, startRunAll } = require('../../src/services/runAllService');

it('triggerHunt enqueues a hunt job when the guard lets it start', async () => {
  const r = await triggerHunt({ query: jest.fn() }, 'c1', 'u1', 'auto', 'ev1');
  expect(r.started).toBe(true);
  expect(added[0]).toMatchObject({ caseId: 'c1', userId: 'u1', trigger: 'auto', evidenceId: 'ev1', huntRunId: 'hr-1' });
});

it('startRunAll delegates with user.id and returns the run state', async () => {
  const job = await startRunAll('c1', { id: 'u9', username: 'x', role: 'admin' }, 'manual');
  expect(job).toMatchObject({ status: 'running' });
});

it('triggerHunt releases the guard and returns started:false when the queue add fails', async () => {
  huntingQueueAdd.mockRejectedValueOnce(new Error('redis blip'));
  const r = await triggerHunt({ query: jest.fn() }, 'c1', 'u1', 'auto', 'ev1');
  expect(finishHuntRun).toHaveBeenCalledWith(expect.anything(), 'hr-1', 'error');
  expect(r).toEqual({ started: false });
});
