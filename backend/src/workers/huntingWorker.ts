import { Worker, Job } from 'bullmq';
import { Pool } from 'pg';
import { createRedisConnection, HuntJobData } from '../config/queue';
import { reconcileStaleHunts } from '../services/huntRuns';
const { runAllEngines } = require('../services/runAllService');

export type HuntDeps = { runAllEngines: (pool: Pool, caseId: string, userId: string, huntRunId: string) => Promise<void>; pool: Pool };

export async function processHunt(data: HuntJobData, deps: HuntDeps): Promise<void> {
  await deps.runAllEngines(deps.pool, data.caseId, data.userId, data.huntRunId);
}

// Wiring (not under unit test): construct the real Worker with real deps.
// Matches parserWorker.ts/ingestionWorker.ts's guard: the Worker is always
// constructed when this module is require()d in production (NODE_ENV !==
// 'test'), including from startWorker.js. Under `npx jest`, NODE_ENV=test
// skips construction so no real Worker/Redis connection is spun up. The unit
// test also mocks `config/queue` for full isolation — its queues are now lazy
// (constructed on first use, not at import), so importing it is already
// connection-free; the mock just keeps the test hermetic regardless
// (see tests/unit/huntingWorker.test.ts).
if (process.env.NODE_ENV !== 'test') {
  const pool = new Pool({ host: process.env.DB_HOST || 'db', database: process.env.DB_NAME || 'forensiclab', user: process.env.DB_USER || 'forensiclab', password: process.env.DB_PASSWORD });
  // Reclaim 'running' hunt_runs orphaned by a worker crash (frozen heartbeat) so the
  // per-case guard doesn't block the case forever. Fire-and-forget: a reconciliation
  // failure must never prevent the worker itself from starting.
  reconcileStaleHunts(pool).catch((err) => console.error('reconcileStaleHunts failed at startup', err));
  new Worker<HuntJobData>('hunting-jobs', async (job: Job<HuntJobData>) => {
    await processHunt(job.data, { runAllEngines, pool });
  }, { connection: createRedisConnection(), concurrency: 1 });
}
