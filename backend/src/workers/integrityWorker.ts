import { Worker, Job } from 'bullmq';
import { Pool } from 'pg';
import { Emitter } from '@socket.io/redis-emitter';
import { createRedisConnection, IntegrityJobData, integrityQueue } from '../config/queue';
const { runIntegrityCheck } = require('../services/integrityCheck');
const { enqueueAllCases } = require('../services/integrityScheduler');

export type IntegrityProgress = { done: number; total: number; evidenceId: string; status: string };

export type IntegrityDeps = {
  db: unknown;
  queue: unknown;
  racines: string[];
  jobId: string | undefined;
  emit: (room: string, event: string, data: unknown) => void;
  runIntegrityCheck: (args: Record<string, unknown>) => Promise<{ aborted: boolean; total: number; done: number; counts: Record<string, number> }>;
  enqueueAllCases: (db: unknown, queue: unknown) => Promise<unknown>;
  updateProgress?: (progress: { done: number; total: number }) => Promise<void> | void;
};

export async function processIntegrity(data: IntegrityJobData, deps: IntegrityDeps): Promise<void> {
  if (data.all) {
    await deps.enqueueAllCases(deps.db, deps.queue);
    return;
  }

  const caseId = (data.caseId as string).toLowerCase();
  const room = `case:${caseId}`;
  const jobId = deps.jobId;

  const onProgress = (p: IntegrityProgress) => {
    if (deps.updateProgress) {
      Promise.resolve(deps.updateProgress({ done: p.done, total: p.total })).catch(() => {});
    }
    deps.emit(room, 'integrity:progress', {
      caseId, jobId, done: p.done, total: p.total, evidenceId: p.evidenceId, status: p.status,
    });
  };

  let result;
  try {
    result = await deps.runIntegrityCheck({
      db: deps.db,
      caseId,
      evidenceId: data.evidenceId ?? null,
      userId: data.userId ?? null,
      trigger: data.trigger,
      jobId,
      racines: deps.racines,
      onProgress,
    });
  } catch (err) {
    deps.emit(room, 'integrity:failed', { caseId, jobId });
    throw err;
  }

  deps.emit(room, 'integrity:done', result.aborted
    ? { caseId, jobId, counts: result.counts, aborted: true }
    : { caseId, jobId, counts: result.counts });
}

if (process.env.NODE_ENV !== 'test') {
  const pool = new Pool({ host: process.env.DB_HOST || 'db', database: process.env.DB_NAME || 'forensiclab', user: process.env.DB_USER || 'forensiclab', password: process.env.DB_PASSWORD });
  const emitter = new Emitter(createRedisConnection());
  const emit = (room: string, event: string, data: unknown) => { emitter.to(room).emit(event, data); };
  const { racinesDeStockage } = require('../services/storagePathGuard');
  new Worker<IntegrityJobData>('integrity-jobs', async (job: Job<IntegrityJobData>) => {
    await processIntegrity(job.data, {
      db: pool,
      queue: integrityQueue(),
      racines: racinesDeStockage(),
      jobId: job.id,
      emit,
      runIntegrityCheck,
      enqueueAllCases,
      updateProgress: (p) => job.updateProgress(p),
    });
  }, { connection: createRedisConnection(), concurrency: 1 });
}
