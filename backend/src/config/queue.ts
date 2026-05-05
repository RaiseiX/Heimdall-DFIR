
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

export interface ParserJobData {
  parser: string;
  evidenceId: string;
  caseId: string;
  userId: string;

  socketId: string;
  extraArgs: Record<string, string>;
}

export function createRedisConnection(): IORedis {
  return new IORedis({
    host:     process.env.REDIS_HOST     || 'redis',
    port:     parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD,
    maxRetriesPerRequest: null,
    enableReadyCheck:     false,
  });
}

export const parserQueue = new Queue<ParserJobData>('parser-jobs', {
  connection: createRedisConnection(),
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5_000 },  // 5s → 10s → 20s between retries
    timeout: 30 * 60 * 1_000,                         // 30-min hard kill per job
    removeOnComplete: { age: 86_400, count: 500 },    // keep 24 h or 500 completed jobs
    removeOnFail:     { age: 7 * 86_400, count: 200 },
  },
});
