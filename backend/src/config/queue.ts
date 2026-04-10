
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

    attempts: 1,
    removeOnComplete: { count: 200 },
    removeOnFail:     { count: 100 },
  },
});
