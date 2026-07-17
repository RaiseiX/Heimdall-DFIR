
import { Queue, QueueOptions } from 'bullmq';
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

/**
 * Lazily construct a BullMQ Queue on first use.
 *
 * BullMQ's Queue constructor eagerly opens its Redis connection (it calls
 * connect() internally, so ioredis `lazyConnect` does not defer it). Because
 * these queues are module-level `export const`s, merely importing this file —
 * which many routes and workers do transitively — used to open sockets to
 * Redis. Under test the host is unreachable, so ioredis kept retrying and held
 * the event loop open ("worker failed to exit gracefully" / jest --forceExit).
 *
 * The Proxy constructs the real Queue (and its connection) only when a queue
 * method/property is actually accessed (first `.add()`, `.getJobs()`, …), so a
 * bare import connects to nothing. The public API is unchanged: consumers keep
 * doing `parserQueue.add(...)`. `then`/symbol probes return undefined so
 * promise-detection or util.inspect can't force construction.
 */
function lazyQueue<T>(name: string, defaultJobOptions: QueueOptions['defaultJobOptions']): Queue<T> {
  let instance: Queue<T> | undefined;
  const resolve = (): Queue<T> => {
    if (!instance) {
      instance = new Queue<T>(name, { connection: createRedisConnection(), defaultJobOptions });
    }
    return instance;
  };
  return new Proxy({} as Queue<T>, {
    get(_target, prop) {
      if (prop === 'then' || typeof prop === 'symbol') return undefined;
      const q = resolve();
      const value = Reflect.get(q as object, prop, q);
      return typeof value === 'function' ? value.bind(q) : value;
    },
    set(_target, prop, value) {
      Reflect.set(resolve() as object, prop, value);
      return true;
    },
  });
}

export const parserQueue = lazyQueue<ParserJobData>('parser-jobs', {
  attempts: 3,
  backoff: { type: 'exponential', delay: 5_000 },  // 5s → 10s → 20s between retries
  removeOnComplete: { age: 86_400, count: 500 },    // keep 24 h or 500 completed jobs
  removeOnFail:     { age: 7 * 86_400, count: 200 },
});

export interface IngestionJobData {
  evidenceId: string; caseId: string; userId: string;
  uploadPath: string; evidenceType: string; socketId: string; forceReparse?: boolean;
}
export const ingestionQueue = lazyQueue<IngestionJobData>('ingestion-jobs', {
  attempts: 2, backoff: { type: 'exponential', delay: 5_000 },
  removeOnComplete: { age: 86_400, count: 500 }, removeOnFail: { age: 7 * 86_400, count: 200 },
});

export interface HuntJobData {
  caseId: string; userId: string; trigger: string; evidenceId?: string; huntRunId: string;
}
export const huntingQueue = lazyQueue<HuntJobData>('hunting-jobs', {
  attempts: 2, backoff: { type: 'exponential', delay: 10_000 },
  removeOnComplete: { age: 86_400, count: 200 }, removeOnFail: { age: 7 * 86_400, count: 100 },
});
