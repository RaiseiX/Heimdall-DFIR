
import { Worker, Job } from 'bullmq';
import logger from '../config/logger';
import IORedis from 'ioredis';
import { Emitter } from '@socket.io/redis-emitter';
import { Pool } from 'pg';
import type { Server as IOServer } from 'socket.io';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import { runParser } from '../services/parserService';
import { runSoarAsync } from '../services/soarService';
import { createRedisConnection, ParserJobData } from '../config/queue';
import { finalizeEvidenceIfComplete } from '../services/ingestion/finalize';
import { maybeTriggerHunt } from './huntTrigger';
// runAllService.js is require()d lazily at call time (inside the job
// handler), NOT at module top-level: it transitively imports
// middleware/auth.js, which throws at import time if JWT_SECRET is unset.
// Several pre-existing unit tests import this worker module without setting
// JWT_SECRET (they never needed to) — an eager top-level require would break
// them even though they never touch the hunt-trigger path.

// Pure mapper — the only piece of this file that's directly unit-tested.
// Exported so tests can import it without triggering the module-scope
// Worker/Redis/Pool wiring below (guarded out under NODE_ENV=test).
export function mapOutcomeToStatus(recordCount: number, failed: boolean): 'parsed' | 'empty' | 'degraded' | 'error' {
  if (failed && recordCount > 0) return 'degraded';   // partial parse
  if (failed) return 'error';
  return recordCount > 0 ? 'parsed' : 'empty';
}

const pool = new Pool({
  host:     process.env.DB_HOST     || 'db',
  port:     parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME     || 'forensiclab',
  user:     process.env.DB_USER     || 'forensiclab',
  password: process.env.DB_PASSWORD,
  max: 5,
  idleTimeoutMillis: 30_000,
});

const emitterRedis = createRedisConnection();
const emitter = new Emitter(emitterRedis);

function makeEmitterIO(job: Job<ParserJobData>): IOServer {
  return {
    to: (room: string) => ({
      emit: (event: string, data: unknown) => {
        emitter.to(room).emit(event, data);
        // Mirror record count into BullMQ job progress so the admin dashboard
        // and any future polling client can track ingestion without a full socket.
        if (event === 'parser:status') {
          const ev = data as { recordCount?: number };
          if (typeof ev.recordCount === 'number' && ev.recordCount > 0) {
            job.updateProgress(ev.recordCount).catch(() => {});
          }
        }
      },
    }),
  } as unknown as IOServer;
}

const workerRedis = createRedisConnection();

// The BullMQ Worker below actively retries against its Redis connection.
// Under `npx jest` (NODE_ENV=test), config/queue is mocked to a fake `{}`
// connection so importing this module (to reach mapOutcomeToStatus) doesn't
// spin up a real worker that never resolves/rejects and hangs the test
// process. In every real deployment NODE_ENV is never 'test', so production
// behavior — the worker is always constructed and started — is unchanged.
function startWorker(): Worker<ParserJobData> {
  return new Worker<ParserJobData>(
    'parser-jobs',
    async (job: Job<ParserJobData>) => {
    const { parser, evidenceId, caseId, userId, socketId, extraArgs } = job.data;

    logger.info(`[Worker] Job ${job.id} — parser=${parser} evidence=${evidenceId} socket=${socketId}`);

    if (parser === 'backup') {
      const BACKUP_DIR = process.env.BACKUP_DIR || '/app/backups';
      if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

      const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const filename = `forensiclab-backup-${ts}.sql.gz`;
      const outPath = path.join(BACKUP_DIR, filename);

      await new Promise<void>((resolve, reject) => {
        const dumpProc = spawn('pg_dump', [
          '--host',     process.env.DB_HOST     || 'db',
          '--port',     process.env.DB_PORT     || '5432',
          '--username', process.env.DB_USER     || 'forensiclab',
          '--dbname',   process.env.DB_NAME     || 'forensiclab',
          '--no-password',
          '--format=plain',
        ], {
          env: { ...process.env, PGPASSWORD: process.env.DB_PASSWORD },
          stdio: ['ignore', 'pipe', 'pipe'],
        });

        const gzipProc  = spawn('gzip', [], { stdio: ['pipe', 'pipe', 'pipe'] });
        const outStream = fs.createWriteStream(outPath);

        dumpProc.stdout.pipe(gzipProc.stdin);
        gzipProc.stdout.pipe(outStream);

        const dumpStderr: Buffer[] = [];
        dumpProc.stderr.on('data', (chunk: Buffer) => dumpStderr.push(chunk));

        dumpProc.on('close', (code) => {
          if (code !== 0) {
            const errMsg = Buffer.concat(dumpStderr).toString().slice(0, 200);
            logger.error('[Worker/backup] pg_dump error:', errMsg);
            gzipProc.kill();
            reject(new Error(`pg_dump failed: ${errMsg}`));
          }
        });

        gzipProc.on('close', (code) => {
          if (code !== 0) {
            reject(new Error('gzip failed during scheduled backup'));
          }
        });

        outStream.on('finish', resolve);
        outStream.on('error', reject);
        dumpProc.on('error', reject);
        gzipProc.on('error', reject);
      });
      const stat = fs.statSync(outPath);
      logger.info(`[Worker/backup] Backup created: ${filename} (${stat.size} bytes)`);

      await pool.query(
        `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
         VALUES ($1, 'backup_db', 'system', NULL, $2, 'worker')`,
        [userId || null, JSON.stringify({ filename, size: stat.size, scheduled: true })]
      );
      return;
    }

    let failed = false;
    let recordCount = 0;
    let caughtErr: unknown;
    try {
      await job.updateProgress(0);
      recordCount = await runParser(
        { parser, evidenceId, caseId, userId, socketId, extraArgs: extraArgs || {} },
        makeEmitterIO(job),
        pool,
      );
    } catch (err) {
      failed = true;
      caughtErr = err;
      logger.error(`[Worker] Uncaught error job ${job.id} (${parser}):`, err);
    }

    // New ingestion pipeline wiring: only activates when the job carries
    // ingestionFileIds (i.e. it was enqueued by ingestionWorker's state
    // machine). Absent that, behavior is unchanged from before this wiring.
    const ingestionFileIds: string[] = extraArgs?.ingestionFileIds ? JSON.parse(extraArgs.ingestionFileIds) : [];
    if (ingestionFileIds.length > 0) {
      const status = mapOutcomeToStatus(recordCount, failed);
      await pool.query(
        `UPDATE ingestion_files SET status=$2, updated_at=NOW() WHERE id = ANY($1)`,
        [ingestionFileIds, status],
      );
      const emitIO = makeEmitterIO(job);
      const emit = (room: string, event: string, data: unknown) => emitIO.to(room).emit(event, data);
      const emitted = await finalizeEvidenceIfComplete(pool, emit, evidenceId, caseId);
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { triggerHunt } = require('../services/runAllService');
      await maybeTriggerHunt(emitted, { pool, caseId, userId, evidenceId, triggerHunt });
    }

    if (failed) {
      // Preserve BullMQ retry semantics + original error identity/message,
      // matching pre-wiring behavior exactly.
      throw caughtErr;
    }
  },
    {
      connection: workerRedis,
      concurrency: 2,
      lockDuration: 60 * 60 * 1000,
    },
  );
}

let worker: Worker<ParserJobData> | undefined;

if (process.env.NODE_ENV !== 'test') {
  worker = startWorker();

  worker.on('completed', (job) => {
    logger.info(`[Worker] ✓ Job ${job.id} completed (${job.data.parser})`);

    const { caseId } = job.data;
    if (caseId) {
      runSoarAsync(caseId, pool, 'auto');
    }
  });

  worker.on('failed', (job, err) => {
    logger.error(`[Worker] ✗ Job ${job?.id} failed (${job?.data?.parser}):`, err.message);
  });

  worker.on('error', (err) => {
    logger.error('[Worker] Worker error:', err.message);
  });

  const shutdown = async (signal: string) => {
    logger.info(`[Worker] ${signal} received, shutting down gracefully…`);
    await worker!.close();
    await pool.end();
    emitterRedis.disconnect();
    workerRedis.disconnect();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  logger.info('[Worker] ForensicLab parser worker started — awaiting jobs on "parser-jobs" queue…');
}
