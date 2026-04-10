
import { Worker, Job } from 'bullmq';
import logger from '../config/logger';
import IORedis from 'ioredis';
import { Emitter } from '@socket.io/redis-emitter';
import { Pool } from 'pg';
import type { Server as IOServer } from 'socket.io';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import { runParser } from '../services/parserService';
import { runSoarAsync } from '../services/soarService';
import { createRedisConnection, ParserJobData } from '../config/queue';

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

function makeEmitterIO(): IOServer {
  return {
    to: (room: string) => ({
      emit: (event: string, data: unknown) => {
        emitter.to(room).emit(event, data);
      },
    }),
  } as unknown as IOServer;
}

const workerRedis = createRedisConnection();

const worker = new Worker<ParserJobData>(
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

      const dump = spawnSync('pg_dump', [
        '--host',     process.env.DB_HOST     || 'db',
        '--port',     process.env.DB_PORT     || '5432',
        '--username', process.env.DB_USER     || 'forensiclab',
        '--dbname',   process.env.DB_NAME     || 'forensiclab',
        '--no-password',
        '--format=plain',
      ], {
        env: { ...process.env, PGPASSWORD: process.env.DB_PASSWORD },
        encoding: 'buffer',
        maxBuffer: 512 * 1024 * 1024,
        timeout: 5 * 60 * 1000,
      });

      if (dump.status !== 0) {
        const errMsg = dump.stderr?.toString() || 'pg_dump failed';
        logger.error('[Worker/backup] pg_dump error:', errMsg);
        throw new Error(`pg_dump failed: ${errMsg.slice(0, 200)}`);
      }

      const gzip = spawnSync('gzip', [], {
        input: dump.stdout,
        encoding: 'buffer',
        maxBuffer: 512 * 1024 * 1024,
      });
      if (gzip.status !== 0) throw new Error('gzip failed during scheduled backup');

      fs.writeFileSync(outPath, gzip.stdout as Buffer);
      const stat = fs.statSync(outPath);
      logger.info(`[Worker/backup] Backup created: ${filename} (${stat.size} bytes)`);

      await pool.query(
        `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
         VALUES ($1, 'backup_db', 'system', NULL, $2, 'worker')`,
        [userId || null, JSON.stringify({ filename, size: stat.size, scheduled: true })]
      );
      return;
    }

    try {
      await runParser(
        { parser, evidenceId, caseId, userId, socketId, extraArgs: extraArgs || {} },
        makeEmitterIO(),
        pool,
      );
    } catch (err) {

      logger.error(`[Worker] Uncaught error job ${job.id} (${parser}):`, err);
      throw err;
    }
  },
  {
    connection: workerRedis,
    concurrency: 2,
    lockDuration: 60 * 60 * 1000,
  },
);

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

async function shutdown(signal: string) {
  logger.info(`[Worker] ${signal} received, shutting down gracefully…`);
  await worker.close();
  await pool.end();
  emitterRedis.disconnect();
  workerRedis.disconnect();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

logger.info('[Worker] ForensicLab parser worker started — awaiting jobs on "parser-jobs" queue…');
