import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { Worker, Job } from 'bullmq';
import { Pool } from 'pg';
import { Emitter } from '@socket.io/redis-emitter';
import { createRedisConnection, IngestionJobData, ingestionQueue, parserQueue } from '../config/queue';
import { isArchive, extractZip } from '../services/ingestion/extractor';
import { walk } from '../services/ingestion/walker';
import { classify, toEvidenceTypeContext } from '../services/ingestion/classifier';
import { checkAndRecord } from '../services/ingestion/dedupService';
import { finalizeEvidenceIfComplete } from '../services/ingestion/finalize';
import { maybeTriggerHunt } from './huntTrigger';
// runAllService.js is require()d lazily at call time (inside the wiring
// block below), NOT at module top-level: it transitively imports
// middleware/auth.js, which throws at import time if JWT_SECRET is unset.
// Several pre-existing unit tests import this worker module (for
// processIngestion) without setting JWT_SECRET — an eager top-level require
// would break them even though they never touch the hunt-trigger path.

export type IngestionDeps = {
  isArchive: typeof isArchive;
  extractZip: typeof extractZip;
  walk: typeof walk;
  classify: typeof classify;
  checkAndRecord: typeof checkAndRecord;
  parserEnqueue: (data: Record<string, unknown>) => Promise<void>;
  finalize: (pool: Pool, evidenceId: string, caseId: string) => Promise<boolean>;
  stageFile: (absPath: string, stagingDir: string, relativePath: string) => Promise<void>;
  pool: Pool;
};

export async function processIngestion(data: IngestionJobData, deps: IngestionDeps): Promise<void> {
  // Translate the artifact-oriented UI evidenceType (disk/log/registry/…)
  // into the classifier's OS-oriented prior context. See FIX D rationale in
  // classifier.ts: an unmapped/ambiguous raw value becomes 'other', which
  // makes classify() skip the prior rather than wrongly damp confidence.
  const evType = toEvidenceTypeContext(data.evidenceType);
  const stagingRoot = path.join(path.dirname(data.uploadPath), `_stage_${data.evidenceId}`);
  const byParser = new Map<string, { ids: string[]; version: string | null }>();

  // Extraction + directory walk are wrapped together: a `.zip` that fails to
  // open (corrupt/truncated) or a walk that throws (e.g. unreadable dir)
  // must NEVER propagate out of this function with zero ingestion_files rows
  // recorded — finalizeEvidenceIfComplete's `rows.length === 0` short-circuit
  // (finalize.ts) would then see nothing to roll up and return false forever,
  // leaving the evidence stuck non-terminal (silent UI hang). On failure,
  // record ONE error row for the upload and finalize so the evidence always
  // reaches a terminal state.
  try {
    let workDir = data.uploadPath;
    if (deps.isArchive(data.uploadPath)) {
      workDir = fs.mkdtempSync(path.join(os.tmpdir(), `ing-${data.evidenceId}-`));
      await deps.extractZip(data.uploadPath, workDir);
    }

    for await (const f of deps.walk(workDir)) {
      const c = deps.classify({ relativePath: f.relativePath, header: f.header, evidenceType: evType });
      const rec = await deps.checkAndRecord(deps.pool, {
        evidenceId: data.evidenceId, caseId: data.caseId, relativePath: f.relativePath, fileSize: f.size,
        sha256: f.sha256, detectedType: c.detectedType, parserName: c.parser, parserVersion: c.parserVersion, confidence: c.confidence,
      }, { forceReparse: data.forceReparse });
      if (rec.isDuplicate || rec.quarantined || !c.parser) continue;
      const stagingDir = path.join(stagingRoot, c.parser);
      await deps.stageFile(f.absPath, stagingDir, f.relativePath);
      const g = byParser.get(c.parser) ?? { ids: [], version: c.parserVersion };
      g.ids.push(rec.ingestionFileId); byParser.set(c.parser, g);
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    // sha256 is NOT NULL — use an all-zero sentinel (never a real file hash)
    // since this row represents the whole failed upload, not one file.
    const SENTINEL_SHA256 = '0'.repeat(64);
    await deps.pool.query(
      `INSERT INTO ingestion_files (evidence_id, case_id, relative_path, file_size, sha256,
         detected_type, confidence, parser_name, parser_version, status, status_detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'error',$10)`,
      [
        data.evidenceId, data.caseId, path.basename(data.uploadPath), null, SENTINEL_SHA256,
        'unknown', 0, null, null, detail,
      ],
    );
    await deps.finalize(deps.pool, data.evidenceId, data.caseId);
    return;
  }

  for (const [parser, g] of byParser) {
    await deps.parserEnqueue({
      parser, evidenceId: data.evidenceId, caseId: data.caseId, userId: data.userId, socketId: data.socketId,
      extraArgs: { stagingDir: path.join(stagingRoot, parser), ingestionFileIds: JSON.stringify(g.ids) },
    });
    await deps.pool.query(`UPDATE ingestion_files SET status='queued', updated_at=NOW() WHERE id = ANY($1)`, [g.ids]);
  }

  if (byParser.size === 0) await deps.finalize(deps.pool, data.evidenceId, data.caseId);
}

// Wiring (not under unit test): construct the real Worker with real deps.
// Matches parserWorker.ts's guard: the Worker is always constructed when
// this module is require()d in production (NODE_ENV !== 'test'), including
// from startWorker.js. Under `npx jest`, NODE_ENV=test skips construction
// so no real Worker/Redis connection is spun up.
if (process.env.NODE_ENV !== 'test') {
  const pool = new Pool({ host: process.env.DB_HOST || 'db', database: process.env.DB_NAME || 'forensiclab', user: process.env.DB_USER || 'forensiclab', password: process.env.DB_PASSWORD });
  const stageFile = async (absPath: string, stagingDir: string, rel: string) => {
    const dest = path.join(stagingDir, path.basename(rel)); fs.mkdirSync(stagingDir, { recursive: true }); await fs.promises.copyFile(absPath, dest);
  };
  // Real socket.io-over-redis emitter (mirrors parserWorker.ts's Emitter
  // wiring) so the zero-parser-jobs case (all-duplicate / all-quarantined /
  // extraction-failure) actually reaches connected clients instead of
  // emitting `evidence:ready` to a no-op. Constructed only here in the
  // wiring block — processIngestion's core stays unit-testable via the
  // dep-injected `finalize`.
  const emitterRedis = createRedisConnection();
  const emitter = new Emitter(emitterRedis);
  const emit = (room: string, event: string, data: unknown) => { emitter.to(room).emit(event, data); };
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { triggerHunt } = require('../services/runAllService');
  new Worker<IngestionJobData>('ingestion-jobs', async (job: Job<IngestionJobData>) => {
    // Wraps finalizeEvidenceIfComplete so a finalize call that flips the
    // emit-once guard (returns true) also enqueues an auto hunt run.
    // Closes over job.data.userId (per-job) — the hunt-enqueue failure is
    // swallowed inside maybeTriggerHunt, so it can never break ingestion.
    const finalize = async (p: Pool, ev: string, cs: string) => {
      const emitted = await finalizeEvidenceIfComplete(p, emit, ev, cs);
      await maybeTriggerHunt(emitted, { pool: p, caseId: cs, userId: job.data.userId, evidenceId: ev, triggerHunt });
      return emitted;
    };
    await processIngestion(job.data, { isArchive, extractZip, walk, classify, checkAndRecord, parserEnqueue: async d => { await parserQueue.add('parse', d as any); }, finalize, stageFile, pool });
  }, { connection: createRedisConnection(), concurrency: 2 });
}
