import { Pool } from 'pg';

// Shared by parserWorker.ts and ingestionWorker.ts: enqueue an auto hunt run
// once an evidence's ingestion_files rows all reach a terminal state (i.e.
// finalizeEvidenceIfComplete's emit-once guard fired). Pure + hermetic —
// deps (pool/triggerHunt) are injected so this has no queue/DB import of its
// own and stays unit-testable without touching Redis or Postgres.
type TriggerFn = (pool: Pool, caseId: string, userId: string, trigger: string, evidenceId: string) => Promise<{ started: boolean }>;

export async function maybeTriggerHunt(emitted: boolean, ctx: { pool: Pool; caseId: string; userId: string; evidenceId: string; triggerHunt: TriggerFn }): Promise<void> {
  if (!emitted) return;
  try { await ctx.triggerHunt(ctx.pool, ctx.caseId, ctx.userId, 'auto', ctx.evidenceId); }
  catch { /* hunt-enqueue failure must never break ingestion */ }
}
