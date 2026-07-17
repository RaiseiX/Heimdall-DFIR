// backend/src/services/huntRuns.ts
import { Pool } from 'pg';

export type HuntStep = { key: string; label: string; status: 'pending'|'running'|'done'|'error'; count: number|null; error: string|null };

export async function startHuntRun(pool: Pool, caseId: string, trigger: string, evidenceId: string|null, steps: HuntStep[]): Promise<{ started: boolean; huntRunId: string|null }> {
  // The partial unique index makes the INSERT fail on conflict when a run is
  // already 'running' for this case → ON CONFLICT DO NOTHING → rowCount 0 = guarded.
  const r = await pool.query(
    `INSERT INTO hunt_runs (case_id, status, trigger, evidence_id, steps)
     VALUES ($1,'running',$2,$3,$4)
     ON CONFLICT (case_id) WHERE status = 'running' DO NOTHING
     RETURNING id`,
    [caseId, trigger, evidenceId, JSON.stringify(steps)]);
  if (r.rows[0]) return { started: true, huntRunId: r.rows[0].id };
  return { started: false, huntRunId: null };
}

export async function updateHuntStep(pool: Pool, huntRunId: string, key: string, patch: Partial<HuntStep>): Promise<void> {
  // Merge patch into the matching step object inside the steps JSONB array.
  await pool.query(
    `UPDATE hunt_runs SET updated_at = NOW(), steps = (
       SELECT jsonb_agg(CASE WHEN s->>'key' = $2 THEN s || $3::jsonb ELSE s END)
       FROM jsonb_array_elements(steps) s)
     WHERE id = $1`,
    [huntRunId, key, JSON.stringify(patch)]);
}

export async function finishHuntRun(pool: Pool, huntRunId: string, status: 'done'|'error'): Promise<void> {
  await pool.query(`UPDATE hunt_runs SET status=$2, finished_at=NOW(), updated_at=NOW() WHERE id=$1`, [huntRunId, status]);
}

export async function getHuntRun(pool: Pool, caseId: string): Promise<{ caseId: string; status: string; trigger: string|null; steps: HuntStep[] }> {
  const r = await pool.query(
    `SELECT status, trigger, steps FROM hunt_runs WHERE case_id=$1 ORDER BY started_at DESC LIMIT 1`, [caseId]);
  if (!r.rows[0]) return { caseId, status: 'idle', trigger: null, steps: [] };
  return { caseId, status: r.rows[0].status, trigger: r.rows[0].trigger, steps: r.rows[0].steps };
}

// Mark 'running' hunts whose heartbeat (updated_at) froze as 'error' — reclaims rows
// orphaned by a worker crash so the per-case guard doesn't block the case forever.
// Threshold defaults to 30 min (> the slowest engine timeout ~15 min, safe margin;
// also safe under multiple worker replicas since a live run keeps updated_at fresh).
export async function reconcileStaleHunts(pool: Pool, staleMinutes = 30): Promise<number> {
  const r = await pool.query(
    `UPDATE hunt_runs SET status='error', finished_at=NOW(), updated_at=NOW()
      WHERE status='running' AND updated_at < NOW() - ($1 || ' minutes')::interval`,
    [String(staleMinutes)]);
  return r.rowCount ?? 0;
}
