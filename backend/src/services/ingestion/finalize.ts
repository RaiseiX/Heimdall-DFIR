// backend/src/services/ingestion/finalize.ts
import { Pool } from 'pg';

export type EmitReady = (room: string, event: string, data: unknown) => void;
const TERMINAL = ['parsed', 'empty', 'degraded', 'error', 'quarantined', 'skipped_duplicate'];

export async function finalizeEvidenceIfComplete(pool: Pool, emit: EmitReady, evidenceId: string, caseId: string): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT status, COUNT(*)::int n FROM ingestion_files WHERE evidence_id=$1 GROUP BY status`, [evidenceId]);
  if (rows.length === 0) return false;
  if (rows.some(r => !TERMINAL.includes(r.status))) return false;   // still pending

  // Emit-once guard: atomically claim the ready_emitted flag. Only the caller whose
  // UPDATE actually flips it emits — safe when the parser worker completes several
  // parser jobs for one evidence concurrently.
  const claim = await pool.query(
    `UPDATE evidence
        SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{ready_emitted}', 'true')
      WHERE id = $1 AND COALESCE(metadata->>'ready_emitted', '') <> 'true'`, [evidenceId]);
  if (claim.rowCount !== 1) return false;   // another concurrent call already emitted

  const rollup = Object.fromEntries(rows.map(r => [r.status, r.n]));
  emit(`case:${caseId}`, 'evidence:ready', { evidenceId, caseId, rollup });
  return true;
}
