import { Pool } from 'pg';

export async function loadDraft(pool: Pool, caseId: string): Promise<Buffer | null> {
  const { rows } = await pool.query('SELECT ydoc FROM report_drafts WHERE case_id = $1', [caseId]);
  return rows.length ? (rows[0].ydoc as Buffer) : null;
}

export async function saveDraft(
  pool: Pool,
  caseId: string,
  ydoc: Buffer,
  textSnapshot: Record<string, string>,
): Promise<void> {
  await pool.query(
    `INSERT INTO report_drafts (case_id, ydoc, text_snapshot, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (case_id) DO UPDATE
       SET ydoc = EXCLUDED.ydoc, text_snapshot = EXCLUDED.text_snapshot, updated_at = NOW()`,
    [caseId, ydoc, JSON.stringify(textSnapshot)],
  );
}
