// backend/src/services/ingestion/dedupService.ts
import { Pool } from 'pg';

export type IngestionFileInput = {
  evidenceId: string; caseId: string; relativePath: string; fileSize: number; sha256: string;
  detectedType: string; parserName: string | null; parserVersion: string | null; confidence: number;
};

const TERMINAL_USEFUL = ['parsed', 'empty', 'degraded'];

export async function checkAndRecord(
  pool: Pool, input: IngestionFileInput, opts: { forceReparse?: boolean } = {},
): Promise<{ ingestionFileId: string; isDuplicate: boolean; quarantined: boolean }> {
  const quarantined = input.detectedType === 'unknown' || input.parserName === null;

  if (!opts.forceReparse && !quarantined) {
    const dup = await pool.query(
      `SELECT id FROM ingestion_files
        WHERE evidence_id=$1 AND sha256=$2 AND parser_name=$3 AND parser_version IS NOT DISTINCT FROM $4
          AND status = ANY($5) ORDER BY created_at LIMIT 1`,
      [input.evidenceId, input.sha256, input.parserName, input.parserVersion, TERMINAL_USEFUL]);
    if (dup.rows[0]) {
      const ins = await pool.query(
        `INSERT INTO ingestion_files (evidence_id, case_id, relative_path, file_size, sha256,
           detected_type, confidence, parser_name, parser_version, status, dedup_of)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'skipped_duplicate',$10) RETURNING id`,
        [input.evidenceId, input.caseId, input.relativePath, input.fileSize, input.sha256,
         input.detectedType, input.confidence, input.parserName, input.parserVersion, dup.rows[0].id]);
      return { ingestionFileId: ins.rows[0].id, isDuplicate: true, quarantined: false };
    }
  }

  const status = quarantined ? 'quarantined' : 'classified';
  const ins = await pool.query(
    `INSERT INTO ingestion_files (evidence_id, case_id, relative_path, file_size, sha256,
       detected_type, confidence, parser_name, parser_version, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
    [input.evidenceId, input.caseId, input.relativePath, input.fileSize, input.sha256,
     input.detectedType, input.confidence, input.parserName, input.parserVersion, status]);
  return { ingestionFileId: ins.rows[0].id, isDuplicate: false, quarantined };
}
