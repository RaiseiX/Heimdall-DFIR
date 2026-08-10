import type { Pool } from 'pg';

// Point-in-time host state extracted from a CatScale collection. One row per
// observed object: a kernel module, an open file, a verified package file, a
// container.
export interface StateRow {
  kind: string;
  label: string;
  source_file: string;
  raw: Record<string, unknown>;
}

export interface StateLink {
  evidence_id?: string | null;
  result_id?: string | null;
}

// A single collection yields ~525k lsof rows on a real host. Row-at-a-time
// inserts would hold a connection for minutes; UNNEST batches keep it to one
// round trip per chunk. The chunk size caps the parameter payload so a single
// statement never carries a multi-hundred-megabyte array.
const CHUNK = 2000;

export async function insertStateRows(
  pool: Pool,
  caseId: string,
  hostName: string,
  collectedAt: Date,
  rows: StateRow[],
  link: StateLink = {},
): Promise<number> {
  if (!rows.length) return 0;

  let inserted = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const res = await pool.query(
      `INSERT INTO catscale_state
         (case_id, evidence_id, result_id, host_name, collected_at, kind, source_file, label, raw)
       SELECT $1::uuid, $2::uuid, $3::uuid, $4::text, $5::timestamptz,
              u.kind, u.source_file, u.label, u.raw
         FROM UNNEST($6::text[], $7::text[], $8::text[], $9::jsonb[])
              AS u(kind, source_file, label, raw)`,
      [
        caseId,
        link.evidence_id ?? null,
        link.result_id ?? null,
        hostName,
        collectedAt,
        chunk.map(r => r.kind),
        chunk.map(r => r.source_file),
        chunk.map(r => r.label),
        chunk.map(r => JSON.stringify(r.raw ?? {})),
      ],
    );
    inserted += res.rowCount ?? 0;
  }
  return inserted;
}
