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

// PostgreSQL stores no NUL byte: `text` rejects it as an invalid byte sequence,
// and `jsonb` rejects its escaped form with "unsupported Unicode escape
// sequence". Several CatScale artifacts legitimately carry one — pot-webshell
// captures the first 1000 bytes of candidate files, which are often binary.
//
// Measured on a real collection (2026-08-13): the insert wrote 76 chunks, hit a
// webshell_candidate row on the 77th and threw. There is no enclosing
// transaction, so the earlier chunks stayed and 528,617 of 680,617 rows were
// lost — the whole lsof inventory among them — while the caller logged a
// warning and reported success. Stripping here rather than in each parser is
// deliberate: it covers every producer, including ones not yet written.
//
// Stripping alters what was captured, so it is done as late as possible and
// only for the NUL itself; every other byte reaches the database untouched.
const stripNul = (s: string): string => s.replace(/\x00/g, '');

// JSON.stringify emits a literal NUL as the six-character escape sequence
// backslash-u-0000, which is what jsonb refuses -- so the escape is removed
// after serialisation, not the raw byte before it.
const jsonNoNul = (v: unknown): string => JSON.stringify(v ?? {}).replace(/\\u0000/g, '');

export async function insertStateRows(
  pool: Pool,
  caseId: string,
  hostName: string,
  collectedAt: Date,
  rows: StateRow[],
  link: StateLink = {},
): Promise<number> {
  if (!rows.length) return 0;

  // One transaction for the purge and every chunk, for two reasons.
  //
  // Idempotence: re-parsing a collection replaced nothing before, it appended.
  // Two clicks on "parse" silently doubled a case, and a doubled event count
  // falsifies any occurrence-based conclusion an analyst draws from it.
  //
  // Atomicity: the insert used to run chunk by chunk outside any transaction.
  // On 2026-08-13 a NUL byte killed the 77th chunk of 341 and the first 76
  // stayed, leaving 152,000 of 680,617 rows behind with the parse reported as
  // successful. Now a failure anywhere rolls the whole state back, so the
  // inventory is either complete or absent — never silently partial.
  //
  // Scope: the evidence when known, otherwise this host inside this case. Never
  // the whole case — one case can hold several CatScale collections from
  // different hosts, and wiping a sibling host's inventory would be far worse
  // than the duplication this prevents.
  const client = await pool.connect();
  let inserted = 0;
  try {
    await client.query('BEGIN');

    if (link.evidence_id) {
      await client.query('DELETE FROM catscale_state WHERE case_id = $1::uuid AND evidence_id = $2::uuid',
        [caseId, link.evidence_id]);
    } else {
      await client.query('DELETE FROM catscale_state WHERE case_id = $1::uuid AND host_name = $2::text',
        [caseId, hostName]);
    }

    for (let i = 0; i < rows.length; i += CHUNK) {
      const chunk = rows.slice(i, i + CHUNK);
      const res = await client.query(
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
          chunk.map(r => stripNul(r.kind)),
          chunk.map(r => stripNul(r.source_file)),
          chunk.map(r => stripNul(r.label)),
          chunk.map(r => jsonNoNul(r.raw)),
        ],
      );
      inserted += res.rowCount ?? 0;
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return inserted;
}
