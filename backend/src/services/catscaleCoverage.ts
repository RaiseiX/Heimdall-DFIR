import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { pipeline } from 'stream/promises';
import type { Pool } from 'pg';
import { buildSourcePath } from './catscaleSourcePath';
import type { CatScaleFailure } from './catscaleFiles';

// ingestion_files is the coverage ledger. One row per file, written before any
// parsing is attempted, so that a parse dying in flight still leaves a record of
// what existed.
//
// Measured on the reference collection (2026-08-14): 158 files, of which 63
// carried content no parser reads and 19 were legitimately empty. Before this,
// the table held zero rows and the question "did we miss anything" could only be
// answered by matching strings against parser output — a method that produced a
// wrong answer twice while looking right.
const CHUNK = 500;

// Symlinks are collected too, and they are evidence in their own right: every
// /etc/rc*.d/K01* and S01* entry is a link, and together they say which services
// start at which runlevel. etc-key-files.tar.gz holds 122 regular files and 203
// links — filtering on isFile() dropped all 203 from the ledger.
function walk(dir: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) out.push(p);
    else if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
  return out;
}

/** Size on disk without following a link: a dangling link still has a size. */
function sizeOf(file: string): number {
  try { return fs.lstatSync(file).size; } catch { return 0; }
}

// Streamed, not readFileSync: full-timeline.csv is 2,556 MB on the reference
// collection, past the size at which Node refuses to materialise a Buffer. A
// ledger that crashes on the largest file in the evidence is worse than none.
//
// A symlink is hashed on its target string, never by following it. An expanded
// /etc archive is full of links pointing at ../init.d/*, which do not exist beside
// them — following one throws ENOENT and would abort the whole ledger over a file
// that is not even missing.
async function sha256(file: string): Promise<string> {
  const h = crypto.createHash('sha256');
  let isLink = false;
  try { isLink = fs.lstatSync(file).isSymbolicLink(); } catch { /* treated as a file */ }
  if (isLink) {
    let target = '';
    try { target = fs.readlinkSync(file); } catch { /* unreadable link, hash the empty target */ }
    h.update(`-> ${target}`);
    return h.digest('hex');
  }
  await pipeline(fs.createReadStream(file), h);
  return h.digest('hex');
}

export async function registerCollectionFiles(
  pool: Pool,
  catscaleRoot: string,
  caseId: string,
  evidenceId: string,
  prefix: string,
): Promise<number> {
  const files = walk(catscaleRoot).sort();
  if (!files.length) return 0;

  const rel: string[] = [];
  const sizes: string[] = [];
  const hashes: string[] = [];
  const statuses: string[] = [];

  for (const f of files) {
    const size = sizeOf(f);
    rel.push(buildSourcePath(catscaleRoot, f, prefix));
    sizes.push(String(size));
    hashes.push(await sha256(f));
    // A zero-byte file is an observation, not a gap: 12 docker-container-port
    // files are empty because those containers publish no port. Settling it here
    // keeps "empty" distinguishable from "never read", which is the whole point.
    statuses.push(size === 0 ? 'empty' : 'received');
  }

  const client = await pool.connect();
  let inserted = 0;
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM ingestion_files WHERE case_id = $1::uuid AND evidence_id = $2::uuid',
      [caseId, evidenceId]);

    for (let i = 0; i < rel.length; i += CHUNK) {
      const res = await client.query(
        `INSERT INTO ingestion_files
           (case_id, evidence_id, relative_path, file_size, sha256, status)
         SELECT $1::uuid, $2::uuid, u.rel, u.size::bigint, u.sha, u.st
           FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[])
                AS u(rel, size, sha, st)`,
        [caseId, evidenceId,
         rel.slice(i, i + CHUNK), sizes.slice(i, i + CHUNK),
         hashes.slice(i, i + CHUNK), statuses.slice(i, i + CHUNK)],
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

/**
 * Register the members of an archive as ledger rows of their own, and mark the
 * archive itself `archive_expanded` with how many it held.
 *
 * Without this an archive is one line in the ledger whatever it contains, so
 * `ssh-folders.tar.gz` reads as a single parsed file while the authorized_keys
 * inside it is accounted for nowhere. A member is keyed exactly as its evidence
 * is keyed elsewhere: `<folder>/<archive> -> <internal path>`.
 */
export async function registerArchiveMembers(
  pool: Pool,
  caseId: string,
  evidenceId: string,
  archiveRelativePath: string,
  extractRoot: string,
): Promise<number> {
  const files = walk(extractRoot).sort();

  const rel: string[] = [];
  const sizes: string[] = [];
  const hashes: string[] = [];
  const statuses: string[] = [];

  for (const f of files) {
    const size = sizeOf(f);
    const inner = path.relative(extractRoot, f).split(path.sep).join('/');
    rel.push(`${archiveRelativePath} → ${inner}`);
    sizes.push(String(size));
    hashes.push(await sha256(f));
    statuses.push(size === 0 ? 'empty' : 'received');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE ingestion_files SET status = 'archive_expanded', status_detail = $3::text, updated_at = NOW()
        WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND relative_path = $4::text`,
      [caseId, evidenceId, String(files.length), archiveRelativePath],
    );
    for (let i = 0; i < rel.length; i += CHUNK) {
      await client.query(
        `INSERT INTO ingestion_files
           (case_id, evidence_id, relative_path, file_size, sha256, status)
         SELECT $1::uuid, $2::uuid, u.rel, u.size::bigint, u.sha, u.st
           FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[])
                AS u(rel, size, sha, st)`,
        [caseId, evidenceId,
         rel.slice(i, i + CHUNK), sizes.slice(i, i + CHUNK),
         hashes.slice(i, i + CHUNK), statuses.slice(i, i + CHUNK)],
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return files.length;
}

/**
 * Settle every ledger row once the parse is over. Three outcomes for a non-empty
 * file and no fourth, applied in this order because the order carries the
 * meaning: rows produced, then parser failed, then nobody claimed it.
 *
 * Returns the per-status tally. Its sum equals the number of files on disk.
 */
export async function reconcileCoverage(
  pool: Pool,
  caseId: string,
  evidenceId: string,
  failures: CatScaleFailure[],
  catscaleRoot: string,
): Promise<Record<string, number>> {
  // A failure aimed at the collection root is not attributable to one file: it is
  // the whole state-collection step dying, as it did on 2026-08-03 and again on
  // 2026-08-13 on a NUL byte. Afterwards nobody knows whether the untouched files
  // would have parsed, so calling them `unsupported` would assert knowledge the
  // crash destroyed. They are recorded as errors carrying the message instead.
  const isGlobal = (f: CatScaleFailure) =>
    path.resolve(f.target) === path.resolve(catscaleRoot);
  const global = failures.filter(isGlobal);
  const perFile = failures.filter(f => !isGlobal(f));

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1a. Exact match. An expanded archive registers each member under its own full
    //     key, `<archive> -> <member>`, and the rows that member produced carry
    //     exactly that string.
    await client.query(
      `UPDATE ingestion_files f
          SET status = 'parsed', status_detail = c.n::text, updated_at = NOW()
         FROM (
           SELECT rel, sum(n)::bigint AS n FROM (
             SELECT source AS rel, count(*) AS n
               FROM collection_timeline
              WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND source IS NOT NULL
              GROUP BY 1
             UNION ALL
             SELECT source_file, count(*)
               FROM catscale_state
              WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND source_file IS NOT NULL
              GROUP BY 1
           ) u GROUP BY rel
         ) c
        WHERE f.case_id = $1::uuid AND f.evidence_id = $2::uuid
          AND f.relative_path = c.rel AND f.status = 'received'`,
      [caseId, evidenceId],
    );

    // 1b. Archives that are read without being expanded — var-log.tar.gz produces
    //     rows keyed `<archive> -> <member>` while the ledger holds only the
    //     archive. Credit the archive, so it does not read as unsupported while its
    //     contents are in the database.
    await client.query(
      `UPDATE ingestion_files f
          SET status = 'parsed', status_detail = c.n::text, updated_at = NOW()
         FROM (
           SELECT rel, sum(n)::bigint AS n FROM (
             SELECT split_part(source, ' → ', 1) AS rel, count(*) AS n
               FROM collection_timeline
              WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND source LIKE '%→%'
              GROUP BY 1
             UNION ALL
             SELECT split_part(source_file, ' → ', 1), count(*)
               FROM catscale_state
              WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND source_file LIKE '%→%'
              GROUP BY 1
           ) u GROUP BY rel
         ) c
        WHERE f.case_id = $1::uuid AND f.evidence_id = $2::uuid
          AND f.relative_path = c.rel AND f.status = 'received'`,
      [caseId, evidenceId],
    );

    // 2a. Failures attributable to one file, matched on its basename.
    if (perFile.length) {
      await client.query(
        `UPDATE ingestion_files
            SET status = 'error', status_detail = u.reason, updated_at = NOW()
           FROM UNNEST($3::text[], $4::text[]) AS u(base, reason)
          WHERE case_id = $1::uuid AND evidence_id = $2::uuid
            AND status = 'received'
            AND relative_path LIKE '%' || u.base`,
        [caseId, evidenceId,
         perFile.map(f => path.basename(f.target)),
         perFile.map(f => f.reason)],
      );
    } else if (global.length) {
      await client.query(
        `UPDATE ingestion_files
            SET status = 'error', status_detail = $3::text, updated_at = NOW()
          WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND status = 'received'`,
        [caseId, evidenceId, global.map(f => f.reason).join('; ')],
      );
    }

    // 3. Everything still 'received' was seen and claimed by nobody. `empty` was
    //    settled at registration and is never revisited here.
    await client.query(
      `UPDATE ingestion_files
          SET status = 'unsupported', updated_at = NOW()
        WHERE case_id = $1::uuid AND evidence_id = $2::uuid AND status = 'received'`,
      [caseId, evidenceId],
    );

    const res = await client.query(
      `SELECT status, count(*)::int AS n FROM ingestion_files
        WHERE case_id = $1::uuid AND evidence_id = $2::uuid GROUP BY status`,
      [caseId, evidenceId],
    );
    await client.query('COMMIT');
    return Object.fromEntries(res.rows.map((r: any) => [r.status, Number(r.n)]));
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
