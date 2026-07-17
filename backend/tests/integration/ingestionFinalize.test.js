const fs = require('fs'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260708000000_ingestion_files.sql'), 'utf8');

describeIfDocker('finalizeEvidenceIfComplete', () => {
  let pool, stop, finalize;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    // NOTE: startPg() already creates `cases` (and `users`, `collection_timeline`)
    // with gen_random_uuid(). Only `evidence` is missing — create just that one.
    // evidence carries a metadata column (as in prod db/init.sql) — finalize uses it as the emit-once guard.
    await pool.query(`CREATE TABLE evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), metadata jsonb NOT NULL DEFAULT '{}')`);
    await pool.query(MIGRATION);
    ({ finalizeEvidenceIfComplete: finalize } = require('../../src/services/ingestion/finalize'));
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  test('emits only when all rows terminal, and only once (idempotent)', async () => {
    const ev = (await pool.query('INSERT INTO evidence DEFAULT VALUES RETURNING id')).rows[0].id;
    const cs = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    await pool.query(`INSERT INTO ingestion_files (evidence_id,case_id,relative_path,sha256,status)
      VALUES ($1,$2,'a',repeat('a',64),'parsed'),($1,$2,'b',repeat('b',64),'parsing')`, [ev, cs]);
    const emit = jest.fn();
    expect(await finalize(pool, emit, ev, cs)).toBe(false);       // b still parsing → no emit
    await pool.query(`UPDATE ingestion_files SET status='error' WHERE relative_path='b' AND evidence_id=$1`, [ev]);
    expect(await finalize(pool, emit, ev, cs)).toBe(true);        // now terminal → emit
    expect(emit).toHaveBeenCalledWith(`case:${cs}`, 'evidence:ready', expect.objectContaining({ evidenceId: ev }));
    expect(await finalize(pool, emit, ev, cs)).toBe(false);       // already emitted → not again
    expect(emit).toHaveBeenCalledTimes(1);                        // idempotent
  });
});
