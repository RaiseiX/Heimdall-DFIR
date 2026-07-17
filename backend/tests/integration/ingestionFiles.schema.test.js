// backend/tests/integration/ingestionFiles.schema.test.js
const fs = require('fs');
const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');

const MIGRATION = fs.readFileSync(
  path.join(__dirname, '../../../db/migrations/20260708000000_ingestion_files.sql'), 'utf8');

describeIfDocker('ingestion_files schema', () => {
  let pool, stop;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    // startPg() already created `cases`; only `evidence` is missing.
    await pool.query(`CREATE TABLE evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid())`);
    await pool.query(MIGRATION);
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  test('accepts a valid row and rejects an invalid status', async () => {
    const ev = (await pool.query(`INSERT INTO evidence DEFAULT VALUES RETURNING id`)).rows[0].id;
    const cs = (await pool.query(`INSERT INTO cases DEFAULT VALUES RETURNING id`)).rows[0].id;
    const ins = await pool.query(
      `INSERT INTO ingestion_files (evidence_id, case_id, relative_path, sha256, status)
       VALUES ($1,$2,'a/b.mft',repeat('a',64),'received') RETURNING id`, [ev, cs]);
    expect(ins.rows[0].id).toBeTruthy();
    await expect(pool.query(
      `INSERT INTO ingestion_files (evidence_id, case_id, relative_path, sha256, status)
       VALUES ($1,$2,'x',repeat('b',64),'not_a_status')`, [ev, cs])).rejects.toThrow();
  });
});
