// backend/tests/integration/ingestionDedup.test.js
const fs = require('fs'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260708000000_ingestion_files.sql'), 'utf8');

describeIfDocker('dedupService.checkAndRecord', () => {
  let pool, stop, checkAndRecord;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    // NOTE: startPg() already creates `cases` (and `users`, `collection_timeline`)
    // with gen_random_uuid(). Only `evidence` is missing — create just that one.
    await pool.query(`CREATE TABLE evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid())`);
    await pool.query(MIGRATION);
    ({ checkAndRecord } = require('../../src/services/ingestion/dedupService'));
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  const base = (over) => ({ relativePath: 'a/$MFT', fileSize: 10, sha256: 'a'.repeat(64), detectedType: 'mft', parserName: 'mft', parserVersion: '1', confidence: 95, ...over });

  test('skips the same content re-parsed on the same evidence', async () => {
    const ev = (await pool.query('INSERT INTO evidence DEFAULT VALUES RETURNING id')).rows[0].id;
    const cs = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    const first = await checkAndRecord(pool, base({ evidenceId: ev, caseId: cs }));
    await pool.query(`UPDATE ingestion_files SET status='parsed' WHERE id=$1`, [first.ingestionFileId]);
    const second = await checkAndRecord(pool, base({ evidenceId: ev, caseId: cs }));
    expect(second.isDuplicate).toBe(true);
    const row = (await pool.query('SELECT status, dedup_of FROM ingestion_files WHERE id=$1', [second.ingestionFileId])).rows[0];
    expect(row.status).toBe('skipped_duplicate');
    expect(row.dedup_of).toBe(first.ingestionFileId);
  });

  test('re-parses when parser_version is bumped', async () => {
    const ev = (await pool.query('INSERT INTO evidence DEFAULT VALUES RETURNING id')).rows[0].id;
    const cs = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    const a = await checkAndRecord(pool, base({ evidenceId: ev, caseId: cs }));
    await pool.query(`UPDATE ingestion_files SET status='parsed' WHERE id=$1`, [a.ingestionFileId]);
    const b = await checkAndRecord(pool, base({ evidenceId: ev, caseId: cs, parserVersion: '2' }));
    expect(b.isDuplicate).toBe(false);
  });
});
