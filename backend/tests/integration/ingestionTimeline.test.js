const fs = require('fs'); const os = require('os'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { importCsvToTimeline } = require('../../src/services/ingestionTimeline');

describeIfDocker('importCsvToTimeline', () => {
  let pool, stop, caseId, resultId;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    caseId = (await pool.query(`INSERT INTO cases (created_by) VALUES (NULL) RETURNING id`)).rows[0].id;
    resultId = (await pool.query(
      `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1,'EvtxECmd','2.0','x','[]'::jsonb,0,NULL) RETURNING id`, [caseId])).rows[0].id;
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  test('imports evtx CSV rows into collection_timeline with raw + timestamp + dedupe; re-import is idempotent', async () => {
    const csv = path.join(os.tmpdir(), `evtx-${Date.now()}.csv`);
    fs.writeFileSync(csv,
      'TimeCreated,Channel,EventId,Computer,MapDescription,Image,CommandLine,EventRecordId\n' +
      '2024-01-02 03:04:05,Security,4688,HOST1,Process created,C:\\evil.exe,evil.exe -run,100\n' +
      '2024-01-02 03:04:06,Security,4688,HOST1,Process created,C:\\ok.exe,ok.exe,101\n');
    const n = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'evtx' });
    expect(n).toBe(2);
    const r = await pool.query(
      `SELECT artifact_type, host_name, raw->>'Image' AS image, raw->>'EventId' AS eid, dedupe_hash
         FROM collection_timeline WHERE case_id=$1 ORDER BY timestamp`, [caseId]);
    expect(r.rows.length).toBe(2);
    expect(r.rows[0].artifact_type).toBe('evtx');
    expect(r.rows[0].host_name).toBe('HOST1');
    expect(r.rows[0].image).toBe('C:\\evil.exe');
    expect(r.rows[0].eid).toBe('4688');
    expect(r.rows[0].dedupe_hash).toMatch(/^[0-9a-f]{16}$/);
    const n2 = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'evtx' });
    expect(n2).toBe(0);
    fs.unlinkSync(csv);
  });
});
