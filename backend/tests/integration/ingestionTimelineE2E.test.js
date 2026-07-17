const fs = require('fs'); const os = require('os'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { importCsvToTimeline } = require('../../src/services/ingestionTimeline');
const { SYSMON_BEHAVIOR_VECTORS } = require('../../src/services/detectionVectors');

describeIfDocker('ingested evtx reaches the hunt (collection_timeline)', () => {
  let pool, stop, caseId, resultId;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    caseId = (await pool.query(`INSERT INTO cases (created_by) VALUES (NULL) RETURNING id`)).rows[0].id;
    resultId = (await pool.query(
      `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1,'EvtxECmd','2.0','x','[]'::jsonb,0,NULL) RETURNING id`, [caseId])).rows[0].id;
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  test('a Sysmon row imported via importCsvToTimeline is visible to a SYSMON_BEHAVIOR_VECTOR query', async () => {
    const csv = path.join(os.tmpdir(), `sysmon-${Date.now()}.csv`);
    // Row satisfies the 'lsass_access' vector (EventId 10, TargetImage lsass.exe,
    // GrantedAccess in the mask set, SourceImage not in the noise allowlist). All 9
    // columns fall within buildSlimRaw's first-15-fields window, so TargetImage/
    // SourceImage/GrantedAccess survive into `raw` unmodified (verified against
    // backend/src/services/timelineFieldExtract.js buildSlimRaw()).
    fs.writeFileSync(csv,
      'TimeCreated,Channel,EventId,Computer,MapDescription,SourceImage,TargetImage,GrantedAccess,EventRecordId\n' +
      '2024-05-01 10:00:00,Microsoft-Windows-Sysmon/Operational,10,HOST1,Process accessed,C:\\\\mimikatz.exe,C:\\\\Windows\\\\system32\\\\lsass.exe,0x1410,7\n');
    const n = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'evtx' });
    expect(n).toBe(1);
    let hits = 0;
    for (const v of SYSMON_BEHAVIOR_VECTORS) { const res = await pool.query(v.query, [caseId]); hits += res.rows.length; }
    expect(hits).toBeGreaterThan(0);
    fs.unlinkSync(csv);
  });
});
