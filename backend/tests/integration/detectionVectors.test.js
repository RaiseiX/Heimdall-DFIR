const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { SYSMON_BEHAVIOR_VECTORS, TIMESTOMP_QUERY, EXEC_ANOMALY_VECTORS, WMI_PERSISTENCE_VECTORS } = require('../../src/services/detectionVectors');

describeIfDocker('detection vectors — integration (ephemeral PG)', () => {
  let pool, stop;
  const CASE = '11111111-1111-1111-1111-111111111111';
  beforeAll(async () => { ({ pool, stop } = await startPg()); }, 60000);
  afterAll(async () => { if (stop) await stop(); });
  beforeEach(async () => { await pool.query('TRUNCATE collection_timeline'); await pool.query(`INSERT INTO cases(id) VALUES ($1) ON CONFLICT DO NOTHING`, [CASE]); });

  async function insert(row) {
    await pool.query(
      `INSERT INTO collection_timeline (case_id, timestamp, artifact_type, description, source, host_name, raw)
       VALUES ($1, now(), $2, $3, $4, $5, $6)`,
      [CASE, row.artifact_type, row.description || '', row.source || '', row.host_name || 'H1', JSON.stringify(row.raw || {})]);
  }
  function vector(id) { return SYSMON_BEHAVIOR_VECTORS.find(v => v.id === id); }
  async function runVector(id) { return (await pool.query(vector(id).query, [CASE])).rows; }
  function execAnomalyVector(id) { return EXEC_ANOMALY_VECTORS.find(v => v.id === id); }
  async function runExecAnomaly(id) { return (await pool.query(execAnomalyVector(id).query, [CASE])).rows; }
  function wmiVector(id) { return WMI_PERSISTENCE_VECTORS.find(v => v.id === id); }
  async function runWmi(id) { return (await pool.query(wmiVector(id).query, [CASE])).rows; }

  // characterization: the extracted vectors run and the array shape is intact
  test('SYSMON_BEHAVIOR_VECTORS keeps the original vector ids', () => {
    const ids = SYSMON_BEHAVIOR_VECTORS.map(v => v.id);
    expect(ids).toEqual(expect.arrayContaining(['lsass_access','remote_thread','exec_from_temp','unsigned_dll','suspicious_network','process_tampering','suspicious_file_create']));
  });

  test('TIMESTOMP_QUERY runs and matches an $SI<$FN row', async () => {
    await insert({ artifact_type: 'mft', raw: { FileName: 'evil.exe', Created0x10: '2021-01-01 00:00:00', Created0x30: '2023-01-01 00:00:00' } });
    const rows = (await pool.query(TIMESTOMP_QUERY, [CASE])).rows;
    expect(rows.length).toBe(1);
  });

  test('H1 LSASS: mimikatz GrantedAccess 0x1410 → hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'evtx', raw: { EventId: '10', TargetImage: 'C:\\Windows\\System32\\lsass.exe', SourceImage: 'C:\\Temp\\mimikatz.exe', GrantedAccess: '0x1410' } });
    expect((await runVector('lsass_access')).length).toBe(1);
  });
  test('H1 LSASS: benign MsMpEng access (allowlisted source) → 0 hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'evtx', raw: { EventId: '10', TargetImage: 'C:\\Windows\\System32\\lsass.exe', SourceImage: 'C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe', GrantedAccess: '0x1410' } });
    expect((await runVector('lsass_access')).length).toBe(0);
  });
  test('H1 LSASS: mimikatz GrantedAccess 0x1410 → hit (legacy uppercase casing: EventID still supported)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'evtx', raw: { EventID: '10', TargetImage: 'C:\\Windows\\System32\\lsass.exe', SourceImage: 'C:\\Temp\\mimikatz.exe', GrantedAccess: '0x1410' } });
    expect((await runVector('lsass_access')).length).toBe(1);
  });

  test('H3 timestomp: sub-second-zeroed $SI with non-zero $FN → hit', async () => {
    const { insert } = global.__detHelpers; const { pool, CASE } = global.__detHelpers;
    // $SI at a LATER whole second but sub-second-zeroed; $FN earlier with real sub-seconds.
    // Isolates the sub-second branch: the $SI<$FN comparison is FALSE (06 > 05), so ONLY the
    // zeroed-sub-second signal can fire — the classic SetFileTime second-precision timestomp.
    await insert({ artifact_type: 'mft', raw: { FileName: 'x.exe', 'SI<FN': 'False',
      Created0x10: '2023-01-01 10:00:06.0000000', Created0x30: '2023-01-01 10:00:05.1234567' } });
    const { TIMESTOMP_QUERY } = require('../../src/services/detectionVectors');
    expect((await pool().query(TIMESTOMP_QUERY, [CASE])).rows.length).toBe(1);
  });
  test('H3 timestomp: MFTECmd SI<FN=True → hit', async () => {
    const { insert, pool, CASE } = global.__detHelpers;
    await insert({ artifact_type: 'mft', raw: { FileName: 'y.exe', 'SI<FN': 'True',
      Created0x10: '2023-01-01 10:00:00.0000000', Created0x30: '2023-01-01 10:00:00.0000000' } });
    const { TIMESTOMP_QUERY } = require('../../src/services/detectionVectors');
    expect((await pool().query(TIMESTOMP_QUERY, [CASE])).rows.length).toBe(1);
  });
  test('H3 timestomp: SI<FN=True row with a MALFORMED $FN does not 500 the ORDER BY (guarded cast)', async () => {
    const { insert, pool, CASE } = global.__detHelpers;
    // matched only by SI<FN='True'; Created0x30 is not a valid timestamp — the ORDER BY
    // cast must be guarded (CASE regex) so it returns the row instead of throwing.
    await insert({ artifact_type: 'mft', raw: { FileName: 'z.exe', 'SI<FN': 'True',
      Created0x10: '2023-01-01 10:00:00.0000000', Created0x30: '' } });
    const { TIMESTOMP_QUERY } = require('../../src/services/detectionVectors');
    expect((await pool().query(TIMESTOMP_QUERY, [CASE])).rows.length).toBe(1);
  });

  test('H2 masquerading: renamed binary (OriginalFileName ≠ Image basename) → hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runExecAnomaly } = global.__detHelpers;
    await insert({ artifact_type: 'evtx', raw: { EventId: '1', Image: 'C:\\Windows\\svch0st.exe', OriginalFileName: 'powershell.exe' } });
    expect((await runExecAnomaly('masquerading')).length).toBe(1);
  });
  test('H2 masquerading: legit binary (OriginalFileName == Image basename) → 0 hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runExecAnomaly } = global.__detHelpers;
    await insert({ artifact_type: 'evtx', raw: { EventId: '1', Image: 'C:\\Windows\\System32\\svchost.exe', OriginalFileName: 'svchost.exe' } });
    expect((await runExecAnomaly('masquerading')).length).toBe(0);
  });

  test('H5 C2 named pipe: msagent_ pipe (EID 17) → hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '17', PipeName: '\\msagent_42' } });
    expect((await runVector('c2_named_pipe')).length).toBe(1);
  });
  test('H5 C2 named pipe: benign system pipe lsass (EID 17) → 0 hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '17', PipeName: '\\lsass' } });
    expect((await runVector('c2_named_pipe')).length).toBe(0);
  });
  test('H5 C2 named pipe: benign Chromium mojo IPC pipe (EID 17) → 0 hit (not a C2 pattern)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '17', PipeName: '\\mojo.7684.13052.14472' } });
    expect((await runVector('c2_named_pipe')).length).toBe(0);
  });

  test('H7 ADS/MOTW: Zone.Identifier stream on downloaded exe (EID 15) → hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '15', TargetFilename: 'C:\\Users\\Public\\evil.exe:Zone.Identifier' } });
    expect((await runVector('ads_motw')).length).toBe(1);
  });
  test('H7 ADS/MOTW: plain file create, no stream (EID 15) → 0 hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '15', TargetFilename: 'C:\\Users\\Public\\notes.txt' } });
    expect((await runVector('ads_motw')).length).toBe(0);
  });
  test('H7 ADS/MOTW: MOTW on a benign downloaded document (EID 15) → 0 hit (Zone.Identifier is ubiquitous)', async () => {
    const { insert, runVector } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '15', TargetFilename: 'C:\\Users\\Public\\report.pdf:Zone.Identifier' } });
    expect((await runVector('ads_motw')).length).toBe(0);
  });

  test('H4 WMI persistence: EID 20 CommandLineEventConsumer → powershell -enc (hit) (real EvtxECmd casing: EventId)', async () => {
    const { insert, runWmi } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '20', Consumer: 'CommandLineEventConsumer', Destination: 'powershell.exe -enc SQBFAFgA' } });
    expect((await runWmi('wmi_binding')).length).toBe(1);
  });
  test('H4 WMI persistence: EID 20 benign NTEventLogEventConsumer (log consumer, no script/exec destination) → 0 hit (real EvtxECmd casing: EventId)', async () => {
    const { insert, runWmi } = global.__detHelpers;
    await insert({ artifact_type: 'sysmon', raw: { EventId: '20', Consumer: 'NTEventLogEventConsumer', Destination: 'Application' } });
    expect((await runWmi('wmi_binding')).length).toBe(0);
  });

  // expose helpers to later tasks via module-scope (re-declared per task file section)
  global.__detHelpers = { insert, runVector, runExecAnomaly, runWmi, pool: () => pool, CASE };
});
