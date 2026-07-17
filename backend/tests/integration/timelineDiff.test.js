const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { diffTimelines } = require('../../src/services/timelineDiff');

describeIfDocker('timeline diff (ephemeral PG)', () => {
  let pool, stop;
  const CASE = '11111111-1111-1111-1111-111111111111';
  const OTHER = '22222222-2222-2222-2222-222222222222';
  const EV_A = 'aaaaaaaa-0000-0000-0000-000000000000';
  const EV_B = 'bbbbbbbb-0000-0000-0000-000000000000';
  beforeAll(async () => { ({ pool, stop } = await startPg()); }, 60000);
  afterAll(async () => { if (stop) await stop(); });
  beforeEach(async () => {
    await pool.query('TRUNCATE collection_timeline');
    await pool.query(`INSERT INTO cases(id) VALUES ($1),($2) ON CONFLICT DO NOTHING`, [CASE, OTHER]);
  });

  // insert a timeline row; hash null => composite fallback path
  async function ins(caseId, ev, host, ts, artifact, desc, hash) {
    await pool.query(
      `INSERT INTO collection_timeline (case_id, evidence_id, host_name, timestamp, artifact_type, description, source, dedupe_hash)
       VALUES ($1,$2,$3,$4,$5,$6,'',$7)`,
      [caseId, ev, host, ts, artifact, desc, hash]);
  }
  const t = (s) => `2026-01-01T10:00:${String(s).padStart(2,'0')}Z`;

  test('added / removed / unchanged by dedupe_hash between two evidences', async () => {
    // shared (unchanged): same event on both sides, matched via the composite fallback key.
    // NOTE: real ingestion never produces two rows with the same (case_id, dedupe_hash) —
    // uq_ct_case_dedupe (partial unique index) rejects the second one via ON CONFLICT DO
    // NOTHING. A non-null hash shared by both rows would violate that constraint, so both
    // rows here use a null hash, landing on the composite (ts+type+host+desc) fallback key —
    // still exercising the cross-evidence "unchanged" match without violating the constraint.
    await ins(CASE, EV_A, 'DC01', t(1), 'evtx', 'shared', null);
    await ins(CASE, EV_B, 'DC01', t(1), 'evtx', 'shared', null);
    // only in A (removed)
    await ins(CASE, EV_A, 'DC01', t(2), 'mft', 'goneA', 'H2');
    // only in B (added)
    await ins(CASE, EV_B, 'DC01', t(3), 'registry', 'newB', 'H3');
    await ins(CASE, EV_B, 'DC01', t(4), 'amcache', 'newB2', 'H4');
    const r = await diffTimelines(pool, CASE, { evidenceId: EV_A }, { evidenceId: EV_B }, {});
    expect(r.counts).toEqual({ added: 2, removed: 1, unchanged: 1 });
    expect(r.added.map(x => x.description).sort()).toEqual(['newB', 'newB2']);
    expect(r.removed.map(x => x.description)).toEqual(['goneA']);
    expect(r.added.every(x => x.diff_side === 'added')).toBe(true);
  });

  test('null dedupe_hash falls back to composite key (identical rows = unchanged)', async () => {
    await ins(CASE, EV_A, 'DC01', t(5), 'evtx', 'same-composite', null);
    await ins(CASE, EV_B, 'DC01', t(5), 'evtx', 'same-composite', null); // same ts+type+host+desc => same key
    await ins(CASE, EV_B, 'DC01', t(6), 'evtx', 'different', null);
    const r = await diffTimelines(pool, CASE, { evidenceId: EV_A }, { evidenceId: EV_B }, {});
    expect(r.counts).toEqual({ added: 1, removed: 0, unchanged: 1 });
  });

  test('host-scoped diff ignores other hosts', async () => {
    await ins(CASE, EV_A, 'DC01', t(1), 'evtx', 'dc', 'HD');
    await ins(CASE, EV_A, 'WS01', t(1), 'evtx', 'ws', 'HW');
    await ins(CASE, EV_B, 'DC01', t(2), 'evtx', 'dc2', 'HD2');
    const r = await diffTimelines(pool, CASE, { evidenceId: EV_A, hostName: 'DC01' }, { evidenceId: EV_B, hostName: 'DC01' }, {});
    expect(r.counts).toEqual({ added: 1, removed: 1, unchanged: 0 }); // WS01 excluded
  });

  test('case-scoped: another case never leaks in', async () => {
    await ins(OTHER, EV_A, 'DC01', t(1), 'evtx', 'other', 'HX');
    await ins(CASE,  EV_B, 'WS01', t(1), 'evtx', 'mine',  'HY');
    const r = await diffTimelines(pool, CASE, { hostName: 'DC01' }, { evidenceId: EV_B }, {});
    // side A = all DC01 rows in CASE (none), side B = EV_B rows in CASE (1) => added 1, nothing from OTHER
    expect(r.counts.added).toBe(1);
    expect(r.removed).toEqual([]);
  });

  test('row lists are capped but counts stay true', async () => {
    for (let i = 0; i < 5; i++) await ins(CASE, EV_B, 'DC01', t(i), 'evtx', 'b'+i, 'K'+i);
    const r = await diffTimelines(pool, CASE, { evidenceId: EV_A }, { evidenceId: EV_B }, { limit: 2 });
    expect(r.counts.added).toBe(5);
    expect(r.added.length).toBe(2);
  });
});
