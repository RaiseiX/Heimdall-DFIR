const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { fetchContext, AnchorNotFound } = require('../../src/services/timelineContext');

describeIfDocker('timeline context (ephemeral PG)', () => {
  let pool, stop;
  const CASE = '11111111-1111-1111-1111-111111111111';
  beforeAll(async () => { ({ pool, stop } = await startPg()); }, 60000);
  afterAll(async () => { if (stop) await stop(); });
  beforeEach(async () => {
    await pool.query('TRUNCATE collection_timeline');
    await pool.query(`INSERT INTO cases(id) VALUES ($1) ON CONFLICT DO NOTHING`, [CASE]);
  });

  // insert with explicit timestamp + host; returns the new id
  async function ins(ts, host, extra = {}) {
    const r = await pool.query(
      `INSERT INTO collection_timeline (case_id, timestamp, artifact_type, description, source, host_name, raw)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [CASE, ts, extra.artifact_type || 'evtx', extra.description || '', extra.source || '', host, JSON.stringify(extra.raw || {})]);
    return r.rows[0].id;
  }
  const t = (s) => `2026-01-01T10:00:${String(s).padStart(2, '0')}Z`;

  test('±N same-host neighbors + anchor, chronological, filters ignored', async () => {
    await ins(t(1), 'DC01', { artifact_type: 'mft' });
    await ins(t(2), 'DC01', { artifact_type: 'evtx' });
    const anchor = await ins(t(3), 'DC01', { artifact_type: 'registry' });
    await ins(t(4), 'DC01', { artifact_type: 'evtx' });
    await ins(t(5), 'DC01', { artifact_type: 'amcache' });
    await ins(t(3), 'WS01', { artifact_type: 'evtx' }); // other host, same time → excluded by default
    const { rows, host_name } = await fetchContext(pool, CASE, anchor, { n: 2 });
    expect(host_name).toBe('DC01');
    expect(rows.map(r => r.artifact_type)).toEqual(['mft', 'evtx', 'registry', 'evtx', 'amcache']);
    expect(rows.find(r => r.is_anchor).id).toBe(anchor);
    expect(rows.every(r => r.host_name === 'DC01')).toBe(true);
  });

  test('all_hosts=true includes other hosts', async () => {
    await ins(t(1), 'WS01');
    const anchor = await ins(t(2), 'DC01');
    await ins(t(3), 'WS01');
    const same = await fetchContext(pool, CASE, anchor, { n: 5, allHosts: false });
    expect(same.rows.length).toBe(1); // only the anchor — no other DC01 rows
    const all = await fetchContext(pool, CASE, anchor, { n: 5, allHosts: true });
    expect(all.rows.length).toBe(3); // WS01 before + anchor + WS01 after
  });

  test('tie-break by id when timestamps are equal', async () => {
    const ts = '2026-01-01T10:00:00Z';
    const a = await ins(ts, 'DC01');
    const b = await ins(ts, 'DC01');
    const c = await ins(ts, 'DC01');
    const { rows } = await fetchContext(pool, CASE, a, { n: 5 });
    expect(rows.map(r => r.id)).toEqual([a, b, c]);
    expect(rows[0].is_anchor).toBe(true);
  });

  test('anchor not found throws AnchorNotFound', async () => {
    await expect(fetchContext(pool, CASE, 999999, {})).rejects.toBeInstanceOf(AnchorNotFound);
  });

  test('n is clamped (n=1 → 1 before + anchor + 1 after)', async () => {
    let anchor;
    for (let i = 0; i < 10; i++) { const id = await ins(t(i), 'DC01'); if (i === 5) anchor = id; }
    const { rows } = await fetchContext(pool, CASE, anchor, { n: 1 });
    expect(rows.length).toBe(3);
    expect(rows[1].is_anchor).toBe(true);
  });
});
