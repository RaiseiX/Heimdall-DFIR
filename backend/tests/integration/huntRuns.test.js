// backend/tests/integration/huntRuns.test.js
const fs = require('fs'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260709000000_hunt_runs.sql'), 'utf8');

describeIfDocker('huntRuns store', () => {
  let pool, stop, hr;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    await pool.query(MIGRATION);                       // startPg already made `cases`
    hr = require('../../src/services/huntRuns');
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  const steps = [{ key: 'yara', label: 'YARA', status: 'pending', count: null, error: null }];

  test('guards to one running hunt per case, then updates + finishes', async () => {
    const cs = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    const a = await hr.startHuntRun(pool, cs, 'auto', null, steps);
    expect(a.started).toBe(true);
    const b = await hr.startHuntRun(pool, cs, 'auto', null, steps);   // already running
    expect(b.started).toBe(false);
    await hr.updateHuntStep(pool, a.huntRunId, 'yara', { status: 'done', count: 3 });
    let run = await hr.getHuntRun(pool, cs);
    expect(run.status).toBe('running');
    expect(run.steps.find(s => s.key === 'yara')).toMatchObject({ status: 'done', count: 3 });
    await hr.finishHuntRun(pool, a.huntRunId, 'done');
    run = await hr.getHuntRun(pool, cs);
    expect(run.status).toBe('done');
    const c = await hr.startHuntRun(pool, cs, 'auto', null, steps);   // no longer running → allowed
    expect(c.started).toBe(true);
  });
});
