// backend/tests/integration/huntReconcile.test.js
const fs = require('fs'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260709000000_hunt_runs.sql'), 'utf8');

describeIfDocker('reconcileStaleHunts', () => {
  let pool, stop, hr;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    await pool.query(MIGRATION);                       // startPg already made `cases`
    hr = require('../../src/services/huntRuns');
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  const steps = [{ key: 'yara', label: 'YARA', status: 'pending', count: null, error: null }];

  test('reclaims stale running hunts as error, leaves fresh running and done hunts untouched', async () => {
    const staleCase = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    const freshCase = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;
    const doneCase = (await pool.query('INSERT INTO cases DEFAULT VALUES RETURNING id')).rows[0].id;

    // Stale: 'running' with updated_at 40 minutes in the past (crashed worker, heartbeat frozen).
    const stale = await hr.startHuntRun(pool, staleCase, 'auto', null, steps);
    await pool.query(`UPDATE hunt_runs SET updated_at = NOW() - interval '40 minutes' WHERE id = $1`, [stale.huntRunId]);

    // Fresh: 'running' with updated_at just now (live run, heartbeat current).
    const fresh = await hr.startHuntRun(pool, freshCase, 'auto', null, steps);

    // Done: finished run, should never be touched regardless of updated_at.
    const done = await hr.startHuntRun(pool, doneCase, 'auto', null, steps);
    await hr.finishHuntRun(pool, done.huntRunId, 'done');
    await pool.query(`UPDATE hunt_runs SET updated_at = NOW() - interval '40 minutes' WHERE id = $1`, [done.huntRunId]);

    const reclaimed = await hr.reconcileStaleHunts(pool, 30);
    expect(reclaimed).toBe(1);

    const staleRow = (await pool.query('SELECT status FROM hunt_runs WHERE id = $1', [stale.huntRunId])).rows[0];
    expect(staleRow.status).toBe('error');

    const freshRow = (await pool.query('SELECT status FROM hunt_runs WHERE id = $1', [fresh.huntRunId])).rows[0];
    expect(freshRow.status).toBe('running');

    const doneRow = (await pool.query('SELECT status FROM hunt_runs WHERE id = $1', [done.huntRunId])).rows[0];
    expect(doneRow.status).toBe('done');

    // The per-case guard is released: a new hunt can now start for the reclaimed case.
    const restarted = await hr.startHuntRun(pool, staleCase, 'auto', null, steps);
    expect(restarted.started).toBe(true);
  });
});
