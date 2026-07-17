const fs = require('fs');
const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { loadCatalog } = require('../../src/services/dfiqCatalog');

const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260703000000_dfiq.sql'), 'utf8');
const CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, '../../data/dfiq/catalog.json'), 'utf8'));

describeIfDocker('dfiq catalog seed (ephemeral PG)', () => {
  let pool, stop;
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE TABLE IF NOT EXISTS timeline_bookmarks (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), case_id uuid)`);
    await pool.query(MIGRATION);
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });

  test('seed is idempotent and preserves custom rows', async () => {
    const a = await loadCatalog(pool, CATALOG);
    expect(a.scenarios).toBeGreaterThan(0);
    const c1 = (await pool.query('SELECT COUNT(*)::int n FROM dfiq_scenarios')).rows[0].n;
    // add a custom scenario (NULL dfiq_id, as required by the CHECK constraint) + a custom
    // question under it (also NULL dfiq_id) — these are the rows a re-seed must never touch.
    const customScenario = await pool.query(
      `INSERT INTO dfiq_scenarios (title, is_custom) VALUES ('mine', TRUE) RETURNING id`);
    const customScenarioId = customScenario.rows[0].id;
    await pool.query(
      `INSERT INTO dfiq_questions (scenario_id, text, is_custom) VALUES ($1, 'my custom question', TRUE)`,
      [customScenarioId]);

    await loadCatalog(pool, CATALOG); // re-seed
    const c2 = (await pool.query('SELECT COUNT(*)::int n FROM dfiq_scenarios')).rows[0].n;
    expect(c2).toBe(c1 + 1); // no dupes from re-seed; custom untouched
    const custom = await pool.query(`SELECT id, title, is_custom FROM dfiq_scenarios WHERE is_custom = TRUE`);
    expect(custom.rows).toHaveLength(1);
    expect(custom.rows[0].id).toBe(customScenarioId);
    expect(custom.rows[0].title).toBe('mine');
    expect(custom.rows[0].is_custom).toBe(true);

    const customQ = await pool.query(
      `SELECT text, is_custom FROM dfiq_questions WHERE scenario_id = $1 AND is_custom = TRUE`,
      [customScenarioId]);
    expect(customQ.rows).toHaveLength(1);
    expect(customQ.rows[0].text).toBe('my custom question');
    expect(customQ.rows[0].is_custom).toBe(true);

    // approaches replaced (DELETE+INSERT per question), not duplicated on re-seed:
    // the DB total must equal the catalog's exact approach count, whatever it is.
    const expectedApproaches = CATALOG.scenarios.reduce(
      (n, s) => n + s.questions.reduce((m, q) => m + (q.approaches ? q.approaches.length : 0), 0), 0);
    const apTotal = (await pool.query(`SELECT COUNT(*)::int n FROM dfiq_approaches`)).rows[0].n;
    expect(apTotal).toBe(expectedApproaches);
  });

  test('CHECK constraint rejects a custom row with a non-NULL dfiq_id', async () => {
    await expect(
      pool.query(`INSERT INTO dfiq_scenarios (dfiq_id, title, is_custom) VALUES ('S1001','x',TRUE)`)
    ).rejects.toMatchObject({ code: '23514' }); // 23514 = check_violation
  });
});
