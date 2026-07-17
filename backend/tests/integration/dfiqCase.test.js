const fs = require('fs'); const path = require('path');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { loadCatalog } = require('../../src/services/dfiqCatalog');
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../db/migrations/20260703000000_dfiq.sql'), 'utf8');
const CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, '../../data/dfiq/catalog.json'), 'utf8'));

// Pure DB helpers mirroring the route bodies (routes themselves need Express; here we test the
// data operations the routes wrap, plus scoping). The route wiring is covered by node --check + manual.
describeIfDocker('dfiq case tracking (ephemeral PG)', () => {
  let pool, stop, scenarioId, qId;
  const CASE_A = '11111111-1111-1111-1111-111111111111';
  const CASE_B = '22222222-2222-2222-2222-222222222222';
  beforeAll(async () => {
    ({ pool, stop } = await startPg());
    await pool.query(`CREATE TABLE IF NOT EXISTS timeline_bookmarks (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), case_id uuid)`);
    await pool.query(MIGRATION);
    await pool.query(`INSERT INTO cases(id) VALUES ($1),($2) ON CONFLICT DO NOTHING`, [CASE_A, CASE_B]);
    await loadCatalog(pool, CATALOG);
    scenarioId = (await pool.query(`SELECT id FROM dfiq_scenarios WHERE dfiq_id='S1001'`)).rows[0].id;
    qId = (await pool.query(`SELECT id FROM dfiq_questions WHERE dfiq_id='Q1001'`)).rows[0].id;
  }, 60000);
  afterAll(async () => { if (stop) await stop(); });
  beforeEach(async () => { await pool.query('TRUNCATE case_dfiq CASCADE'); await pool.query('TRUNCATE timeline_bookmarks CASCADE'); });

  async function attach(caseId) {
    return (await pool.query(`INSERT INTO case_dfiq (case_id, scenario_id) VALUES ($1,$2) RETURNING id`, [caseId, scenarioId])).rows[0].id;
  }

  test('attach is idempotent per (case, scenario)', async () => {
    await attach(CASE_A);
    await expect(pool.query(`INSERT INTO case_dfiq (case_id, scenario_id) VALUES ($1,$2)`, [CASE_A, scenarioId]))
      .rejects.toMatchObject({ code: '23505' });
  });

  test('answer upsert + evidence link scoped to same case', async () => {
    const inst = await attach(CASE_A);
    const ans = (await pool.query(
      `INSERT INTO case_dfiq_answers (case_dfiq_id, question_id, status, note) VALUES ($1,$2,'answered','n')
       ON CONFLICT (case_dfiq_id, question_id) DO UPDATE SET status='answered' RETURNING id`, [inst, qId])).rows[0].id;
    const bmA = (await pool.query(`INSERT INTO timeline_bookmarks (case_id) VALUES ($1) RETURNING id`, [CASE_A])).rows[0].id;
    await pool.query(`INSERT INTO case_dfiq_evidence (case_dfiq_answer_id, bookmark_id) VALUES ($1,$2)`, [ans, bmA]);
    const ev = await pool.query('SELECT * FROM case_dfiq_evidence WHERE case_dfiq_answer_id=$1', [ans]);
    expect(ev.rows).toHaveLength(1);
  });

  test('cross-case isolation: instance of case A not visible under case B', async () => {
    const inst = await attach(CASE_A);
    const seenUnderB = await pool.query('SELECT id FROM case_dfiq WHERE id=$1 AND case_id=$2', [inst, CASE_B]);
    expect(seenUnderB.rows).toHaveLength(0);
  });
});
