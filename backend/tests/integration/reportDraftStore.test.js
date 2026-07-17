const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { loadDraft, saveDraft } = require('../../src/services/reportDraftStore');

describeIfDocker('reportDraftStore', () => {
  let pg, caseId;
  beforeAll(async () => {
    pg = await startPg();
    const u = await pg.pool.query(`INSERT INTO users (username, full_name, password_hash, role) VALUES ('rd','RD','x','analyst') RETURNING id`);
    const c = await pg.pool.query(`INSERT INTO cases (title, case_number, status, created_by) VALUES ('C','RD-1','open',$1) RETURNING id`, [u.rows[0].id]);
    caseId = c.rows[0].id;
  });
  afterAll(async () => { if (pg) await pg.stop(); });

  it('returns null when no draft exists', async () => {
    expect(await loadDraft(pg.pool, caseId)).toBeNull();
  });

  it('saves then loads the ydoc bytes and upserts on conflict', async () => {
    await saveDraft(pg.pool, caseId, Buffer.from([1, 2, 3]), { executive_summary: 'hi' });
    const a = await loadDraft(pg.pool, caseId);
    expect(Buffer.isBuffer(a)).toBe(true);
    expect(Array.from(a)).toEqual([1, 2, 3]);
    await saveDraft(pg.pool, caseId, Buffer.from([9]), { executive_summary: 'bye' });
    const b = await loadDraft(pg.pool, caseId);
    expect(Array.from(b)).toEqual([9]);
    const snap = await pg.pool.query('SELECT text_snapshot FROM report_drafts WHERE case_id=$1', [caseId]);
    expect(snap.rows[0].text_snapshot).toEqual({ executive_summary: 'bye' });
  });
});
