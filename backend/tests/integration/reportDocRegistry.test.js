const Y = require('yjs');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const reg = require('../../src/services/reportDocRegistry');
const { loadDraft } = require('../../src/services/reportDraftStore');

describeIfDocker('reportDocRegistry', () => {
  let pg, caseId, userId;
  beforeAll(async () => {
    pg = await startPg();
    const u = await pg.pool.query(`INSERT INTO users (username, full_name, password_hash, role) VALUES ('rg','RG','x','analyst') RETURNING id`);
    userId = u.rows[0].id;
    const c = await pg.pool.query(`INSERT INTO cases (title, case_number, status, created_by) VALUES ('C','RG-1','open',$1) RETURNING id`, [userId]);
    caseId = c.rows[0].id;
  });
  afterAll(async () => { if (pg) await pg.stop(); });

  it('round-trips: apply an update, flush, and a fresh getDoc reproduces the text', async () => {
    const doc = await reg.getDoc(pg.pool, caseId);
    reg.addSubscriber(caseId);
    // simulate a client edit encoded as an update
    const client = new Y.Doc();
    client.getText('executive_summary').insert(0, 'hello world');
    const update = Y.encodeStateAsUpdate(client);
    reg.applyRemoteUpdate(pg.pool, caseId, update);
    expect(doc.getText('executive_summary').toString()).toBe('hello world');
    await reg.flush(pg.pool, caseId);
    // persisted
    const buf = await loadDraft(pg.pool, caseId);
    expect(buf).not.toBeNull();
    // releasing the last subscriber evicts + flushes; a fresh getDoc reloads from DB
    await reg.releaseDoc(pg.pool, caseId);
    const reloaded = await reg.getDoc(pg.pool, caseId);
    expect(reloaded.getText('executive_summary').toString()).toBe('hello world');
    await reg.releaseDoc(pg.pool, caseId);
  });

  it('acquireDoc: concurrent first-access returns the SAME doc instance and counts both subscribers', async () => {
    // fresh caseId not yet cached
    const c2 = await pg.pool.query(`INSERT INTO cases (title, case_number, status, created_by) VALUES ('C2','RG-2','open',$1) RETURNING id`, [userId]);
    const id2 = c2.rows[0].id;
    const [d1, d2] = await Promise.all([reg.acquireDoc(pg.pool, id2), reg.acquireDoc(pg.pool, id2)]);
    expect(d1).toBe(d2); // same Y.Doc instance, no duplicate
    d1.getText('executive_summary').insert(0, 'x');
    expect(d2.getText('executive_summary').toString()).toBe('x'); // shared doc
    await reg.releaseDoc(pg.pool, id2);
    // one subscriber left -> not evicted
    const d3 = await reg.getDoc(pg.pool, id2);
    expect(d3).toBe(d1);
    await reg.releaseDoc(pg.pool, id2); // now evicts
  });
});
