jest.mock('../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn(),
  ELEVATED: new Set(['admin', 'team_lead']),
}));
jest.mock('../../src/config/queue', () => ({
  parserQueue: { add: jest.fn(), getJobs: jest.fn().mockResolvedValue([]) },
}));
const Y = require('yjs');
const { canAccessCase } = require('../../src/middleware/caseAccess');
const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { startSocketServer } = require('../helpers/socketHarness');
const reportDocs = require('../../src/services/reportDocRegistry');

const waitFor = (socket, event) =>
  new Promise((res, rej) => { const t = setTimeout(() => rej(new Error(`timeout ${event}`)), 3000); socket.once(event, (d) => { clearTimeout(t); res(d); }); });

describeIfDocker('report collab relay', () => {
  let pg, srv, caseId, user;
  beforeAll(async () => {
    pg = await startPg();
    const u = await pg.pool.query(
      `INSERT INTO users (username, full_name, password_hash, role) VALUES ('rc','RC','x','analyst') RETURNING id, username, full_name, role`
    );
    user = u.rows[0];
    const c = await pg.pool.query(
      `INSERT INTO cases (title, case_number, status, created_by) VALUES ('C','RC-1','open',$1) RETURNING id`,
      [user.id]
    );
    caseId = c.rows[0].id;
    srv = await startSocketServer(pg.pool);
  }, 60000);
  afterAll(async () => { if (srv) await srv.stop(); if (pg) await pg.stop(); });

  test('relays a client update to a peer in the same case room', async () => {
    canAccessCase.mockReset().mockResolvedValue(true);
    const a = srv.connect(user);
    const b = srv.connect(user);
    await Promise.all([waitFor(a, 'connect'), waitFor(b, 'connect')]);
    a.emit('case:join', { caseId }); b.emit('case:join', { caseId });
    await Promise.all([waitFor(a, 'case:presence'), waitFor(b, 'case:presence')]);
    a.emit('report:join', { caseId }); b.emit('report:join', { caseId });
    await Promise.all([waitFor(a, 'report:state'), waitFor(b, 'report:state')]);

    const doc = new Y.Doc();
    doc.getText('key_findings').insert(0, 'lateral movement via SMB');
    const update = Buffer.from(Y.encodeStateAsUpdate(doc)).toString('base64');
    const got = waitFor(b, 'report:update');
    a.emit('report:update', { caseId, update });
    const msg = await got;
    const peer = new Y.Doc();
    Y.applyUpdate(peer, new Uint8Array(Buffer.from(msg.update, 'base64')));
    expect(peer.getText('key_findings').toString()).toBe('lateral movement via SMB');
    a.close(); b.close();
  });

  test('rejects report:update from a socket without case access (no relay)', async () => {
    canAccessCase.mockReset().mockResolvedValue(false);
    const a = srv.connect(user);
    const b = srv.connect(user);
    await Promise.all([waitFor(a, 'connect'), waitFor(b, 'connect')]);
    let relayed = false; b.on('report:update', () => { relayed = true; });
    a.emit('report:update', { caseId, update: Buffer.from(Y.encodeStateAsUpdate(new Y.Doc())).toString('base64') });
    await new Promise((r) => setTimeout(r, 300));
    expect(relayed).toBe(false);
    a.close(); b.close();
  });

  test('re-join on the same socket does not over-count subscribers (evicts after leave)', async () => {
    canAccessCase.mockReset().mockResolvedValue(true);
    const a = srv.connect(user);
    await waitFor(a, 'connect');
    a.emit('case:join', { caseId });
    await waitFor(a, 'case:presence');
    a.emit('report:join', { caseId }); await waitFor(a, 'report:state');
    a.emit('report:join', { caseId }); await waitFor(a, 'report:state'); // re-join
    expect(reportDocs.subscriberCount(caseId)).toBe(1);                   // NOT 2
    a.emit('case:leave', { caseId });
    await new Promise((r) => setTimeout(r, 200));
    expect(reportDocs.subscriberCount(caseId)).toBe(0);                   // evicted
    a.close();
  });
});
