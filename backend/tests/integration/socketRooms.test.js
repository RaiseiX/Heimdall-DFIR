jest.mock('../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn(),
  ELEVATED: new Set(['admin', 'team_lead']),
}));
jest.mock('../../src/config/queue', () => ({
  parserQueue: { add: jest.fn(), getJobs: jest.fn().mockResolvedValue([]) },
}));
const { canAccessCase } = require('../../src/middleware/caseAccess');
const { parserQueue } = require('../../src/config/queue');

const { startPg, describeIfDocker } = require('../helpers/ephemeralPg');
const { startSocketServer } = require('../helpers/socketHarness');

const waitFor = (socket, event) =>
  new Promise((res, rej) => { const t = setTimeout(() => rej(new Error(`timeout ${event}`)), 3000); socket.once(event, (d) => { clearTimeout(t); res(d); }); });

describeIfDocker('socket rooms', () => {
  let pg, srv, caseId, owner;
  beforeAll(async () => {
    pg = await startPg();
    owner = (await pg.pool.query(`INSERT INTO users (username, role) VALUES ('alice','analyst') RETURNING id, username, role`)).rows[0];
    caseId = (await pg.pool.query(`INSERT INTO cases (created_by) VALUES ($1) RETURNING id`, [owner.id])).rows[0].id;
    srv = await startSocketServer(pg.pool);
  }, 60000);
  afterAll(async () => { if (srv) await srv.stop(); if (pg) await pg.stop(); });

  beforeEach(() => {
    canAccessCase.mockReset().mockImplementation(async (user) => user?.username === 'alice');
    parserQueue.add.mockClear();
  });

  test('member joins and receives case:presence (extraction preserves behavior)', async () => {
    const c = srv.connect({ id: owner.id, username: owner.username, role: owner.role });
    await waitFor(c, 'connect');
    c.emit('case:join', { caseId });
    const presence = await waitFor(c, 'case:presence');
    expect(Array.isArray(presence)).toBe(true);
    expect(presence.some((p) => p.id === owner.id)).toBe(true);
  });

  test('non-member case:join is denied and not roomed', async () => {
    const mallory = (await pg.pool.query(`INSERT INTO users (username, role) VALUES ('mallory','analyst') RETURNING id, username, role`)).rows[0];
    const c = srv.connect({ id: mallory.id, username: mallory.username, role: mallory.role });
    await waitFor(c, 'connect');
    c.emit('case:join', { caseId });
    const denied = await waitFor(c, 'case:join:denied');
    expect(denied.caseId).toBe(caseId);
    let got = false; c.once('evidence:ready', () => { got = true; });
    srv.io.to(`case:${caseId}`).emit('evidence:ready', { evidenceId: 'x', caseId, rollup: {} });
    await new Promise((r) => setTimeout(r, 300));
    expect(got).toBe(false);   // mallory never joined the prefixed room
  });

  test('non-member chat:send writes nothing and errors', async () => {
    const mallory = (await pg.pool.query(`SELECT id, username, role FROM users WHERE username='mallory'`)).rows[0];
    const before = (await pg.pool.query(`SELECT count(*)::int n FROM case_messages WHERE case_id=$1`, [caseId])).rows[0].n;
    const c = srv.connect({ id: mallory.id, username: mallory.username, role: mallory.role });
    await waitFor(c, 'connect');
    const err = waitFor(c, 'chat:error');
    c.emit('chat:send', { caseId, content: 'intrusion' });
    await err;
    const after = (await pg.pool.query(`SELECT count(*)::int n FROM case_messages WHERE case_id=$1`, [caseId])).rows[0].n;
    expect(after).toBe(before);
  });

  test('non-member parser:start enqueues nothing and errors', async () => {
    const mallory = (await pg.pool.query(`SELECT id, username, role FROM users WHERE username='mallory'`)).rows[0];
    parserQueue.add.mockClear();
    const c = srv.connect({ id: mallory.id, username: mallory.username, role: mallory.role });
    await waitFor(c, 'connect');
    const err = waitFor(c, 'parser:error');
    c.emit('parser:start', { caseId, evidenceId: 'e1', parser: 'evtx' });
    await err;
    expect(parserQueue.add).not.toHaveBeenCalled();
  });

  test('member in the case room receives evidence:ready (prefixed room)', async () => {
    const c = srv.connect({ id: owner.id, username: owner.username, role: owner.role });
    await waitFor(c, 'connect');
    c.emit('case:join', { caseId });
    await waitFor(c, 'case:presence');          // joined
    const p = waitFor(c, 'evidence:ready');
    srv.io.to(`case:${caseId}`).emit('evidence:ready', { evidenceId: 'e1', caseId, rollup: { done: 3 } });
    const payload = await p;
    expect(payload.evidenceId).toBe('e1');
    expect(payload.caseId).toBe(caseId);
  });
});
