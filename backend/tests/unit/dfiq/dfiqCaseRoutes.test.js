// Route-level security-guard tests for dfiqCase.js — pool, auth, and caseAccess mocked.
// Focus: case isolation. canAccessCase gates every route; instanceInCase gates per-instance
// routes; the evidence route additionally enforces the bookmark belongs to the same case.
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(),
}));
jest.mock('../../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn().mockResolvedValue(true),
}));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const { canAccessCase } = require('../../../src/middleware/caseAccess');
const dfiqCaseRouter = require('../../../src/routes/dfiqCase');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/cases/:caseId/dfiq', dfiqCaseRouter);
  return app;
}

const BASE = '/api/cases/c-1/dfiq';

beforeEach(() => {
  pool.query.mockReset();
  canAccessCase.mockReset().mockResolvedValue(true);
  mockUser = { id: 'user-1', role: 'analyst' };
});

describe('dfiq case routes — security guards', () => {
  test('canAccessCase=false blocks GET / with 403 and no query runs', async () => {
    canAccessCase.mockResolvedValueOnce(false);
    const res = await request(makeApp(), 'GET', BASE);
    expect(res.status).toBe(403);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('canAccessCase=false blocks POST /attach with 403 and no query runs', async () => {
    canAccessCase.mockResolvedValueOnce(false);
    const res = await request(makeApp(), 'POST', `${BASE}/attach`, { scenario_id: 's1' });
    expect(res.status).toBe(403);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('DELETE /:instanceId on an instance not in this case returns 404', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] }); // instanceInCase SELECT finds nothing
    const res = await request(makeApp(), 'DELETE', `${BASE}/other-inst`);
    expect(res.status).toBe(404);
    expect(pool.query).toHaveBeenCalledTimes(1); // only the guard SELECT, no DELETE issued
  });

  test('GET /:instanceId/answers on an instance not in this case returns 404', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] }); // instanceInCase SELECT finds nothing
    const res = await request(makeApp(), 'GET', `${BASE}/other-inst/answers`);
    expect(res.status).toBe(404);
    expect(pool.query).toHaveBeenCalledTimes(1);
  });

  test('POST evidence with a bookmark outside this case returns 400 and inserts nothing', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [{ id: 'inst-1' }] }) // instanceInCase passes
      .mockResolvedValueOnce({ rows: [] });                // bookmark SELECT finds nothing (wrong case)
    const res = await request(makeApp(), 'POST', `${BASE}/inst-1/answers/q-1/evidence`, { bookmark_id: 'bm-foreign' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/hors de ce cas/);
    expect(pool.query).toHaveBeenCalledTimes(2); // guard + bookmark check only, no evidence insert
  });

  test('POST evidence with a bookmark inside this case succeeds and inserts', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [{ id: 'inst-1' }] })     // instanceInCase passes
      .mockResolvedValueOnce({ rows: [{ id: 'bm-1' }] })       // bookmark belongs to case
      .mockResolvedValueOnce({ rows: [{ id: 'ans-1' }] })      // answer upsert
      .mockResolvedValueOnce({ rows: [] });                    // evidence insert
    const res = await request(makeApp(), 'POST', `${BASE}/inst-1/answers/q-1/evidence`, { bookmark_id: 'bm-1' });
    expect(res.status).toBe(201);
    expect(pool.query).toHaveBeenCalledTimes(4);
  });
});
