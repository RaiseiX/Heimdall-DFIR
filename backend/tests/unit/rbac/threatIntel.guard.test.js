// Route-level security-guard test for threatIntel.ts — pool + auth mocked, real caseAccessParam
// (so the test also proves authenticate runs before it: req.user must be set).
// The router also fires an un-awaited `initTables(pool)` call on every request (line 59-63
// in threatIntel.ts) and, on the admin path, correlateCase() reaches a real @elastic/elasticsearch
// client — both are mocked away below so the test stays fast/deterministic and only exercises
// the caseAccessParam guard.
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(), requireRole: () => (_req, _res, next) => next(),
}));
jest.mock('@elastic/elasticsearch', () => ({
  Client: jest.fn().mockImplementation(() => ({
    indices: { exists: jest.fn().mockResolvedValue(false) },
    count: jest.fn().mockResolvedValue({ count: 0 }),
  })),
}));
const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const threatIntelRouter = require('../../../src/routes/threatIntel');

function makeApp() { const app = express(); app.use(express.json()); app.locals.pool = pool; app.use('/api/threat-intel', threatIntelRouter); return app; }
beforeEach(() => {
  pool.query.mockReset();
  pool.query.mockResolvedValue({ rowCount: 0, rows: [] }); // default: covers initTables' fire-and-forget query
});

test('non-assigned analyst gets 403 on a :caseId route', async () => {
  mockUser = { id: 'u1', role: 'analyst' };
  // canAccessCase → false (default mockResolvedValue above already returns rowCount: 0)
  const res = await request(makeApp(), 'POST', '/api/threat-intel/correlate/c-1', {});
  expect(res.status).toBe(403);
});
test('elevated user passes the guard (not 403; ELEVATED bypasses the DB check)', async () => {
  mockUser = { id: 'u1', role: 'admin' };
  const res = await request(makeApp(), 'POST', '/api/threat-intel/correlate/c-1', {});
  expect(res.status).not.toBe(403);   // guard lets admin through (downstream may 200/500, just not 403)
});
