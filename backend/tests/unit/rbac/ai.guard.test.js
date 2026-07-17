// Route-level security-guard test for ai.ts — pool + auth mocked, real caseAccessParam
// (so the test also proves authenticate runs before it: req.user must be set).
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(), requireRole: () => (_req, _res, next) => next(),
}));
const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const aiRouter = require('../../../src/routes/ai');

function makeApp() { const app = express(); app.use(express.json()); app.locals.pool = pool; app.use('/api', aiRouter); return app; }
beforeEach(() => { pool.query.mockReset(); });

test('non-assigned analyst gets 403 on a :caseId route', async () => {
  mockUser = { id: 'u1', role: 'analyst' };
  pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });  // canAccessCase → false
  const res = await request(makeApp(), 'GET', '/api/cases/c-1/ai/history');
  expect(res.status).toBe(403);
});
test('elevated user passes the guard (not 403; ELEVATED bypasses the DB check)', async () => {
  mockUser = { id: 'u1', role: 'admin' };
  const res = await request(makeApp(), 'GET', '/api/cases/c-1/ai/history');
  expect(res.status).not.toBe(403);   // guard lets admin through (downstream may 200/500, just not 403)
});
