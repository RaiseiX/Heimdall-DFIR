// Route-level security-guard test for investigation.js — pool, auth, and caseAccess mocked.
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(), requireRole: () => (_req, _res, next) => next(),
}));
jest.mock('../../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn().mockResolvedValue(true),
  ELEVATED: new Set(['admin', 'team_lead']),
}));
const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const { canAccessCase } = require('../../../src/middleware/caseAccess');
const investigationRouter = require('../../../src/routes/investigation');

function makeApp() { const app = express(); app.use(express.json()); app.use('/api/cases/:caseId/investigation', investigationRouter); return app; }
beforeEach(() => { pool.query.mockReset(); canAccessCase.mockReset().mockResolvedValue(true); mockUser = { id: 'u1', role: 'analyst' }; });

test('unauthorized user gets 403 and no DB query runs', async () => {
  canAccessCase.mockResolvedValueOnce(false);
  const res = await request(makeApp(), 'GET', '/api/cases/c-1/investigation');
  expect(res.status).toBe(403);
  expect(pool.query).not.toHaveBeenCalled();
});
test('authorized user passes the guard (not 403)', async () => {
  canAccessCase.mockResolvedValue(true);
  pool.query.mockResolvedValue({ rows: [] });
  const res = await request(makeApp(), 'GET', '/api/cases/c-1/investigation');
  expect(res.status).not.toBe(403);
});
