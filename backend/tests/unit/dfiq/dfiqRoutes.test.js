// Route tests for dfiq.js — pool, auth, and caseAccess mocked.
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(),
}));
jest.mock('../../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn().mockResolvedValue(true),
  caseAccessParam: jest.fn(),
  caseListFilter: jest.fn(),
  ELEVATED: new Set(['admin', 'team_lead']),
}));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const dfiqRouter = require('../../../src/routes/dfiq');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/dfiq', dfiqRouter);
  return app;
}

const BASE = '/api/dfiq';

beforeEach(() => {
  pool.query.mockReset();
  mockUser = { id: 'user-1', role: 'analyst' };
});

describe('dfiq routes', () => {
  test('GET /scenarios returns the list', async () => {
    pool.query.mockResolvedValueOnce({
      rows: [{ id: 's1', dfiq_id: 'S1001', title: 'Scenario 1', description: null, tags: [], is_custom: false, question_count: 3 }],
    });
    const res = await request(makeApp(), 'GET', `${BASE}/scenarios`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].title).toBe('Scenario 1');
  });

  test('POST /scenarios as a non-elevated user returns 403', async () => {
    mockUser = { id: 'user-1', role: 'analyst' };
    const res = await request(makeApp(), 'POST', `${BASE}/scenarios`, { title: 'My custom scenario' });
    expect(res.status).toBe(403);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('POST /scenarios as elevated returns 201 with is_custom=true', async () => {
    mockUser = { id: 'admin-1', role: 'admin' };
    pool.query.mockResolvedValueOnce({
      rows: [{ id: 's2', dfiq_id: null, title: 'My custom scenario', description: null, tags: [], is_custom: true, source: 'custom', created_by: 'admin-1' }],
    });
    const res = await request(makeApp(), 'POST', `${BASE}/scenarios`, { title: 'My custom scenario' });
    expect(res.status).toBe(201);
    expect(res.body.is_custom).toBe(true);
  });

  test('PUT /scenarios/:id on a public (non-custom) scenario returns 403', async () => {
    mockUser = { id: 'admin-1', role: 'admin' };
    pool.query.mockResolvedValueOnce({ rows: [{ is_custom: false }] }); // assertCustomScenario SELECT
    const res = await request(makeApp(), 'PUT', `${BASE}/scenarios/s1`, { title: 'edited' });
    expect(res.status).toBe(403);
  });

  test('DELETE /scenarios/:id on a public (non-custom) scenario returns 403', async () => {
    mockUser = { id: 'admin-1', role: 'admin' };
    pool.query.mockResolvedValueOnce({ rows: [{ is_custom: false }] }); // assertCustomScenario SELECT
    const res = await request(makeApp(), 'DELETE', `${BASE}/scenarios/s1`);
    expect(res.status).toBe(403);
  });
});
