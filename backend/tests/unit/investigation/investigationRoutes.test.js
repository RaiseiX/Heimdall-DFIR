// Route tests for investigation.js — pool + auth mocked, real express router.
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = { id: 'user-1' }; next(); },
  auditLog: jest.fn(),
}));
jest.mock('../../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn().mockResolvedValue(true),
  ELEVATED: new Set(['admin', 'team_lead']),
}));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const investigationRouter = require('../../../src/routes/investigation');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/cases/:caseId/investigation', investigationRouter);
  return app;
}

const BASE = '/api/cases/c-1/investigation';

beforeEach(() => { pool.query.mockReset(); });

describe('investigation routes', () => {
  test('GET / returns steps + findings', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [{ id: 's1', phase: 'analysis', title: 'T', status: 'todo' }] })
      .mockResolvedValueOnce({ rows: [{ id: 'b1', title: 'Finding', mitre_tactic: 'Execution' }] });
    const res = await request(makeApp(), 'GET', BASE);
    expect(res.status).toBe(200);
    expect(res.body.steps).toHaveLength(1);
    expect(res.body.findings[0].title).toBe('Finding');
  });

  test('POST /steps without title returns 400', async () => {
    const res = await request(makeApp(), 'POST', `${BASE}/steps`, { phase: 'analysis' });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('POST /steps creates a step (201)', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 's2', title: 'Hash evidence' }] });
    const res = await request(makeApp(), 'POST', `${BASE}/steps`, { phase: 'acquisition', title: 'Hash evidence' });
    expect(res.status).toBe(201);
    expect(res.body.title).toBe('Hash evidence');
    const params = pool.query.mock.calls[0][1];
    expect(params).toContain('Hash evidence');
    expect(params).toContain('acquisition');
  });

  test('POST /seed seeds 4 phases when empty', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });        // existence check
    pool.query.mockResolvedValue({ rows: [] });            // 4 inserts
    const res = await request(makeApp(), 'POST', `${BASE}/seed`);
    expect(res.status).toBe(200);
    expect(res.body.seeded).toBe(true);
    // 1 existence check + 4 phase inserts
    expect(pool.query).toHaveBeenCalledTimes(5);
  });

  test('POST /seed is a no-op when steps already exist', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ '?column?': 1 }] });
    const res = await request(makeApp(), 'POST', `${BASE}/seed`);
    expect(res.status).toBe(200);
    expect(res.body.seeded).toBe(false);
    expect(pool.query).toHaveBeenCalledTimes(1);
  });

  test('GET /navigator returns an ATT&CK layer', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [{ case_number: 'CASE-9' }] })
      .mockResolvedValueOnce({ rows: [{ mitre_technique: 'T1059', mitre_tactic: 'Execution', confidence: 'high' }] });
    const res = await request(makeApp(), 'GET', `${BASE}/navigator`);
    expect(res.status).toBe(200);
    expect(res.body.domain).toBe('enterprise-attack');
    expect(res.body.techniques[0].techniqueID).toBe('T1059');
    expect(res.body.techniques[0].score).toBe(100);
  });

  test('DELETE /steps/:id returns success', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request(makeApp(), 'DELETE', `${BASE}/steps/s1`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});
