// Route tests for mitre.js — structured fields + clearable PATCH (IMP-2 fix).
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = { id: 'user-1' }; next(); },
  auditLog: jest.fn(),
}));
jest.mock('../../../src/config/logger', () => ({ default: { info() {}, warn() {}, error() {} } }));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const mitreRouter = require('../../../src/routes/mitre');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/mitre', mitreRouter);
  return app;
}

beforeEach(() => { pool.query.mockReset(); });

describe('mitre routes', () => {
  test('POST persists significance + links_to', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [] })                       // dup check
      .mockResolvedValueOnce({ rows: [{ id: 'm1' }] });          // insert
    const res = await request(makeApp(), 'POST', '/api/mitre/c-1', {
      technique_id: 'T1059', tactic: 'Execution', technique_name: 'Cmd',
      significance: 'attacker ran scripts', links_to: 'm0',
    });
    expect(res.status).toBe(201);
    const params = pool.query.mock.calls[1][1];
    expect(params).toContain('attacker ran scripts');
    expect(params).toContain('m0');
  });

  test('PATCH updates only provided keys', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'm1', significance: 'x' }] });
    const res = await request(makeApp(), 'PATCH', '/api/mitre/c-1/m1', { significance: 'x' });
    expect(res.status).toBe(200);
    const sql = pool.query.mock.calls[0][0];
    expect(sql).toMatch(/significance = \$1/);
    expect(sql).not.toMatch(/confidence/);   // not in body → not in SET
  });

  test('PATCH can clear links_to with empty string', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'm1' }] });
    const res = await request(makeApp(), 'PATCH', '/api/mitre/c-1/m1', { links_to: '' });
    expect(res.status).toBe(200);
    const vals = pool.query.mock.calls[0][1];
    expect(vals[0]).toBeNull();   // '' coerced to null → actually clears the column
  });

  test('PATCH with no updatable fields returns 400', async () => {
    const res = await request(makeApp(), 'PATCH', '/api/mitre/c-1/m1', { foo: 'bar' });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });
});
