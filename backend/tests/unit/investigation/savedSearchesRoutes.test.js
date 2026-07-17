// Route tests for savedSearches.js — pool, auth, and caseAccess mocked.
let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = mockUser; next(); },
  auditLog: jest.fn(),
}));
jest.mock('../../../src/middleware/caseAccess', () => ({
  canAccessCase: jest.fn().mockResolvedValue(true),
  ELEVATED: new Set(['admin', 'team_lead']),
}));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const { canAccessCase } = require('../../../src/middleware/caseAccess');
const savedSearchesRouter = require('../../../src/routes/savedSearches');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/cases/:caseId/saved-searches', savedSearchesRouter);
  return app;
}

const BASE = '/api/cases/c-1/saved-searches';

beforeEach(() => {
  pool.query.mockReset();
  canAccessCase.mockReset().mockResolvedValue(true);
  mockUser = { id: 'user-1', role: 'analyst' };
});

describe('saved searches routes', () => {
  test('POST creates a personal search with author = requester', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 's1', scope: 'personal', author_id: 'user-1' }] });
    const res = await request(makeApp(), 'POST', BASE, {
      name: '  4624 type 10 on DC01  ',
      query: { search: 'psexec', hostFilter: 'DC01' },
    });
    expect(res.status).toBe(201);
    const params = pool.query.mock.calls[0][1];
    expect(params).toContain('c-1');      // case_id from route
    expect(params).toContain('user-1');   // author_id from req.user
    expect(params).toContain('4624 type 10 on DC01'); // trimmed name
    expect(params).toContain('personal'); // default scope
  });

  test('POST strips keys outside the whitelist before persisting', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 's1' }] });
    await request(makeApp(), 'POST', BASE, {
      name: 'x',
      query: { search: 'a', hostFilter: 'DC01', page: 5, evidenceId: 'e1', columns: ['a'] },
    });
    const storedJson = pool.query.mock.calls[0][1].find(p => typeof p === 'string' && p.startsWith('{'));
    expect(JSON.parse(storedJson)).toEqual({ search: 'a', hostFilter: 'DC01' });
  });

  test('POST rejects a query serialising over 16 Ko', async () => {
    const res = await request(makeApp(), 'POST', BASE, {
      name: 'big', query: { search: 'x'.repeat(20000) },
    });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('POST without a valid name returns 400', async () => {
    const res = await request(makeApp(), 'POST', BASE, { name: '   ', query: {} });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('POST with an invalid scope returns 400', async () => {
    const res = await request(makeApp(), 'POST', BASE, { name: 'x', scope: 'global', query: {} });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('POST duplicate (case_id, author_id, name) returns 409', async () => {
    pool.query.mockRejectedValueOnce({ code: '23505' });
    const res = await request(makeApp(), 'POST', BASE, { name: 'dup', query: {} });
    expect(res.status).toBe(409);
  });

  test('GET restricts to my personal + case-shared of this case', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request(makeApp(), 'GET', BASE);
    expect(res.status).toBe(200);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toContain("s.author_id = $2 OR s.scope = 'case'");
    expect(params).toEqual(['c-1', 'user-1']);
  });

  test('PUT promotes to case scope (owner)', async () => {
    pool.query
      .mockResolvedValueOnce({ rows: [{ author_id: 'user-1' }] })          // ownership SELECT
      .mockResolvedValueOnce({ rows: [{ id: 's1', scope: 'case' }] });     // UPDATE
    const res = await request(makeApp(), 'PUT', `${BASE}/s1`, { scope: 'case' });
    expect(res.status).toBe(200);
    expect(res.body.scope).toBe('case');
    expect(pool.query.mock.calls[1][1]).toContain('case');
  });

  test('PUT by a non-author returns 403 and issues no UPDATE', async () => {
    mockUser = { id: 'user-2', role: 'analyst' };
    pool.query.mockResolvedValueOnce({ rows: [{ author_id: 'user-1' }] }); // ownership SELECT only
    const res = await request(makeApp(), 'PUT', `${BASE}/s1`, { name: 'hijack' });
    expect(res.status).toBe(403);
    expect(pool.query).toHaveBeenCalledTimes(1);
  });

  test('DELETE by a non-author non-admin returns 403', async () => {
    mockUser = { id: 'user-2', role: 'analyst' };
    pool.query.mockResolvedValueOnce({ rows: [{ author_id: 'user-1' }] });
    const res = await request(makeApp(), 'DELETE', `${BASE}/s1`);
    expect(res.status).toBe(403);
    expect(pool.query).toHaveBeenCalledTimes(1);
  });

  test('DELETE by an admin removes another author\'s search', async () => {
    mockUser = { id: 'admin-9', role: 'admin' };
    pool.query
      .mockResolvedValueOnce({ rows: [{ author_id: 'user-1' }] }) // ownership SELECT
      .mockResolvedValueOnce({ rows: [] });                       // DELETE
    const res = await request(makeApp(), 'DELETE', `${BASE}/s1`);
    expect(res.status).toBe(200);
    expect(pool.query).toHaveBeenCalledTimes(2);
  });

  test('PUT/DELETE on an id from another case returns 404 (case isolation)', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] }); // ownership SELECT scoped by case_id finds nothing
    const res = await request(makeApp(), 'PUT', `${BASE}/other-case-id`, { name: 'x' });
    expect(res.status).toBe(404);
  });

  test('a user without case access is refused with 403', async () => {
    canAccessCase.mockResolvedValueOnce(false);
    const res = await request(makeApp(), 'GET', BASE);
    expect(res.status).toBe(403);
    expect(pool.query).not.toHaveBeenCalled();
  });
});
