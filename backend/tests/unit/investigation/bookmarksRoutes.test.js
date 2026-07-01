// Route tests for bookmarks.js structured fields — pool + auth mocked.
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: (req, _res, next) => { req.user = { id: 'user-1' }; next(); },
  auditLog: jest.fn(),
}));

const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const bookmarksRouter = require('../../../src/routes/bookmarks');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/cases/:caseId/bookmarks', bookmarksRouter);
  return app;
}

const BASE = '/api/cases/c-1/bookmarks';

beforeEach(() => { pool.query.mockReset(); });

describe('bookmarks structured fields', () => {
  test('POST persists significance/confidence/links_to', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'b1', title: 'F' }] });
    const res = await request(makeApp(), 'POST', BASE, {
      title: 'Service created',
      mitre_tactic: 'Persistence',
      significance: 'likely persistence',
      confidence: 'high',
      links_to: 'b0',
    });
    expect(res.status).toBe(201);
    const params = pool.query.mock.calls[0][1];
    expect(params).toContain('likely persistence');
    expect(params).toContain('high');
    expect(params).toContain('b0');
  });

  test('POST without title returns 400', async () => {
    const res = await request(makeApp(), 'POST', BASE, { significance: 'x' });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('PUT updates structured fields', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'b1', title: 'F' }] });
    const res = await request(makeApp(), 'PUT', `${BASE}/b1`, {
      title: 'F', significance: 'updated', confidence: 'medium', links_to: null,
    });
    expect(res.status).toBe(200);
    const params = pool.query.mock.calls[0][1];
    expect(params).toContain('updated');
    expect(params).toContain('medium');
  });

  test('PUT on missing bookmark returns 404', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request(makeApp(), 'PUT', `${BASE}/nope`, { title: 'x' });
    expect(res.status).toBe(404);
  });
});
