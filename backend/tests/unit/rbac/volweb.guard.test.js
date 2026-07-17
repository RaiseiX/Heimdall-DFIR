// Route-level security-guard test for volweb.ts — pool + auth mocked, real caseAccessParam
// (so the test also proves authenticate runs before it: req.user must be set).
// volweb.ts does `fs.mkdirSync(TEMP_DIR/UPLOADS_DIR)` at module load time, defaulting to the
// container paths /app/temp and /app/uploads which aren't writable in this env. Point the
// existing TEMP_DIR/UPLOAD_DIR env overrides at a scratch dir before requiring the router
// (no route logic touched).
const os = require('os');
const path = require('path');
const fs = require('fs');
const scratchRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'volweb-guard-test-'));
process.env.TEMP_DIR = path.join(scratchRoot, 'temp');
process.env.UPLOAD_DIR = path.join(scratchRoot, 'uploads');

let mockUser;
jest.mock('../../../src/config/database', () => ({ pool: { query: jest.fn() } }));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: jest.fn((req, _res, next) => { req.user = mockUser; next(); }),
  auditLog: jest.fn(), requireRole: () => (_req, _res, next) => next(),
}));
const express = require('express');
const { request } = require('../../helpers/routeHarness');
const { pool } = require('../../../src/config/database');
const { authenticate } = require('../../../src/middleware/auth');
const volwebRouter = require('../../../src/routes/volweb');

function makeApp() { const app = express(); app.use(express.json()); app.locals.pool = pool; app.use('/api/volweb', volwebRouter); return app; }
beforeEach(() => { pool.query.mockReset(); authenticate.mockClear(); });

test('non-assigned analyst gets 403 on a :caseId route', async () => {
  mockUser = { id: 'u1', role: 'analyst' };
  pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });  // canAccessCase → false
  const res = await request(makeApp(), 'GET', '/api/volweb/status/c-1');
  expect(res.status).toBe(403);
});
test('elevated user passes the guard (not 403; ELEVATED bypasses the DB check)', async () => {
  mockUser = { id: 'u1', role: 'admin' };
  const res = await request(makeApp(), 'GET', '/api/volweb/status/c-1');
  expect(res.status).not.toBe(403);   // guard lets admin through (downstream may 200/500, just not 403)
});

test('/sso/:token is public — the router-level guard skips authenticate for it', async () => {
  mockUser = undefined; // no Bearer JWT on this origin — VolWeb magic-link handoff, see nginx/volweb.conf
  await request(makeApp(), 'GET', '/api/volweb/sso/faketoken');
  // The route handler still runs (and may itself reject the fake token), but the
  // auth middleware must never have been invoked — that's the proof /sso is public.
  expect(authenticate).not.toHaveBeenCalled();
});

test(':caseId routes still require authenticate — guard is not globally disabled', async () => {
  mockUser = { id: 'u1', role: 'admin' };
  await request(makeApp(), 'GET', '/api/volweb/status/c-1');
  expect(authenticate).toHaveBeenCalled();
});
