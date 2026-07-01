const { pool } = require('../config/database');

function accessLogMiddleware(req, res, next) {
  if (!req.user) return next();
  if (req.path === '/api/health') return next();

  const start = Date.now();

  res.on('finish', () => {
    pool.query(
      `INSERT INTO access_log (user_id, username, method, path, status_code, response_ms, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7::inet)`,
      [
        req.user.id       || null,
        req.user.username || null,
        req.method,
        req.path,
        res.statusCode,
        Date.now() - start,
        req.ip || null,
      ]
    ).catch(() => {});
  });

  next();
}

module.exports = { accessLogMiddleware };
