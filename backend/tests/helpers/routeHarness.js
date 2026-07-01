// Dependency-free HTTP harness for testing Express routers without supertest.
// Spins up the app on an ephemeral port, issues a real request via the built-in
// http module, tears the server down, and returns { status, body }.
const http = require('http');

function request(app, method, path, body) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      const data = body != null ? JSON.stringify(body) : null;
      const req = http.request(
        {
          host: '127.0.0.1', port, path, method,
          headers: {
            'Content-Type': 'application/json',
            ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
          },
        },
        (res) => {
          let buf = '';
          res.on('data', (c) => { buf += c; });
          res.on('end', () => {
            server.close();
            let parsed = null;
            try { parsed = buf ? JSON.parse(buf) : null; } catch { parsed = buf; }
            resolve({ status: res.statusCode, body: parsed });
          });
        },
      );
      req.on('error', (e) => { server.close(); reject(e); });
      if (data) req.write(data);
      req.end();
    });
  });
}

module.exports = { request };
