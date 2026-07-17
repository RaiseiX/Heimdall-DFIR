const http = require('http');
const { Server: IOServer } = require('socket.io');
const jwt = require('jsonwebtoken');
const ioClient = require('socket.io-client');
const { registerSocketHandlers } = require('../../src/socket/socketHandlers');

const JWT_SECRET = 'test-socket-secret';
const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

async function startSocketServer(pool) {
  const httpServer = http.createServer();
  const io = new IOServer(httpServer, { cors: { origin: '*' } });
  registerSocketHandlers(io, { pool, logger: silentLogger, JWT_SECRET });
  await new Promise((res) => httpServer.listen(0, res));
  const port = httpServer.address().port;
  const url = `http://localhost:${port}`;
  const clients = [];
  function connect(user) {
    const socket = ioClient(url, { auth: { token: jwt.sign(user, JWT_SECRET) }, transports: ['websocket'], forceNew: true });
    clients.push(socket);
    return socket;
  }
  async function stop() { for (const c of clients) c.close(); io.close(); await new Promise((res) => httpServer.close(res)); }
  return { io, url, port, connect, stop, JWT_SECRET };
}
module.exports = { startSocketServer };
