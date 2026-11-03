
require('ts-node').register({
  transpileOnly: true,
  compilerOptions: {
    module: 'commonjs',
    esModuleInterop: true,
    allowSyntheticDefaultImports: true,
    resolveJsonModule: true,
  },
});

const express = require('express');
const http = require('http');
const { Server: IOServer } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const path = require('path');

const IORedis = require('ioredis');
const { createAdapter } = require('@socket.io/redis-adapter');

const { pool, testConnection } = require('./config/database');
const { runGuardedMigrations } = require('./services/schemaMigrations');
const { COLLECTION_TIMELINE_STATEMENTS, COLLECTION_TIMELINE_EXPECTED_COLUMNS } = require('./config/collectionTimelineDdl');
const { NETWORK_CONNECTIONS_STATEMENTS, NETWORK_CONNECTIONS_EXPECTED_COLUMNS } = require('./config/networkConnectionsDdl');
const { markDegraded, clearDegraded } = require('./services/schemaState');
const requireHealthySchema = require('./middleware/requireHealthySchema');
const { connectRedis } = require('./config/redis');
const { authenticate, auditLog, JWT_SECRET } = require('./middleware/auth');
const logger = require('./config/logger').default;
const { requestIdMiddleware } = require('./middleware/requestId');
const { accessLogMiddleware } = require('./middleware/accessLogMiddleware');

const attributionRoutes = require('./routes/attribution');
const authRoutes = require('./routes/auth');
const casesRoutes = require('./routes/cases');
const evidenceRoutes = require('./routes/evidence');
const evidenceDeletionPreviewRoutes = require('./routes/evidenceDeletionPreview');
const timelineRoutes = require('./routes/timeline');
const iocRoutes = require('./routes/iocs');
const networkRoutes = require('./routes/network');
const reportRoutes = require('./routes/reports');
const usersRoutes = require('./routes/users');
const searchRoutes = require('./routes/search');
const collectionRoutes = require('./routes/collection');
const collectionFilesRoutes = require('./routes/collectionFiles');
const mitreRoutes = require('./routes/mitre');

const uploadRoutes = require('./routes/upload');
const parsersStreamRoutes = require('./routes/parsers-stream');
const artifactsRoutes = require('./routes/artifacts');
const threatHuntingRoutes = require('./routes/threatHunting');
const threatIntelRoutes   = require('./routes/threatIntel');
const mispRoutes          = require('./routes/misp');
const sysmonRoutes        = require('./routes/sysmon');
const timelinePinsRoutes  = require('./routes/timelinePins');
const chatRoutes          = require('./routes/chat');
const adminRoutes         = require('./routes/admin');
const settingsRoutes      = require('./routes/settings');
const triageRoutes        = require('./routes/triage');
const notebookRoutes      = require('./routes/notebook');
const playbooksRoutes     = require('./routes/playbooks');
const soarRoutes          = require('./routes/soar');
const feedbackRoutes      = require('./routes/feedback');
const volwebRoutes        = require('./routes/volweb');
const llmRoutes           = require('./routes/llm');
const aiRoutes            = require('./routes/ai');
const bookmarksRoutes     = require('./routes/bookmarks');
const investigationRoutes = require('./routes/investigation');
const savedSearchesRoutes = require('./routes/savedSearches');
const dfiqRoutes = require('./routes/dfiq');
const dfiqCaseRoutes = require('./routes/dfiqCase');

const app = express();

// Trust the reverse proxy hop(s) in front (Traefik / nginx) so req.ip is the real
// client IP — required for accurate audit logs and IP-based rate limiting.
// Configurable: set TRUST_PROXY_HOPS to the number of proxies between client and app.
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS || 1));

app.set('etag', false);

const server = http.createServer(app);
const PORT = process.env.PORT || 4000;

server.requestTimeout    = 0;
server.timeout           = 0;
server.keepAliveTimeout  = 0;
server.headersTimeout    = 0;

const io = new IOServer(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true,
  },
  transports: ['polling', 'websocket'],
  pingTimeout: 60000,
  pingInterval: 25000,
});

const _redisAdapterOpts = {
  host:     process.env.REDIS_HOST     || 'redis',
  port:     parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
};
const _redisPub = new IORedis(_redisAdapterOpts);
const _redisSub = new IORedis(_redisAdapterOpts);
_redisPub.on('error', (err) => logger.error('[Socket.io adapter pub]', { error: err.message }));
_redisSub.on('error', (err) => logger.error('[Socket.io adapter sub]', { error: err.message }));
io.adapter(createAdapter(_redisPub, _redisSub));

app.locals.pool = pool;
app.locals.io = io;

const { registerSocketHandlers } = require('./socket/socketHandlers');
registerSocketHandlers(io, { pool, logger, JWT_SECRET });
const { demarrerFilet } = require('./socket/sessionEviction');
app.locals.filetSessions = demarrerFilet(io);

io.engine.on('connection', (rawSocket) => {
  logger.debug('[Engine.io] Nouvelle connexion brute', { transport: rawSocket.transport.name, id: rawSocket.id });
});
io.engine.on('connection_error', (err) => {
  logger.error('[Engine.io] Erreur connexion', { code: err.code, error: err.message });
});

app.set('etag', false);

app.use(helmet({
  // CSP and HSTS are set by Nginx (nginx.conf) — kept false here to avoid duplication.
  // These are re-enabled for direct-access defence if Nginx is bypassed.
  contentSecurityPolicy:          false,  // complex — managed by Nginx CSP header
  strictTransportSecurity:        false,  // managed by Nginx (requires TLS)
  crossOriginEmbedderPolicy:      false,  // breaks some browser features
  // Re-enabled — safe to set even when Nginx also sets them (idempotent)
  xContentTypeOptions:            true,
  xFrameOptions:                  { action: 'sameorigin' },
  referrerPolicy:                 { policy: 'strict-origin-when-cross-origin' },
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
// Custom Morgan format — excludes Authorization header and query strings from logs
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim(), { type: 'http_access' }) },
  skip:   (req) => req.path === '/api/health',
}));
app.use(requestIdMiddleware);
app.use(accessLogMiddleware);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use('/api/attribution', attributionRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/cases', casesRoutes);
app.use('/api/evidence', evidenceDeletionPreviewRoutes);
app.use('/api/evidence', evidenceRoutes);
app.use('/api/timeline', timelineRoutes);
app.use('/api/iocs', iocRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/collection', collectionFilesRoutes);
app.use('/api/collection', requireHealthySchema, collectionRoutes);
app.use('/api/mitre', mitreRoutes);

const timelineRulesRouter = require('./routes/timelineRules');
app.use('/api/timeline-rules', timelineRulesRouter);

const columnPrefsRouter = require('./routes/columnPrefs');
app.use('/api/column-prefs', columnPrefsRouter);

app.use('/api/upload', authenticate, requireHealthySchema, uploadRoutes);
app.use('/api/parsers', authenticate, requireHealthySchema, parsersStreamRoutes);
app.use('/api/artifacts', artifactsRoutes);
app.use('/api/threat-hunting', threatHuntingRoutes);
app.use('/api/threat-intel',   threatIntelRoutes);
app.use('/api/misp',           mispRoutes);
app.use('/api/sysmon',         sysmonRoutes);
app.use('/api/timeline-pins',  timelinePinsRoutes);
app.use('/api/chat',           chatRoutes);
app.use('/api/admin',                  adminRoutes);
app.use('/api/settings',               settingsRoutes);
app.use('/api/triage',                 triageRoutes);
app.use('/api/notebook',               notebookRoutes);
app.use('/api/playbooks',              playbooksRoutes);
app.use('/api/cases/:caseId/soar',    soarRoutes);
app.use('/api/cases/:caseId/bookmarks',     bookmarksRoutes);
app.use('/api/cases/:caseId/investigation', investigationRoutes);
app.use('/api/cases/:caseId/saved-searches', savedSearchesRoutes);
app.use('/api/cases/:caseId/dfiq',    dfiqCaseRoutes);
app.use('/api/dfiq',                  dfiqRoutes);
app.use('/api/feedback',              feedbackRoutes);
app.use('/api/volweb',                volwebRoutes);
app.use('/api/llm',                   llmRoutes);

// Health endpoint must be registered before the /api catch-all (aiRoutes)
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      version: '2.7.0',
      timestamp: new Date().toISOString(),
      features: ['chunked-upload', 'streaming-parsers', 'socket-io', 'bullmq-queue'],
      services: { database: 'connected', redis: 'connected' },
    });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});

app.use('/api',                       aiRoutes);

app.use((err, req, res, _next) => {
  logger.error('[Error]', { requestId: req.requestId, error: err.message, status: err.status || 500 });
  res.status(err.status || 500).json({
    error: err.message || 'Erreur interne serveur',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

async function runMigrations() {
  // collection_timeline holds millions of rows, so its DDL is the one that can
  // actually queue behind a long-running SELECT and, once queued in ACCESS
  // EXCLUSIVE, block every INSERT arriving after it. Run it under lock_timeout,
  // and refuse writes rather than let the parsers hit missing columns.
  try {
    await runGuardedMigrations(pool, {
      name: 'collection_timeline',
      statements: COLLECTION_TIMELINE_STATEMENTS,
      // On an already-migrated database this skips the batch without taking any
      // lock, so a restart during a long read cannot disable ingestion for work
      // that does not exist.
      skipIfPresent: { table: 'collection_timeline', columns: COLLECTION_TIMELINE_EXPECTED_COLUMNS },
    });
    clearDegraded('collection_timeline');
  } catch (e) {
    logger.error('[migration] collection_timeline FAILED — ingestion disabled', { error: e.message });
    markDegraded('collection_timeline', e.message);
  }

  // network_connections n'avait pas d'evidence_id : avec plusieurs collectes dans un
  // cas, une connexion ne pouvait pas dire d'ou elle venait. Meme garde que ci-dessus.
  try {
    await runGuardedMigrations(pool, {
      name: 'network_connections',
      statements: NETWORK_CONNECTIONS_STATEMENTS,
      skipIfPresent: { table: 'network_connections', columns: NETWORK_CONNECTIONS_EXPECTED_COLUMNS },
    });
    clearDegraded('network_connections');
  } catch (e) {
    logger.error('[migration] network_connections FAILED', { error: e.message });
    markDegraded('network_connections', e.message);
  }

  try {
    const { SCHEMA_SQL, COLONNES } = require('./services/parseQueue');
    await runGuardedMigrations(pool, {
      name: 'parse_queue',
      statements: [SCHEMA_SQL],
      skipIfPresent: { table: 'parse_queue', columns: COLONNES },
    });
    clearDegraded('parse_queue');
  } catch (e) {
    logger.error('[migration] parse_queue FAILED', { error: e.message });
    markDegraded('parse_queue', e.message);
  }
}

async function start() {
  try {
    await testConnection();
    logger.info('✓ PostgreSQL connecté');

    await connectRedis();
    logger.info('✓ Redis connecté');

    await runMigrations();

    server.listen(PORT, '0.0.0.0', () => {
      logger.info('Heimdall DFIR API démarrée', {
        version: '2.7.0',
        port: PORT,
        mode: 'Streaming + Chunked Upload',
      });
    });

    collectionRoutes.reprendreFile(io)
      .catch(e => logger.error('[parse-queue] reprise impossible', { error: e.message }));

    // Daily retention purge tick (no-op unless explicitly enabled in Settings).
    // Runs every 6h; the service itself re-checks the policy on each tick.
    try {
      const { retentionTick } = require('./services/retentionService');
      const RETENTION_INTERVAL_MS = 6 * 60 * 60 * 1000;
      setTimeout(() => retentionTick().catch(e => logger.error('[retention] tick:', e.message)), 5 * 60 * 1000);
      setInterval(() => retentionTick().catch(e => logger.error('[retention] tick:', e.message)), RETENTION_INTERVAL_MS);
    } catch (e) {
      logger.error('[retention] scheduler init failed:', e.message);
    }
  } catch (err) {
    logger.error('Échec du démarrage', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

start();
