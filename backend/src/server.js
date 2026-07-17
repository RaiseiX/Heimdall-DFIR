
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
const { connectRedis } = require('./config/redis');
const { authenticate, auditLog, JWT_SECRET } = require('./middleware/auth');
const logger = require('./config/logger').default;
const { requestIdMiddleware } = require('./middleware/requestId');
const { accessLogMiddleware } = require('./middleware/accessLogMiddleware');

const attributionRoutes = require('./routes/attribution');
const authRoutes = require('./routes/auth');
const casesRoutes = require('./routes/cases');
const evidenceRoutes = require('./routes/evidence');
const timelineRoutes = require('./routes/timeline');
const iocRoutes = require('./routes/iocs');
const networkRoutes = require('./routes/network');
const reportRoutes = require('./routes/reports');
const usersRoutes = require('./routes/users');
const searchRoutes = require('./routes/search');
const collectionRoutes = require('./routes/collection');
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
app.use('/api/evidence', evidenceRoutes);
app.use('/api/timeline', timelineRoutes);
app.use('/api/iocs', iocRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/collection', collectionRoutes);
app.use('/api/mitre', mitreRoutes);

const timelineRulesRouter = require('./routes/timelineRules');
app.use('/api/timeline-rules', timelineRulesRouter);

const columnPrefsRouter = require('./routes/columnPrefs');
app.use('/api/column-prefs', columnPrefsRouter);

app.use('/api/upload', authenticate, uploadRoutes);
app.use('/api/parsers', authenticate, parsersStreamRoutes);
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
  try {
    await pool.query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hmac VARCHAR(64)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)`);
    logger.info('[migration] audit_log.hmac OK');
  } catch (e) {
    logger.warn('[migration] audit_log', { error: e.message });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS timeline_pins (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        case_id       UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        author_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        evidence_id   UUID REFERENCES evidence(id) ON DELETE CASCADE,
        event_ts      TIMESTAMPTZ,
        artifact_type VARCHAR(64),
        description   TEXT,
        source        TEXT,
        raw_data      JSONB,
        note          TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(case_id, author_id, event_ts, source)
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tpins_case   ON timeline_pins(case_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tpins_author ON timeline_pins(author_id, case_id)`);

    await pool.query(`ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS is_global BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS promoted_by UUID REFERENCES users(id)`);
    await pool.query(`ALTER TABLE timeline_pins ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ`);
    logger.info('[migration] timeline_pins OK');
  } catch (e) {
    logger.warn('[migration] timeline_pins', { error: e.message });
  }
  try {
    await pool.query(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS risk_score SMALLINT`);
    await pool.query(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS risk_level VARCHAR(10)`);
    await pool.query(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS risk_computed_at TIMESTAMPTZ`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_cases_risk_level ON cases(risk_level)`);
    logger.info('[migration] risk_score columns OK');
  } catch (e) {
    logger.warn('[migration] risk_score', { error: e.message });
  }
  try {
    await pool.query(`
      CREATE OR REPLACE VIEW ioc_cross_case AS
      SELECT
        value AS ioc_value,
        ioc_type,
        COUNT(DISTINCT case_id)                 AS case_count,
        ARRAY_AGG(DISTINCT case_id::text)       AS case_ids,
        COUNT(*)                                AS total_occurrences,
        MAX(created_at)                         AS last_seen
      FROM iocs
      WHERE value IS NOT NULL AND value != ''
      GROUP BY value, ioc_type
      HAVING COUNT(DISTINCT case_id) > 1
    `);
    logger.info('[migration] ioc_cross_case view OK');
  } catch (e) {
    logger.warn('[migration] ioc_cross_case view', { error: e.message });
  }

  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS preferences JSONB NOT NULL DEFAULT '{}'::jsonb`);
    logger.info('[migration] users.preferences OK');
  } catch (e) {
    logger.warn('[migration] users.preferences', { error: e.message });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  VARCHAR(64) NOT NULL UNIQUE,
        expires_at  TIMESTAMPTZ NOT NULL,
        revoked     BOOLEAN NOT NULL DEFAULT FALSE,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rt_user    ON refresh_tokens(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens(expires_at) WHERE revoked = FALSE`);
    logger.info('[migration] refresh_tokens OK');
  } catch (e) {
    logger.warn('[migration] refresh_tokens', { error: e.message });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_conversations (
        id          BIGSERIAL PRIMARY KEY,
        case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        user_id     UUID NOT NULL REFERENCES users(id),
        role        VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant')),
        content     TEXT NOT NULL,
        tokens_used INTEGER,
        model       VARCHAR(100),
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        metadata    JSONB DEFAULT '{}'
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_conv_case ON ai_conversations(case_id, created_at ASC)`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_investigator_context (
        id         BIGSERIAL PRIMARY KEY,
        case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        free_text  TEXT,
        updated_by UUID REFERENCES users(id),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (case_id)
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_ctx_case ON ai_investigator_context(case_id)`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_feedback (
        id         BIGSERIAL PRIMARY KEY,
        case_id    UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
        rating     SMALLINT NOT NULL CHECK (rating IN (-1, 1)),
        agent_type VARCHAR(32),
        model      VARCHAR(100),
        msg_ref    TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_feedback_case ON ai_feedback(case_id)`);
    logger.info('[migration] ai_conversations + ai_investigator_context + ai_feedback OK');
  } catch (e) {
    logger.warn('[migration] ai tables', { error: e.message });
  }

  try {
    await pool.query(`ALTER TABLE case_messages ADD COLUMN IF NOT EXISTS reply_to_id UUID REFERENCES case_messages(id) ON DELETE SET NULL`);
    await pool.query(`ALTER TABLE case_messages ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE`);
    await pool.query(`ALTER TABLE case_messages ADD COLUMN IF NOT EXISTS pinned_by UUID REFERENCES users(id) ON DELETE SET NULL`);
    await pool.query(`ALTER TABLE case_messages ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_pinned ON case_messages(case_id, pinned) WHERE pinned = TRUE`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS case_message_reactions (
        id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        message_id UUID NOT NULL REFERENCES case_messages(id) ON DELETE CASCADE,
        user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        emoji      TEXT NOT NULL CHECK (char_length(emoji) <= 10),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (message_id, user_id, emoji)
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reactions_message ON case_message_reactions(message_id)`);
    logger.info('[migration] chat v2 OK');
  } catch (e) {
    logger.warn('[migration] chat v2', { error: e.message });
  }

  try {
    await pool.query(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS volweb_case_id INTEGER`);
    await pool.query(`ALTER TABLE evidence ADD COLUMN IF NOT EXISTS volweb_evidence_id INTEGER`);
    await pool.query(`ALTER TABLE evidence ADD COLUMN IF NOT EXISTS volweb_status TEXT CHECK (volweb_status IN ('uploading','processing','complete','error','not_linked'))`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_evidence_volweb ON evidence(volweb_status) WHERE volweb_status IS NOT NULL`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS memory_uploads (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        case_id          UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        evidence_id      UUID REFERENCES evidence(id) ON DELETE SET NULL,
        filename         TEXT NOT NULL,
        total_size       BIGINT NOT NULL,
        dump_os          TEXT NOT NULL DEFAULT 'windows' CHECK (dump_os IN ('windows','linux','mac')),
        temp_path        TEXT NOT NULL,
        total_chunks     INTEGER NOT NULL,
        received_chunks  INTEGER NOT NULL DEFAULT 0,
        status           TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading','hashing','forwarding','complete','error')),
        error_message    TEXT,
        created_by       UUID REFERENCES users(id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_memory_uploads_case   ON memory_uploads(case_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_memory_uploads_status ON memory_uploads(status)`);

    await pool.query(`ALTER TABLE memory_uploads ADD COLUMN IF NOT EXISTS chunk_size BIGINT NOT NULL DEFAULT 52428800`);
    await pool.query(`ALTER TABLE memory_uploads ADD COLUMN IF NOT EXISTS received_chunks_set INTEGER[] NOT NULL DEFAULT '{}'`);

    await pool.query(`ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_volweb_status_check`);
    await pool.query(`ALTER TABLE evidence ADD CONSTRAINT evidence_volweb_status_check CHECK (volweb_status IN ('uploading','processing','ready','complete','error','not_linked'))`);
    logger.info('[migration] volweb integration OK');
  } catch (e) {
    logger.warn('[migration] volweb integration', { error: e.message });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS report_templates (
        id          SERIAL PRIMARY KEY,
        name        VARCHAR(255) NOT NULL,
        description TEXT,
        config      JSONB NOT NULL DEFAULT '{}',
        is_default  BOOLEAN NOT NULL DEFAULT false,
        created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    logger.info('[migration] report_templates OK');
  } catch (e) {
    logger.warn('[migration] report_templates', { error: e.message });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS access_log (
        id           BIGSERIAL PRIMARY KEY,
        user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
        username     VARCHAR(100),
        method       VARCHAR(10) NOT NULL,
        path         TEXT NOT NULL,
        status_code  SMALLINT,
        response_ms  INTEGER,
        ip_address   INET,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_log_created ON access_log(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_log_user    ON access_log(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_log_method  ON access_log(method)`);
    logger.info('[migration] access_log OK');
  } catch (e) {
    logger.warn('[migration] access_log', { error: e.message });
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
