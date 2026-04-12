
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
const sysmonRoutes        = require('./routes/sysmon');
const timelinePinsRoutes  = require('./routes/timelinePins');
const chatRoutes          = require('./routes/chat');
const adminRoutes         = require('./routes/admin');
const playbooksRoutes     = require('./routes/playbooks');
const soarRoutes          = require('./routes/soar');
const feedbackRoutes      = require('./routes/feedback');
const volwebRoutes        = require('./routes/volweb');
const llmRoutes           = require('./routes/llm');
const aiRoutes            = require('./routes/ai');

const app = express();

app.set('etag', false);

const server = http.createServer(app);
const PORT = process.env.PORT || 4000;

server.keepAliveTimeout = 75000;
server.headersTimeout   = 76000;

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

io.engine.on('connection', (rawSocket) => {
  logger.debug('[Engine.io] Nouvelle connexion brute', { transport: rawSocket.transport.name, id: rawSocket.id });
});
io.engine.on('connection_error', (err) => {
  logger.error('[Engine.io] Erreur connexion', { code: err.code, error: err.message });
});

io.use((socket, next) => {
  const transport = socket.conn?.transport?.name ?? 'unknown';
  logger.debug('[Socket.io] Middleware auth', { transport, sid: socket.id });
  const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.split(' ')[1];
  if (!token) {
    logger.warn('[Socket.io] Token manquant');
    return next(new Error('Token Socket.io manquant'));
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    logger.debug('[Socket.io] Auth OK', { username: decoded.username });
    next();
  } catch (err) {
    logger.warn('[Socket.io] Token invalide', { error: err.message });
    next(new Error('Token Socket.io invalide'));
  }
});

const presenceMap = new Map();

function getPresence(caseId) {
  const room = presenceMap.get(caseId);
  if (!room) return [];
  return Array.from(room.values());
}

io.on('connection', (socket) => {
  const user = socket.user;
  logger.info('[Socket.io] Connexion', { username: user?.username, sid: socket.id });

  socket.join(`user:${user.id}`);

  // sessionMap: socketId → { caseId, sessionId, startedAt }
  const sessionMap = new Map();

  socket.on('case:join', async ({ caseId }) => {
    if (!caseId) return;
    socket.join(caseId);
    if (!presenceMap.has(caseId)) presenceMap.set(caseId, new Map());
    presenceMap.get(caseId).set(socket.id, {
      id:        user.id,
      username:  user.username,
      full_name: user.full_name,
    });
    io.to(caseId).emit('case:presence', getPresence(caseId));
    logger.info('[Presence] Utilisateur rejoint', { username: user.username, caseId });
    // Record session start
    try {
      const res = await pool.query(
        `INSERT INTO case_sessions (case_id, user_id, started_at) VALUES ($1, $2, NOW()) RETURNING id`,
        [caseId, user.id]
      );
      sessionMap.set(socket.id + ':' + caseId, { caseId, sessionId: res.rows[0].id, startedAt: Date.now() });
    } catch (_) {}
  });

  async function closeSession(socketId, caseId) {
    const key = socketId + ':' + caseId;
    const sess = sessionMap.get(key);
    if (!sess) return;
    sessionMap.delete(key);
    const dur = Math.round((Date.now() - sess.startedAt) / 1000);
    try {
      await pool.query(
        `UPDATE case_sessions SET ended_at = NOW(), duration_s = $1 WHERE id = $2`,
        [dur, sess.sessionId]
      );
    } catch (_) {}
  }

  socket.on('case:leave', async ({ caseId }) => {
    if (!caseId) return;
    socket.leave(caseId);
    presenceMap.get(caseId)?.delete(socket.id);
    io.to(caseId).emit('case:presence', getPresence(caseId));
    logger.info('[Presence] Utilisateur quitte', { username: user.username, caseId });
    await closeSession(socket.id, caseId);
  });

  socket.on('chat:send', async ({ caseId, content, reply_to_id }) => {
    if (!caseId || !content || typeof content !== 'string') return;
    const text = content.trim().slice(0, 4000);
    if (!text) return;
    try {
      const result = await pool.query(
        `INSERT INTO case_messages (case_id, author_id, content, reply_to_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id, case_id, content, created_at, reply_to_id`,
        [caseId, user.id, text, reply_to_id || null]
      );
      const row = result.rows[0];

      let replyTo = null;
      if (row.reply_to_id) {
        const rt = await pool.query(
          `SELECT m.id, m.content, u.username, u.full_name
           FROM case_messages m JOIN users u ON u.id = m.author_id
           WHERE m.id = $1`,
          [row.reply_to_id]
        );
        if (rt.rows.length) replyTo = rt.rows[0];
      }

      const msg = {
        id:         row.id,
        case_id:    row.case_id,
        content:    row.content,
        created_at: row.created_at,
        author_id:  user.id,
        username:   user.username,
        full_name:  user.full_name,
        role:       user.role,
        reply_to:   replyTo,
        reactions:  [],
        pinned:     false,
      };
      io.to(caseId).emit('chat:message', msg);

      const mentions = [...new Set((text.match(/@(\w+)/g) || []).map(m => m.slice(1).toLowerCase()))];
      if (mentions.length > 0) {
        const mentionedUsers = await pool.query(
          `SELECT id, username FROM users WHERE lower(username) = ANY($1::text[]) AND id != $2`,
          [mentions, user.id]
        ).catch(() => ({ rows: [] }));
        for (const mu of mentionedUsers.rows) {
          io.to(`user:${mu.id}`).emit('chat:mention', {
            from_user:     user.username,
            from_full_name: user.full_name,
            case_id:       caseId,
            message_id:    row.id,
            preview:       text.slice(0, 100),
            sent_at:       row.created_at,
          });
          pool.query(
            `INSERT INTO case_notifications (user_id, case_id, type, payload)
             VALUES ($1, $2, 'mention', $3)`,
            [mu.id, caseId, JSON.stringify({ from: user.username, preview: text.slice(0, 80) })]
          ).catch(() => {});
        }
      }

      pool.query(
        `INSERT INTO case_notifications (user_id, case_id, type, payload)
         SELECT u.id, $1, 'chat', $2 FROM users u
         WHERE u.id != $3 AND NOT (lower(u.username) = ANY($4::text[]))
           AND EXISTS (SELECT 1 FROM cases WHERE id = $1)`,
        [caseId, JSON.stringify({ from: user.username, preview: text.slice(0, 80) }), user.id, mentions]
      ).catch(e => logger.warn('[chat:notify]', { error: e.message }));
    } catch (err) {
      socket.emit('chat:error', { message: 'Erreur envoi message' });
    }
  });

  socket.on('chat:typing', (data) => {
    if (!data || !data.caseId) return;
    socket.to(data.caseId).emit('chat:typing', data);
  });

  socket.on('chat:react', (data) => {
    if (!data || !data.caseId) return;
    socket.to(data.caseId).emit('chat:react', data);
  });

  socket.on('chat:pin', (data) => {
    if (!data || !data.caseId) return;
    socket.to(data.caseId).emit('chat:pin', data);
  });

  socket.on('parser:start', async (data) => {
    const { parserQueue } = require('./config/queue');
    try {

      const [waiting, active] = await Promise.all([
        parserQueue.getJobs(['waiting']),
        parserQueue.getJobs(['active']),
      ]);
      const userJobs = [...waiting, ...active].filter(j => j.data?.userId === user.id);
      if (userJobs.length >= 5) {
        logger.warn('[socket parser:start] 429 rate limit', { userId: user.id, count: userJobs.length });
        socket.emit('parser:error', { message: 'Trop de jobs en attente. Limite : 5 jobs simultanés.' });
        return;
      }

      await parserQueue.add('parse', {
        parser:     data.parser,
        evidenceId: data.evidenceId,
        caseId:     data.caseId,
        userId:     user.id,
        socketId:   socket.id,
        extraArgs:  data.extraArgs || {},
      });
    } catch (err) {
      socket.emit('parser:error', { message: err.message });
    }
  });

  socket.on('disconnect', async (reason) => {
    logger.info('[Socket.io] Déconnexion', { username: user?.username, sid: socket.id, reason });

    for (const [caseId, room] of presenceMap.entries()) {
      if (room.has(socket.id)) {
        room.delete(socket.id);
        io.to(caseId).emit('case:presence', getPresence(caseId));
        await closeSession(socket.id, caseId);
      }
    }
  });

  socket.on('error', (err) => {
    logger.error('[Socket.io] Erreur socket', { sid: socket.id, error: err.message });
  });
});

app.set('etag', false);

app.use(helmet({

  contentSecurityPolicy:          false,
  strictTransportSecurity:        false,
  referrerPolicy:                 false,
  xXssProtection:                 false,
  xFrameOptions:                  false,
  xContentTypeOptions:            false,

  crossOriginEmbedderPolicy:      false,
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(morgan('combined'));
app.use(requestIdMiddleware);

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
app.use('/api/sysmon',         sysmonRoutes);
app.use('/api/timeline-pins',  timelinePinsRoutes);
app.use('/api/chat',           chatRoutes);
app.use('/api/admin',                  adminRoutes);
app.use('/api/playbooks',              playbooksRoutes);
app.use('/api/cases/:caseId/soar',    soarRoutes);
app.use('/api/feedback',              feedbackRoutes);
app.use('/api/volweb',                volwebRoutes);
app.use('/api/llm',                   llmRoutes);
app.use('/api',                       aiRoutes);

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
    logger.info('[migration] ai_conversations + ai_investigator_context OK');
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
  } catch (err) {
    logger.error('Échec du démarrage', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

start();
