const jwt = require('jsonwebtoken');
const { canAccessCase, objetDansDossier, utilisateursAvecAcces } = require('../middleware/caseAccess');
const reportDocs = require('../services/reportDocRegistry');
const notebookDocs = require('../services/notebookDocs');
const { brancherCarnet } = require('./notebookSocket');

function registerSocketHandlers(io, { pool, logger, JWT_SECRET }) {
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
  const netmapPresenceMap = new Map();

  function getPresence(caseId) {
    const room = presenceMap.get(caseId);
    if (!room) return [];
    return Array.from(room.values());
  }

  function getNetmapPresence(caseId) {
    const room = netmapPresenceMap.get(caseId);
    if (!room) return [];
    return Array.from(room.values());
  }

  io.on('connection', (socket) => {
    const user = socket.user;
    logger.info('[Socket.io] Connexion', { username: user?.username, sid: socket.id });

    const guard = async (caseId) => !!caseId && (await canAccessCase(user, caseId).catch(() => false));

    socket.join(`user:${user.id}`);

    // sessionMap: socketId → { caseId, sessionId, startedAt }
    const sessionMap = new Map();
    const reportSubs = new Set(); // caseIds this socket subscribed to for report collab
    const carnet = brancherCarnet({ socket, pool, registre: notebookDocs, guard, user, logger });

    socket.on('case:join', async ({ caseId }) => {
      if (!(await guard(caseId))) { socket.emit('case:join:denied', { caseId }); return; }
      socket.join(caseId);
      socket.join(`case:${caseId}`);
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
      socket.leave(`case:${caseId}`);
      presenceMap.get(caseId)?.delete(socket.id);
      io.to(caseId).emit('case:presence', getPresence(caseId));
      logger.info('[Presence] Utilisateur quitte', { username: user.username, caseId });
      await closeSession(socket.id, caseId);
      if (reportSubs.delete(caseId)) reportDocs.releaseDoc(pool, caseId).catch(() => {});
      carnet.quitter(caseId);
    });

    socket.on('report:join', async ({ caseId }) => {
      if (!(await guard(caseId))) return;
      let doc;
      if (reportSubs.has(caseId)) {
        doc = await reportDocs.getDoc(pool, caseId);          // already subscribed on this socket — resend state only
      } else {
        reportSubs.add(caseId);
        doc = await reportDocs.acquireDoc(pool, caseId);       // first join on this socket — subscribe once
      }
      socket.emit('report:state', { caseId, update: reportDocs.encodeState(doc).toString('base64') });
    });

    socket.on('report:update', async ({ caseId, update }) => {
      // Bound the payload (base64 Yjs update); a single section edit is a few KB.
      if (!caseId || typeof update !== 'string' || update.length > 1_000_000) return;
      if (!(await guard(caseId))) return;
      reportDocs.applyRemoteUpdate(pool, caseId, new Uint8Array(Buffer.from(update, 'base64')));
      socket.to(`case:${caseId}`).emit('report:update', { caseId, update });
    });

    socket.on('networkmap:join', async ({ caseId }) => {
      if (!(await guard(caseId))) return;
      socket.join(`netmap:${caseId}`);
      if (!netmapPresenceMap.has(caseId)) netmapPresenceMap.set(caseId, new Map());
      netmapPresenceMap.get(caseId).set(socket.id, { id: user.id, username: user.username, full_name: user.full_name });
      io.to(`netmap:${caseId}`).emit('networkmap:presence', getNetmapPresence(caseId));
    });

    socket.on('networkmap:leave', ({ caseId }) => {
      if (!caseId) return;
      socket.leave(`netmap:${caseId}`);
      netmapPresenceMap.get(caseId)?.delete(socket.id);
      io.to(`netmap:${caseId}`).emit('networkmap:presence', getNetmapPresence(caseId));
    });

    socket.on('chat:send', async ({ caseId, content, reply_to_id }) => {
      if (!(await guard(caseId))) { socket.emit('chat:error', { message: 'Accès refusé' }); return; }
      if (!caseId || !content || typeof content !== 'string') return;
      const text = content.trim().slice(0, 4000);
      if (!text) return;
      try {
        if (reply_to_id) {
          const citeOk = await objetDansDossier('chat_message', reply_to_id, caseId, pool).catch(() => false);
          if (!citeOk) { socket.emit('chat:error', { message: 'Ressource introuvable' }); return; }
        }
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
             WHERE m.id = $1 AND m.case_id = $2`,
            [row.reply_to_id, caseId]
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
            `SELECT u.id, u.username FROM users u
             WHERE lower(u.username) = ANY($1::text[]) AND u.id != $2 AND ${utilisateursAvecAcces('$3')}`,
            [mentions, user.id, caseId]
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
             AND ${utilisateursAvecAcces('$1')}`,
          [caseId, JSON.stringify({ from: user.username, preview: text.slice(0, 80) }), user.id, mentions]
        ).catch(e => logger.warn('[chat:notify]', { error: e.message }));
      } catch (err) {
        socket.emit('chat:error', { message: 'Erreur envoi message' });
      }
    });

    socket.on('chat:typing', async (data) => {
      try {
        const caseId = data?.caseId;
        if (typeof caseId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(caseId)) return;
        if (!(await guard(caseId))) return;
        socket.to(caseId).emit('chat:typing', { caseId, userId: user.id, username: user.username });
      } catch (_) {}
    });

    socket.on('chat:react', async (data) => {
      try {
        const caseId = data?.caseId;
        const messageId = data?.messageId;
        const emoji = data?.emoji;
        if (typeof caseId !== 'string' || !(await guard(caseId))) return;
        if (typeof emoji !== 'string' || emoji.length === 0 || emoji.length > 10) return;
        if (!(await objetDansDossier('chat_message', messageId, caseId, pool))) return;
        const existe = await pool.query(
          'SELECT 1 FROM case_message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
          [messageId, user.id, emoji]
        );
        socket.to(caseId).emit('chat:react', {
          caseId,
          messageId,
          emoji,
          userId: user.id,
          added: existe.rows.length > 0,
        });
      } catch (_) {}
    });

    socket.on('chat:pin', async (data) => {
      try {
        const caseId = data?.caseId;
        const messageId = data?.messageId;
        if (typeof caseId !== 'string' || !(await guard(caseId))) return;
        if (!(await objetDansDossier('chat_message', messageId, caseId, pool))) return;
        const etat = await pool.query(
          'SELECT pinned FROM case_messages WHERE id = $1 AND case_id = $2',
          [messageId, caseId]
        );
        if (!etat.rows.length) return;
        socket.to(caseId).emit('chat:pin', {
          message_id: messageId,
          pinned:     etat.rows[0].pinned === true,
          pinned_by:  user.username,
          case_id:    caseId,
        });
      } catch (_) {}
    });

    socket.on('parser:start', async (data) => {
      if (!(await guard(data?.caseId))) { socket.emit('parser:error', { message: 'Accès refusé' }); return; }
      const { parserQueue } = require('../config/queue');
      const { getAvailableTools, optionsParseurClient } = require('../services/parserService');
      try {
        const tools = getAvailableTools();
        const parserConnu = typeof data.parser === 'string'
          && data.parser !== 'backup'
          && Object.prototype.hasOwnProperty.call(tools, data.parser)
          && tools[data.parser].available;
        if (!parserConnu) {
          socket.emit('parser:error', { message: 'Parseur inconnu' });
          return;
        }

        const evidenceOk = await objetDansDossier('evidence', data.evidenceId, data.caseId, pool).catch(() => false);
        if (!evidenceOk) {
          socket.emit('parser:error', { message: 'Ressource introuvable' });
          return;
        }

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

        const extraArgs = optionsParseurClient(data.extraArgs);

        await parserQueue.add('parse', {
          parser:     data.parser,
          evidenceId: data.evidenceId,
          caseId:     data.caseId,
          userId:     user.id,
          socketId:   socket.id,
          extraArgs,
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
      for (const [caseId, room] of netmapPresenceMap.entries()) {
        if (room.has(socket.id)) {
          room.delete(socket.id);
          io.to(`netmap:${caseId}`).emit('networkmap:presence', getNetmapPresence(caseId));
        }
      }
      // release every report doc this socket subscribed to
      for (const cid of reportSubs) { reportDocs.releaseDoc(pool, cid).catch(() => {}); }
      reportSubs.clear();
      carnet.fermer();
    });

    socket.on('error', (err) => {
      logger.error('[Socket.io] Erreur socket', { sid: socket.id, error: err.message });
    });
  });
}

module.exports = { registerSocketHandlers };
