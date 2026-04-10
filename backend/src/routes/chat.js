
const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

router.get('/:caseId/history', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const limit = Math.min(200, parseInt(req.query.limit) || 50);
    const beforeId = req.query.before_id || null;

    let beforeTs = null;
    if (beforeId) {
      const cur = await pool.query(
        'SELECT created_at FROM case_messages WHERE id = $1',
        [beforeId]
      );
      if (cur.rows.length) beforeTs = cur.rows[0].created_at;
    }

    const msgsRes = await pool.query(
      `SELECT
         m.id, m.case_id, m.content, m.created_at,
         m.reply_to_id, m.pinned, m.pinned_at,
         u.id   AS author_id,
         u.username, u.full_name, u.role,
         -- reply-to preview (flat columns to avoid subquery overhead)
         rt.id          AS rt_id,
         rt.content     AS rt_content,
         ru.username    AS rt_username,
         ru.full_name   AS rt_full_name,
         pu.username    AS pinned_by_username
       FROM case_messages m
       JOIN users u  ON u.id  = m.author_id
       LEFT JOIN case_messages rt ON rt.id = m.reply_to_id
       LEFT JOIN users ru ON ru.id = rt.author_id
       LEFT JOIN users pu ON pu.id = m.pinned_by
       WHERE m.case_id = $1
         AND ($2::timestamptz IS NULL OR m.created_at < $2)
       ORDER BY m.created_at DESC
       LIMIT $3`,
      [caseId, beforeTs, limit + 1]
    );

    const rows = msgsRes.rows;
    const hasMore = rows.length > limit;
    const messages = (hasMore ? rows.slice(0, limit) : rows).reverse();

    const msgIds = messages.map(m => m.id);
    let reactionsRaw = [];
    if (msgIds.length > 0) {
      const rRes = await pool.query(
        `SELECT r.message_id, r.emoji, r.user_id, u.username, u.full_name
         FROM case_message_reactions r
         JOIN users u ON u.id = r.user_id
         WHERE r.message_id = ANY($1::uuid[])`,
        [msgIds]
      );
      reactionsRaw = rRes.rows;
    }

    const reactByMsg = {};
    for (const r of reactionsRaw) {
      if (!reactByMsg[r.message_id]) reactByMsg[r.message_id] = [];
      reactByMsg[r.message_id].push({ emoji: r.emoji, user_id: r.user_id, username: r.username, full_name: r.full_name });
    }

    const result = messages.map(m => ({
      id:         m.id,
      case_id:    m.case_id,
      content:    m.content,
      created_at: m.created_at,
      author_id:  m.author_id,
      username:   m.username,
      full_name:  m.full_name,
      role:       m.role,
      pinned:     m.pinned,
      pinned_at:  m.pinned_at,
      pinned_by_username: m.pinned_by_username || null,
      reply_to: m.rt_id ? {
        id:        m.rt_id,
        content:   m.rt_content,
        username:  m.rt_username,
        full_name: m.rt_full_name,
      } : null,
      reactions: reactByMsg[m.id] || [],
    }));

    res.json({ messages: result, has_more: hasMore });
  } catch (err) {
    logger.error('[chat:history]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/pinned', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.id, m.content, m.created_at, m.pinned_at,
              u.username, u.full_name,
              pu.username AS pinned_by_username
       FROM case_messages m
       JOIN users u  ON u.id = m.author_id
       LEFT JOIN users pu ON pu.id = m.pinned_by
       WHERE m.case_id = $1 AND m.pinned = TRUE
       ORDER BY m.pinned_at DESC
       LIMIT 1`,
      [req.params.caseId]
    );
    res.json(r.rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/:messageId/pin', authenticate, async (req, res) => {
  try {
    const { caseId, messageId } = req.params;

    const cur = await pool.query(
      'SELECT pinned FROM case_messages WHERE id = $1 AND case_id = $2',
      [messageId, caseId]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'Message introuvable' });

    const nowPinned = !cur.rows[0].pinned;

    if (nowPinned) {

      await pool.query(
        'UPDATE case_messages SET pinned = FALSE, pinned_by = NULL, pinned_at = NULL WHERE case_id = $1',
        [caseId]
      );
    }

    await pool.query(
      `UPDATE case_messages
       SET pinned    = $1,
           pinned_by = $2,
           pinned_at = $3
       WHERE id = $4`,
      [nowPinned, nowPinned ? req.user.id : null, nowPinned ? new Date() : null, messageId]
    );

    const io = req.app.locals.io;
    if (io) {
      io.to(caseId).emit('chat:pin', {
        message_id: messageId,
        pinned:     nowPinned,
        pinned_by:  req.user.username,
        case_id:    caseId,
      });
    }

    res.json({ ok: true, pinned: nowPinned });
  } catch (err) {
    logger.error('[chat:pin]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/:messageId/react', authenticate, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;
    if (!emoji || typeof emoji !== 'string' || emoji.length > 10) {
      return res.status(400).json({ error: 'Emoji invalide' });
    }

    const existing = await pool.query(
      'SELECT id FROM case_message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
      [messageId, req.user.id, emoji]
    );

    let added;
    if (existing.rows.length) {

      await pool.query(
        'DELETE FROM case_message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
        [messageId, req.user.id, emoji]
      );
      added = false;
    } else {

      await pool.query(
        'INSERT INTO case_message_reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
        [messageId, req.user.id, emoji]
      );
      added = true;
    }

    res.json({ ok: true, added, emoji, user_id: req.user.id });
  } catch (err) {
    logger.error('[chat:react]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/notifications', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM case_notifications
       WHERE user_id = $1 AND read = FALSE
       ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/notifications/:id/read', authenticate, async (req, res) => {
  try {
    await pool.query(
      'UPDATE case_notifications SET read = TRUE WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/notifications/read-all', authenticate, async (req, res) => {
  try {
    await pool.query(
      'UPDATE case_notifications SET read = TRUE WHERE user_id = $1',
      [req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/ping', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { message, target_user_id } = req.body;
    const pingMsg = (message || '').toString().trim().slice(0, 200) || 'Ping !';

    const payload = JSON.stringify({
      from: req.user.username,
      from_id: req.user.id,
      message: pingMsg,
      case_id: caseId,
      target_user_id: target_user_id || null,
    });

    if (target_user_id) {
      await pool.query(
        `INSERT INTO case_notifications (user_id, case_id, type, payload) VALUES ($1, $2, 'ping', $3)`,
        [target_user_id, caseId, payload]
      );
    } else {
      await pool.query(
        `INSERT INTO case_notifications (user_id, case_id, type, payload)
         SELECT u.id, $1, 'ping', $2 FROM users u
         WHERE EXISTS (SELECT 1 FROM cases WHERE id = $1)`,
        [caseId, payload]
      );
    }

    const socketPayload = {
      from_user: req.user.username,
      from_full_name: req.user.full_name,
      message: pingMsg,
      case_id: caseId,
      sent_at: new Date().toISOString(),
      target_user_id: target_user_id || null,
    };

    const io = req.app.locals.io;
    if (io) {
      if (target_user_id) {

        io.to(`user:${target_user_id}`).emit('case:ping', socketPayload);
      } else {

        io.to(caseId).emit('case:ping', socketPayload);
      }
    }

    res.json({ ok: true });
  } catch (err) {
    logger.error('[chat:ping]', err);
    res.status(500).json({ error: 'Erreur envoi ping' });
  }
});

router.delete('/:caseId/:messageId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM case_messages WHERE id = $1 AND author_id = $2 RETURNING id',
      [req.params.messageId, req.user.id]
    );
    if (result.rows.length === 0) return res.status(403).json({ error: 'Non autorisé' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
