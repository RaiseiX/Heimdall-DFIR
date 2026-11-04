const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog, auditCritical, computeAuditHmac, computeAuditHmacLegacy } = require('../middleware/auth');
const { verifyAuditLog } = require('../services/auditChain');
const { couperSessionsUtilisateur } = require('../services/sessionRevocation');
const { revoquerJti, normaliserId } = require('../services/sessionGuard');

const logger = require('../config/logger').default;
const router = express.Router();

const DEFAULT_PREFERENCES = {
  language: 'fr',
  timezone: 'utc',
  theme: 'dark',
  chat_color: '#4d82c0',
  table_density: 'standard',
};

router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, full_name, role, last_login, created_at, preferences FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    const row = result.rows[0];
    res.json({ ...row, preferences: { ...DEFAULT_PREFERENCES, ...(row.preferences || {}) } });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.patch('/me/preferences', authenticate, async (req, res) => {
  try {
    const allowed = ['language', 'timezone', 'theme', 'chat_color', 'table_density', 'display_name',
      'notif_desktop', 'notif_critical', 'notif_mentions', 'notif_oncall'];
    const patch = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) patch[key] = req.body[key];
    }
    if (Object.keys(patch).length === 0) return res.status(400).json({ error: 'Aucune préférence valide' });

    const result = await pool.query(
      `UPDATE users
       SET preferences = preferences || $1::jsonb, updated_at = NOW()
       WHERE id = $2
       RETURNING preferences`,
      [JSON.stringify(patch), req.user.id]
    );
    const merged = { ...DEFAULT_PREFERENCES, ...(result.rows[0].preferences || {}) };
    res.json({ preferences: merged });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Personal API tokens ──────────────────────────────────────────────────────
router.get('/me/tokens', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, name, created_at, last_used FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ tokens: r.rows });
  } catch (err) {
    logger.error('tokens list:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/me/tokens', authenticate, async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim().slice(0, 120);
    if (!name) return res.status(400).json({ error: 'Nom requis' });
    const raw  = `hmd_${crypto.randomBytes(32).toString('hex')}`;
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    const r = await pool.query(
      'INSERT INTO api_tokens (user_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id, name, created_at',
      [req.user.id, name, hash]
    );
    // The raw token is returned ONCE — only the hash is stored.
    res.status(201).json({ token: raw, ...r.rows[0] });
  } catch (err) {
    logger.error('token create:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/me/tokens/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM api_tokens WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Active sessions (refresh tokens) ─────────────────────────────────────────
router.get('/me/sessions', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, created_at, expires_at FROM refresh_tokens
       WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ sessions: r.rows });
  } catch (err) {
    logger.error('sessions list:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/me/sessions/revoke-all', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE',
      [req.user.id]
    );
    await couperSessionsUtilisateur(req.app.locals.io, req.user.id);
    if (req.user.jti) {
      const ttl = req.user.exp ? req.user.exp - Math.floor(Date.now() / 1000) : 28800;
      await revoquerJti(req.user.jti, ttl > 0 ? ttl : 1);
    }
    res.json({ revoked: r.rowCount });
  } catch (err) {
    logger.error('sessions revoke-all:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

async function inTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const value = await work(client);
    await client.query('COMMIT');
    return value;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

const USER_UPDATE_FIELDS = ['full_name', 'role', 'is_active'];

router.get('/', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, full_name, role, is_active, last_login, created_at FROM users ORDER BY created_at'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { full_name, role, is_active } = req.body;
    const outcome = await inTransaction(async (client) => {
      const avant = await client.query('SELECT role, is_active FROM users WHERE id = $1 FOR UPDATE', [req.params.id]);
      const result = await client.query(
        `UPDATE users SET full_name = COALESCE($1, full_name),
         role = COALESCE($2, role), is_active = COALESCE($3, is_active), updated_at = NOW()
         WHERE id = $4 RETURNING id, username, full_name, role, is_active`,
        [full_name, role, is_active, req.params.id]
      );
      if (result.rows.length === 0) return null;
      const ancien = avant.rows[0];
      const apres = result.rows[0];
      const submitted = req.body && typeof req.body === 'object' ? req.body : {};
      const changed = USER_UPDATE_FIELDS.filter(f => submitted[f] !== undefined && submitted[f] !== null);
      await auditCritical(client, req.user.id, 'update_user', 'user', req.params.id, {
        changed_fields: changed,
        previous_role: ancien ? ancien.role : null,
        new_role: apres.role,
        previous_is_active: ancien ? ancien.is_active : null,
        new_is_active: apres.is_active,
      }, req.ip);
      return { ancien, apres };
    });
    if (!outcome) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    const { ancien, apres } = outcome;
    if (ancien && (apres.is_active === false || apres.role !== ancien.role)) {
      await couperSessionsUtilisateur(req.app.locals.io, apres.id);
    }
    res.json(apres);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/:id/password', authenticate, async (req, res) => {
  try {
    if (normaliserId(req.user.id) !== normaliserId(req.params.id) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Non autorisé' });
    }
    const { password } = req.body;
    const { getSecurityPolicy } = require('../services/securityPolicy');
    const minLen = (await getSecurityPolicy()).passwordMinLength;
    if (!password || password.length < minLen) return res.status(400).json({ error: `Min ${minLen} caractères` });
    const hash = await bcrypt.hash(password, 12);
    const maj = await inTransaction(async (client) => {
      const updated = await client.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 RETURNING id', [hash, req.params.id]);
      if (updated.rows && updated.rows[0]) {
        await client.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE', [updated.rows[0].id]);
      }
      await auditCritical(client, req.user.id, 'change_password', 'user', req.params.id, {}, req.ip);
      return updated;
    });
    if (maj.rows && maj.rows[0]) {
      const cible = maj.rows[0].id;
      await couperSessionsUtilisateur(req.app.locals.io, cible);
    }
    res.json({ message: 'Mot de passe mis à jour' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (normaliserId(req.user.id) === normaliserId(req.params.id)) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
    const deleted = await inTransaction(async (client) => {
      const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING id, username', [req.params.id]);
      if (result.rows.length === 0) return null;
      await auditCritical(client, req.user.id, 'delete_user', 'user', req.params.id, { deleted: result.rows[0].username }, req.ip);
      return result.rows[0];
    });
    if (!deleted) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    await couperSessionsUtilisateur(req.app.locals.io, deleted.id);
    res.json({ message: 'Utilisateur supprimé' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Audit log integrity verification (HMAC recompute) ───────────────────────
router.get('/audit/verify', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const PAGE = 1000;
    const meta = await pool.query('SELECT genesis_seq::text AS genesis_seq FROM audit_chain_meta LIMIT 1');
    const genesis = meta.rows[0] ? meta.rows[0].genesis_seq : null;

    let verified = 0, tampered = 0, legacy = 0, missing = 0, legacyChecked = 0;
    const tamperedIds = [];
    let cursor = '0';
    for (;;) {
      const page = await pool.query(
        `SELECT seq::text AS seq_text, id, user_id, action, entity_type, entity_id, details, created_at, hmac
           FROM audit_log
          WHERE prev_hash IS NULL AND seq > $1::bigint AND ($2::bigint IS NULL OR seq < $2::bigint)
          ORDER BY audit_log.seq ASC LIMIT $3`, [cursor, genesis, PAGE]
      );
      for (const row of page.rows) {
        legacyChecked++;
        if (!row.hmac) { missing++; continue; }
        const fields = {
          user_id: row.user_id, action: row.action, entity_type: row.entity_type,
          entity_id: row.entity_id, details: row.details ?? {},
          ts: new Date(row.created_at).toISOString(),
        };
        if (computeAuditHmac(fields) === row.hmac || computeAuditHmacLegacy(fields) === row.hmac) {
          verified++;
        } else {
          const keys = row.details && typeof row.details === 'object' ? Object.keys(row.details) : [];
          if (keys.length <= 1) { tampered++; if (tamperedIds.length < 20) tamperedIds.push(row.id); }
          else legacy++;
        }
      }
      if (page.rows.length < PAGE) break;
      cursor = page.rows[page.rows.length - 1].seq_text;
    }

    const report = await verifyAuditLog(pool);
    const firstProblem = report.problems[0];
    const chain = firstProblem
      ? { ok: false, checked: report.checked, reason: firstProblem.type, breakAtSeq: firstProblem.seq }
      : { ok: true, checked: report.checked };

    const summary = {
      checked: legacyChecked + report.checked,
      legacy_checked: legacyChecked,
      verified, tampered, legacy_unverifiable: legacy, missing,
      tampered_ids: tamperedIds,
      chain,
      complete: report.complete,
      genesis_seq: report.genesis_seq,
      first_seq: report.first_seq,
      last_seq: report.last_seq,
      last_hmac: report.last_hmac,
      problem_counts: report.problem_counts,
      problems: report.problems,
      problems_truncated: report.problems_truncated,
    };

    await auditLog(req.user.id, 'verify_audit_integrity', 'system', null,
      {
        checked: summary.checked, verified, tampered, legacy_unverifiable: legacy, missing, chain,
        complete: summary.complete, first_seq: summary.first_seq, last_seq: summary.last_seq,
        last_hmac: summary.last_hmac, problem_counts: summary.problem_counts,
      }, req.ip);
    res.json(summary);
  } catch (err) {
    logger.error('audit verify error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/audit', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { action, user_id, entity_type, date_from, date_to, limit = 100, offset = 0 } = req.query;

    const ALLOWED_ENTITY_TYPES = ['case', 'evidence', 'user', 'collection', 'report', 'ioc', 'mitre', 'yara_rule', 'sigma_rule', 'taxii_feed', 'system', 'bookmark', 'sysmon'];
    const ALLOWED_ACTIONS = [
      'login', 'login_failed', 'login_blocked', 'logout', 'token_refresh',
      'create_user', 'update_user', 'delete_user', 'change_password',
      'create_case', 'update_case', 'hard_delete_case',
      'triage_compute', 'legal_hold_enable', 'legal_hold_disable',
      'upload_evidence', 'delete_evidence', 'upload_evidence_chunked',
      'import_collection', 'parse_collection', 'delete_collection_data', 'pcap_parse',
      'run_hayabusa',
      'add_mitre_technique', 'update_mitre_technique', 'delete_mitre_technique',
      'generate_report', 'download_report',
      'create_ioc', 'delete_ioc', 'export_stix', 'correlate_case',
      'run_yara_scan', 'run_sigma_hunt', 'fetch_taxii',
      'backup_db', 'backup_schedule_set', 'backup_schedule_removed', 'download_backup',
      'run_soar', 'soar_run',
      'start_playbook',
      'create_bookmark',
      'download_sysmon_config', 'deploy_sysmon_config',
      'run_parser',
      'verify_audit_integrity', 'update_settings',
      'retention_auto_purge', 'retention_run_manual',
      'audit_key_rotation', 'export_anonymized', 'download_collection_file',
      'upload_evidence_stream', 'confirm_ioc', 'upload_memory_dump',
      'delete_parser_result', 'purge_fs_timeline', 'purge_catscale_state',
      'hard_delete_case_started', 'retention_auto_purge_started', 'delete_evidence_started',
      'delete_collection_data_started', 'delete_parser_result_started',
    ];

    let query = `
      SELECT al.id, al.action, al.entity_type, al.entity_id, al.details, al.ip_address, al.created_at, al.hmac,
             u.username, u.full_name
      FROM audit_log al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1`;
    const params = [];

    if (action && ALLOWED_ACTIONS.includes(action)) {
      params.push(action);
      query += ` AND al.action = $${params.length}`;
    }
    if (user_id) {
      params.push(user_id);
      query += ` AND al.user_id = $${params.length}`;
    }
    if (entity_type && ALLOWED_ENTITY_TYPES.includes(entity_type)) {
      params.push(entity_type);
      query += ` AND al.entity_type = $${params.length}`;
    }
    if (date_from) {
      params.push(date_from);
      query += ` AND al.created_at >= $${params.length}`;
    }
    if (date_to) {
      params.push(date_to);
      query += ` AND al.created_at <= $${params.length}`;
    }

    const countQuery = query.replace(
      /SELECT al\.id.*FROM audit_log/s,
      'SELECT COUNT(*) FROM audit_log'
    );
    const countResult = await pool.query(countQuery, params);
    const total = parseInt(countResult.rows[0].count);

    params.push(Math.min(parseInt(limit) || 100, 500));
    query += ` ORDER BY al.created_at DESC LIMIT $${params.length}`;
    params.push(parseInt(offset) || 0);
    query += ` OFFSET $${params.length}`;

    const result = await pool.query(query, params);
    res.json({ total, rows: result.rows });
  } catch (err) {
    logger.error('Audit query error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
