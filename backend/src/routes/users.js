const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

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
    const allowed = ['language', 'timezone', 'theme', 'chat_color', 'table_density', 'display_name'];
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
    const result = await pool.query(
      `UPDATE users SET full_name = COALESCE($1, full_name),
       role = COALESCE($2, role), is_active = COALESCE($3, is_active), updated_at = NOW()
       WHERE id = $4 RETURNING id, username, full_name, role, is_active`,
      [full_name, role, is_active, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    await auditLog(req.user.id, 'update_user', 'user', req.params.id, req.body, req.ip);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/:id/password', authenticate, async (req, res) => {
  try {
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Non autorisé' });
    }
    const { password } = req.body;
    if (!password || password.length < 8) return res.status(400).json({ error: 'Min 8 caractères' });
    const hash = await bcrypt.hash(password, 12);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hash, req.params.id]);
    await auditLog(req.user.id, 'change_password', 'user', req.params.id, {}, req.ip);
    res.json({ message: 'Mot de passe mis à jour' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (req.user.id === req.params.id) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING username', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    await auditLog(req.user.id, 'delete_user', 'user', req.params.id, { deleted: result.rows[0].username }, req.ip);
    res.json({ message: 'Utilisateur supprimé' });
  } catch (err) {
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
