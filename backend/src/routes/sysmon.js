const express = require('express');
const path = require('path');
const fs = require('fs');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

const CONFIGS_DIR = path.resolve(__dirname, '../../../../sysmon-configs');
const INDEX_FILE = path.join(CONFIGS_DIR, 'index.json');

function loadIndex() {
  try {
    return JSON.parse(fs.readFileSync(INDEX_FILE, 'utf8'));
  } catch {
    return [];
  }
}

router.get('/configs', authenticate, async (req, res) => {
  try {
    const index = loadIndex();
    const dbRes = await pool.query(
      'SELECT config_key, is_recommended, deployed_at, notes FROM sysmon_configs'
    );
    const dbMap = Object.fromEntries(dbRes.rows.map(r => [r.config_key, r]));

    const configs = index.map(c => {
      const db = dbMap[c.id] || {};
      const filePath = path.join(CONFIGS_DIR, c.filename);
      const size = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;
      return {
        ...c,
        is_recommended: db.is_recommended ?? false,
        deployed_at: db.deployed_at ?? null,
        notes: db.notes ?? null,
        file_size: size,
        available: size > 0,
      };
    });

    res.json(configs);
  } catch (err) {
    logger.error('[sysmon]', err);
    res.status(500).json({ error: 'Erreur chargement configs' });
  }
});

router.get('/configs/:id/download', authenticate, async (req, res) => {
  try {
    const index = loadIndex();
    const config = index.find(c => c.id === req.params.id);
    if (!config) return res.status(404).json({ error: 'Configuration non trouvée' });

    const filePath = path.join(CONFIGS_DIR, config.filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Fichier introuvable' });

    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(CONFIGS_DIR)) return res.status(403).json({ error: 'Accès refusé' });

    await auditLog(req.user.id, 'download_sysmon_config', 'sysmon', req.params.id, { filename: config.filename }, req.ip);
    res.setHeader('Content-Disposition', `attachment; filename="${config.filename}"`);
    res.setHeader('Content-Type', 'application/xml');
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Erreur téléchargement' });
  }
});

router.post('/configs/:id/mark-deployed', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { notes } = req.body;
    await pool.query(
      `UPDATE sysmon_configs SET deployed_at = NOW(), deployed_by = $1, notes = COALESCE($2, notes)
       WHERE config_key = $3`,
      [req.user.id, notes || null, req.params.id]
    );
    await auditLog(req.user.id, 'deploy_sysmon_config', 'sysmon', req.params.id, { notes }, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur mise à jour' });
  }
});

module.exports = router;
