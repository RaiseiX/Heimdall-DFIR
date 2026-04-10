const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { processMemoryDump } = require('../services/volwebService');

const logger = require('../config/logger').default;
const router = express.Router();

async function verifyFileIntegrity(filePath, storedHash) {
  return new Promise((resolve) => {
    if (!storedHash) {
      return resolve({ ok: false, stored: null, computed: null, reason: 'no_stored_hash' });
    }
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => {
      const computed = hash.digest('hex');
      resolve({ ok: computed === storedHash, stored: storedHash, computed });
    });
    stream.on('error', (err) => {
      resolve({ ok: false, stored: storedHash, computed: null, reason: err.message });
    });
  });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(process.env.UPLOAD_DIR || '/app/uploads', req.params.caseId || 'temp');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 * 1024 } });

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, u.full_name as added_by_name,
        (SELECT COUNT(*) FROM evidence_comments WHERE evidence_id = e.id) as comment_count
      FROM evidence e
      LEFT JOIN users u ON e.added_by = u.id
      WHERE e.case_id = $1
      ORDER BY e.created_at DESC
    `, [req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Fichier requis' });

    const hash_md5    = crypto.createHash('md5');
    const hash_sha1   = crypto.createHash('sha1');
    const hash_sha256 = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(file.path, { highWaterMark: 64 * 1024 });
      stream.on('data', chunk => { hash_md5.update(chunk); hash_sha1.update(chunk); hash_sha256.update(chunk); });
      stream.on('end', resolve);
      stream.on('error', reject);
    });

    const md5    = hash_md5.digest('hex');
    const sha1   = hash_sha1.digest('hex');
    const sha256 = hash_sha256.digest('hex');

    const { evidence_type, notes } = req.body;

    const result = await pool.query(
      `INSERT INTO evidence (case_id, name, original_filename, file_path, file_size, evidence_type, hash_md5, hash_sha1, hash_sha256, notes, added_by, chain_of_custody)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [
        req.params.caseId, file.originalname, file.originalname, file.path,
        file.size, evidence_type || 'other', md5, sha1, sha256,
        notes, req.user.id,
        JSON.stringify([{ action: 'uploaded', user: req.user.full_name, timestamp: new Date().toISOString(), hash_sha256: sha256 }])
      ]
    );

    await auditLog(req.user.id, 'upload_evidence', 'evidence', result.rows[0].id, { filename: file.originalname, hash_sha256: sha256 }, req.ip);
    res.status(201).json(result.rows[0]);

    if ((evidence_type || '').toLowerCase() === 'memory') {
      pool.query('SELECT case_number, title FROM cases WHERE id = $1', [req.params.caseId])
        .then(caseRes => {
          if (!caseRes.rows.length) return;
          const { case_number, title } = caseRes.rows[0];
          const osGuess = /linux/i.test(file.originalname) ? 'linux'
            : /mac|osx/i.test(file.originalname) ? 'mac' : 'windows';
          processMemoryDump({
            filePath:       file.path,
            caseTitle:      title,
            caseNumber:     case_number,
            os:             req.body.dump_os || osGuess,
            heimdallCaseId: req.params.caseId,
            evidenceId:     result.rows[0].id,
            pool,
            io:             req.app.locals.io,
          });
        })
        .catch(e => logger.warn('[VolWeb] case lookup error:', e.message));
    }
  } catch (err) {
    logger.error('Upload error:', err);
    res.status(500).json({ error: 'Erreur upload' });
  }
});

router.put('/:id/highlight', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE evidence SET is_highlighted = NOT is_highlighted, updated_at = NOW() WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:id/hex', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT file_path, name, scan_status, hash_sha256 FROM evidence WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    if (result.rows[0].scan_status === 'quarantined') {
      return res.status(403).json({ error: 'Accès refusé — fichier en quarantaine' });
    }

    const { file_path: filePath, name, hash_sha256: storedHash } = result.rows[0];
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé sur le disque' });
    }

    const offset = parseInt(req.query.offset) || 0;
    const length = Math.min(parseInt(req.query.length) || 512, 4096);

    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buffer, 0, length, offset);
    fs.closeSync(fd);

    const stats = fs.statSync(filePath);

    const integrity = await verifyFileIntegrity(filePath, storedHash);
    if (!integrity.ok) {
      res.setHeader('X-Integrity-Alert', 'true');
    }

    res.json({
      name,
      total_size: stats.size,
      offset,
      length: bytesRead,
      hex: buffer.slice(0, bytesRead).toString('hex'),
      ascii: buffer.slice(0, bytesRead).toString('ascii').replace(/[^\x20-\x7E]/g, '.'),
      integrity_ok: integrity.ok,
      ...(integrity.ok ? {} : { integrity_alert: true, stored_hash: integrity.stored, computed_hash: integrity.computed }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lecture hex' });
  }
});

router.get('/:id/strings', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT file_path, scan_status, hash_sha256 FROM evidence WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    if (result.rows[0].scan_status === 'quarantined') {
      return res.status(403).json({ error: 'Accès refusé — fichier en quarantaine' });
    }

    const { file_path: filePath, hash_sha256: storedHash } = result.rows[0];
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé' });
    }

    const minLength = parseInt(req.query.min_length) || 4;
    const strings = [];
    let current = '';
    let byteOffset = 0;
    let currentOffset = 0;

    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
      stream.on('data', chunk => {
        if (strings.length >= 1000) { stream.destroy(); return; }
        for (let i = 0; i < chunk.length && strings.length < 1000; i++) {
          const byte = chunk[i];
          if (byte >= 0x20 && byte <= 0x7E) {
            if (current.length === 0) currentOffset = byteOffset + i;
            current += String.fromCharCode(byte);
          } else {
            if (current.length >= minLength) {
              strings.push({ offset: currentOffset, value: current, length: current.length });
            }
            current = '';
          }
        }
        byteOffset += chunk.length;
      });
      stream.on('end', () => {
        if (current.length >= minLength) strings.push({ offset: currentOffset, value: current, length: current.length });
        resolve();
      });
      stream.on('error', reject);
      stream.on('close', resolve);
    });

    const integrity = await verifyFileIntegrity(filePath, storedHash);
    if (!integrity.ok) {
      res.setHeader('X-Integrity-Alert', 'true');
    }

    res.json({
      total: strings.length,
      strings,
      integrity_ok: integrity.ok,
      ...(integrity.ok ? {} : { integrity_alert: true, stored_hash: integrity.stored, computed_hash: integrity.computed }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur extraction strings' });
  }
});

router.get('/:id/integrity', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT file_path, name, hash_sha256, scan_status FROM evidence WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    const { file_path: filePath, name, hash_sha256: storedHash } = result.rows[0];

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Fichier non trouvé sur le disque', integrity_ok: false });
    }

    const integrity = await verifyFileIntegrity(filePath, storedHash);

    res.json({
      evidence_id: req.params.id,
      name,
      integrity_ok: integrity.ok,
      stored_hash: integrity.stored,
      computed_hash: integrity.computed,
      ...(integrity.reason ? { reason: integrity.reason } : {}),
    });
  } catch (err) {
    logger.error('Integrity check error:', err);
    res.status(500).json({ error: 'Erreur vérification intégrité' });
  }
});

router.get('/:id/comments', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ec.*, u.full_name as author, u.role as author_role
      FROM evidence_comments ec
      JOIN users u ON ec.user_id = u.id
      WHERE ec.evidence_id = $1
      ORDER BY ec.is_pinned DESC, ec.created_at DESC
    `, [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:id/comments', authenticate, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Contenu requis' });

    const result = await pool.query(
      'INSERT INTO evidence_comments (evidence_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, req.user.id, content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:id', authenticate, async (req, res) => {
  try {
    const row = await pool.query(
      'SELECT file_path, name, case_id FROM evidence WHERE id = $1',
      [req.params.id]
    );
    if (row.rows.length === 0) return res.status(404).json({ error: 'Preuve introuvable' });

    const { file_path, name, case_id } = row.rows[0];

    if (file_path && fs.existsSync(file_path)) {
      const stat = fs.statSync(file_path);
      if (stat.isDirectory()) {
        fs.rmSync(file_path, { recursive: true, force: true });
      } else {
        fs.unlinkSync(file_path);
      }
    }

    await pool.query('DELETE FROM evidence_comments WHERE evidence_id = $1', [req.params.id]);
    await pool.query('DELETE FROM parser_results WHERE evidence_id = $1', [req.params.id]);
    await pool.query('UPDATE timeline_events SET evidence_id = NULL WHERE evidence_id = $1', [req.params.id]);
    await pool.query('DELETE FROM evidence WHERE id = $1', [req.params.id]);

    await auditLog(req.user.id, 'delete_evidence', 'evidence', req.params.id, { name }, req.ip);
    res.json({ success: true });
  } catch (err) {
    logger.error('Delete evidence error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
