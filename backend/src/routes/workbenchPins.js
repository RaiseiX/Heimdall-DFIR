// Workbench Evidence Bridge — server-side persistence + tamper-evident chain-of-custody ledger.
// Every mutation (pin / unpin / update / clear) appends one row to `workbench_evidence_audit`
// whose `content_hash` = sha256(prev_hash || action || canonical_payload_json), forming a
// verifiable hash chain per case for defensibility.

const { Router } = require('express');
const crypto = require('crypto');
const logger = require('../config/logger').default;
const { authenticate } = require('../middleware/auth');

const router = Router();

const SELECT_COLS = `
  pin_id, case_id, collection_timeline_id, dedupe_hash, pinned_at, pinned_by,
  timestamp, artifact_type, tool, source, description, event_id,
  host_name, user_name, mitre_technique_id, tags, note, color, status, updated_at
`;

// Deterministic JSON encoder for hash-chain integrity: sorts object keys recursively.
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}

async function appendAudit(client, { caseId, pinId, actorId, action, payload }) {
  const { rows: prev } = await client.query(
    `SELECT content_hash FROM workbench_evidence_audit
     WHERE case_id = $1 ORDER BY seq DESC LIMIT 1`,
    [caseId]
  );
  const prevHash = prev[0]?.content_hash || null;
  const payloadCanon = canonicalJson(payload);
  const content = (prevHash || '') + '|' + action + '|' + payloadCanon;
  const contentHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  await client.query(
    `INSERT INTO workbench_evidence_audit (case_id, pin_id, actor_id, action, payload, prev_hash, content_hash)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
    [caseId, pinId, actorId, action, payloadCanon, prevHash, contentHash]
  );
  return contentHash;
}

// List all pins for a case
router.get('/:caseId', authenticate, async (req, res) => {
  const { pool } = req.app.locals;
  try {
    const { rows } = await pool.query(
      `SELECT ${SELECT_COLS} FROM workbench_evidence_pins
       WHERE case_id = $1 ORDER BY pinned_at DESC`,
      [req.params.caseId]
    );
    res.json({ pins: rows });
  } catch (err) {
    logger.error('[wb-pins] GET:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Create a pin
router.post('/:caseId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId } = req.params;
  const b = req.body || {};
  if (!b.pin_id) return res.status(400).json({ error: 'pin_id required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO workbench_evidence_pins
         (pin_id, case_id, collection_timeline_id, dedupe_hash, pinned_at, pinned_by,
          timestamp, artifact_type, tool, source, description, event_id,
          host_name, user_name, mitre_technique_id, tags, note, color, status)
       VALUES ($1,$2,$3,$4, COALESCE($5::timestamptz, now()), $6,
               $7,$8,$9,$10,$11,$12,
               $13,$14,$15, COALESCE($16, ARRAY[]::TEXT[]), COALESCE($17, ''), $18, COALESCE($19, 'triage'))
       ON CONFLICT (pin_id) DO NOTHING
       RETURNING ${SELECT_COLS}`,
      [b.pin_id, caseId, b.collection_timeline_id ?? null, b.dedupe_hash ?? null, b.pinned_at ?? null, req.user.id,
       b.timestamp ?? null, b.artifact_type ?? null, b.tool ?? null, b.source ?? null, b.description ?? null, b.event_id ?? null,
       b.host_name ?? null, b.user_name ?? null, b.mitre_technique_id ?? null, b.tags ?? null, b.note ?? null, b.color ?? null, b.status ?? null]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'pin already exists' });
    }
    await appendAudit(client, { caseId, pinId: b.pin_id, actorId: req.user.id, action: 'pin', payload: rows[0] });
    await client.query('COMMIT');
    if (io) io.to(`case:${caseId}`).emit('workbench:pin:added', rows[0]);
    res.status(201).json({ pin: rows[0] });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    logger.error('[wb-pins] POST:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Patch (update status / note / tags / color)
router.patch('/:caseId/:pinId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId, pinId } = req.params;
  const b = req.body || {};
  const allowed = ['note', 'status', 'tags', 'color'];
  const sets = [];
  const vals = [];
  for (const k of allowed) {
    if (Object.prototype.hasOwnProperty.call(b, k)) {
      vals.push(b[k]);
      sets.push(`${k} = $${vals.length}`);
    }
  }
  if (!sets.length) return res.status(400).json({ error: 'no mutable fields supplied' });
  sets.push(`updated_at = now()`);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    vals.push(pinId); vals.push(caseId);
    const { rows } = await client.query(
      `UPDATE workbench_evidence_pins SET ${sets.join(', ')}
       WHERE pin_id = $${vals.length - 1} AND case_id = $${vals.length}
       RETURNING ${SELECT_COLS}`,
      vals
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'pin not found' });
    }
    await appendAudit(client, { caseId, pinId, actorId: req.user.id, action: 'update', payload: b });
    await client.query('COMMIT');
    if (io) io.to(`case:${caseId}`).emit('workbench:pin:updated', rows[0]);
    res.json({ pin: rows[0] });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    logger.error('[wb-pins] PATCH:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Unpin
router.delete('/:caseId/:pinId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId, pinId } = req.params;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `DELETE FROM workbench_evidence_pins WHERE pin_id = $1 AND case_id = $2 RETURNING pin_id`,
      [pinId, caseId]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'pin not found' });
    }
    await appendAudit(client, { caseId, pinId, actorId: req.user.id, action: 'unpin', payload: { pin_id: pinId } });
    await client.query('COMMIT');
    if (io) io.to(`case:${caseId}`).emit('workbench:pin:removed', { pin_id: pinId });
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    logger.error('[wb-pins] DELETE:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Clear all pins for a case
router.delete('/:caseId', authenticate, async (req, res) => {
  const { pool, io } = req.app.locals;
  const { caseId } = req.params;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `DELETE FROM workbench_evidence_pins WHERE case_id = $1 RETURNING pin_id`,
      [caseId]
    );
    await appendAudit(client, { caseId, pinId: '00000000-0000-0000-0000-000000000000', actorId: req.user.id, action: 'clear', payload: { removed: rows.length } });
    await client.query('COMMIT');
    if (io) io.to(`case:${caseId}`).emit('workbench:pin:cleared', { case_id: caseId, removed: rows.length });
    res.json({ ok: true, removed: rows.length });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    logger.error('[wb-pins] CLEAR:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Audit / chain-of-custody ledger — returns the full chain + verification status.
router.get('/:caseId/audit', authenticate, async (req, res) => {
  const { pool } = req.app.locals;
  const { caseId } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT a.seq, a.case_id, a.pin_id, a.actor_id, u.username AS actor_name,
              a.action, a.payload, a.prev_hash, a.content_hash, a.created_at
       FROM workbench_evidence_audit a
       LEFT JOIN users u ON u.id = a.actor_id
       WHERE a.case_id = $1
       ORDER BY a.seq ASC`,
      [caseId]
    );

    // Verify each link: recompute sha256(prev_hash || action || canonical(payload)).
    let verified = true;
    let brokenAt = null;
    let prev = null;
    for (const r of rows) {
      const payloadCanon = typeof r.payload === 'string' ? r.payload : canonicalJson(r.payload);
      const content = (prev || '') + '|' + r.action + '|' + payloadCanon;
      const expect = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
      if (expect !== r.content_hash || (prev && r.prev_hash !== prev)) {
        verified = false;
        brokenAt = r.seq;
        break;
      }
      prev = r.content_hash;
    }

    res.json({ entries: rows, verified, broken_at: brokenAt, count: rows.length });
  } catch (err) {
    logger.error('[wb-pins] AUDIT:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
