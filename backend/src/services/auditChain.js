// Audit-log tamper evidence.
//
// A per-row HMAC proves a row was not EDITED. It cannot prove the log is
// COMPLETE: anyone with DB write access can DELETE or TRUNCATE rows and every
// surviving HMAC still verifies. A hash chain closes that hole — each row binds
// its predecessor's HMAC, so removing a row breaks the link of its successor.
//
// Rows written before this scheme have prev_hash IS NULL and are verified under
// the legacy per-row scheme in middleware/auth.js. We deliberately do NOT
// back-fill a chain over them: a chain computed after the fact proves nothing
// (whoever could tamper could also re-chain) and would fake continuity.
const crypto = require('crypto');
const logger = require('../config/logger').default;

/** First link of the chain. Marks "the chain starts here", not "no predecessor exists". */
const GENESIS_HASH = '0'.repeat(64);

/** Domain-separation label so a derived audit key can never collide with token signing. */
const AUDIT_KEY_INFO = 'heimdall-audit-chain-v1';

let warned = false;

/**
 * Key used to HMAC audit rows.
 *
 * DESIGN DECISION — key separation vs. upgrade safety:
 *   Ideal:    an independent AUDIT_HMAC_KEY. Leaking JWT_SECRET then does NOT
 *             let an attacker forge audit entries.
 *   Fallback: derive from JWT_SECRET. Keeps existing deployments booting after
 *             an upgrade, and still stops a JWT-signing oracle from directly
 *             producing audit HMACs — but does not survive a JWT_SECRET leak.
 *
 * The fallback is the default on purpose: this project has already been bitten
 * by a worker crash-looping at boot over a missing JWT_SECRET. Hard-failing here
 * would break audit logging — and therefore the whole app — on upgrade.
 * Set AUDIT_HMAC_KEY in production to get real separation.
 */
function resolveAuditKey() {
  const explicit = process.env.AUDIT_HMAC_KEY;
  if (explicit) return explicit;

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) throw new Error('AUDIT_HMAC_KEY or JWT_SECRET is required to sign the audit log');

  if (!warned) {
    warned = true;
    logger.warn(
      'AUDIT_HMAC_KEY is not set — deriving the audit key from JWT_SECRET. ' +
      'Set AUDIT_HMAC_KEY to a distinct secret so a JWT_SECRET leak cannot forge audit entries.'
    );
  }
  return crypto.createHmac('sha256', jwtSecret).update(AUDIT_KEY_INFO).digest('hex');
}

/**
 * Recursively sort object keys so the HMAC payload survives JSONB key reordering
 * (jsonb does not preserve insertion order; canonical form makes verification
 * deterministic).
 */
function canonicalize(v) {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = canonicalize(v[k]); return acc; }, {});
  }
  return v;
}

/** HMAC of one row, bound to its predecessor's HMAC. */
function computeAuditHmacChained({ user_id, action, entity_type, entity_id, details, ts }, prevHash) {
  const payload = JSON.stringify(canonicalize({ user_id, action, entity_type, entity_id, details, ts }));
  return crypto.createHmac('sha256', resolveAuditKey())
    .update(`${prevHash}\n${payload}`)
    .digest('hex');
}

/**
 * Walk a contiguous, seq-ascending slice of chained rows.
 *
 * Note on gaps: a BIGSERIAL value is consumed even by a rolled-back INSERT, so a
 * hole in `seq` is NOT evidence of deletion and must not be reported as tampering.
 * Only a broken prev_hash link is.
 *
 * @param {object[]} rows      contiguous slice, ascending by seq
 * @param {string}   startPrev hmac expected before the first row. Defaults to
 *   genesis; pass the preceding row's hmac to verify a WINDOW of a long chain
 *   without reporting a false break on its first row.
 * @returns {{ok: true, checked: number} | {ok: false, reason: 'chain_break'|'hmac_mismatch', breakAtSeq: number}}
 */
function verifyAuditChain(rows, startPrev = GENESIS_HASH) {
  let expectedPrev = startPrev;
  for (const r of rows) {
    if (r.prev_hash !== expectedPrev) {
      return { ok: false, reason: 'chain_break', breakAtSeq: r.seq };
    }
    if (computeAuditHmacChained(r, r.prev_hash) !== r.hmac) {
      return { ok: false, reason: 'hmac_mismatch', breakAtSeq: r.seq };
    }
    expectedPrev = r.hmac;
  }
  return { ok: true, checked: rows.length };
}

// Advisory-lock key serializing chain appends. Backend and worker are SEPARATE
// processes, so an in-process mutex would not help: two writers would read the
// same tail hash and fork the chain. The lock is transaction-scoped, so it is
// released on COMMIT/ROLLBACK even if the process dies mid-append.
const AUDIT_CHAIN_LOCK = 4805921;

/**
 * Append one row to the chain, atomically.
 *
 * read-tail → compute → insert must not interleave with another writer, hence
 * the advisory lock. Returns the row's hmac and the predecessor it bound to.
 */
async function appendAuditRow(pool, { userId, action, entityType, entityId, details = {}, ipAddress = null }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [AUDIT_CHAIN_LOCK]);

    const prev = await client.query(
      `SELECT hmac FROM audit_log WHERE prev_hash IS NOT NULL ORDER BY seq DESC LIMIT 1`);
    const prevHash = prev.rows[0]?.hmac || GENESIS_HASH;

    const ts = new Date().toISOString();
    const hmac = computeAuditHmacChained(
      { user_id: userId, action, entity_type: entityType, entity_id: entityId, details, ts }, prevHash);

    await client.query(
      `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, created_at, hmac, prev_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [userId, action, entityType, entityId, JSON.stringify(details), ipAddress, ts, hmac, prevHash]);

    await client.query('COMMIT');
    return { hmac, prevHash };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  GENESIS_HASH,
  resolveAuditKey,
  canonicalize,
  computeAuditHmacChained,
  verifyAuditChain,
  appendAuditRow,
};
