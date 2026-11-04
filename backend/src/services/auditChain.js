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

/** First link of the chain. Marks "the chain starts here", not "no predecessor exists". */
const GENESIS_HASH = '0'.repeat(64);

/** Domain-separation label so a derived audit key can never collide with token signing. */
const AUDIT_KEY_INFO = 'heimdall-audit-chain-v1';

const KEY_ID_V1 = 'v1';
const KEY_ID_V2 = 'v2';
const KNOWN_KEY_IDS = new Set([KEY_ID_V1, KEY_ID_V2]);
const ROTATION_ACTION = 'audit_key_rotation';

function assertAuditKeyConfigured(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('JWT_SECRET is required: it verifies the v1 and legacy audit rows');
  }
  const key = typeof env.AUDIT_HMAC_KEY === 'string' ? env.AUDIT_HMAC_KEY.trim() : '';
  const jwtTrimmed = typeof jwtSecret === 'string' ? jwtSecret.trim() : jwtSecret;
  if (!key) {
    throw new Error('AUDIT_HMAC_KEY is required and must not be empty: the audit log cannot be signed without it');
  }
  if (key === jwtTrimmed) {
    throw new Error('AUDIT_HMAC_KEY must differ from JWT_SECRET');
  }
  if (key.startsWith('CHANGEME')) {
    throw new Error('AUDIT_HMAC_KEY is still a CHANGEME placeholder: generate a real secret');
  }
  return key;
}

function v2KeyConfigured() {
  try {
    assertAuditKeyConfigured();
    return true;
  } catch {
    return false;
  }
}

function resolveAuditKeyV1() {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) throw new Error('JWT_SECRET is required to verify v1 audit rows');
  return crypto.createHmac('sha256', jwtSecret).update(AUDIT_KEY_INFO).digest('hex');
}

function resolveAuditKey(keyId = KEY_ID_V2) {
  if (keyId === KEY_ID_V1) return resolveAuditKeyV1();
  if (keyId === KEY_ID_V2) return assertAuditKeyConfigured();
  throw new Error(`Unknown audit key id: ${keyId}`);
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

function rowKeyId(row) {
  return row.key_id || KEY_ID_V1;
}

/** HMAC of one row, bound to its predecessor's HMAC. */
function computeAuditHmacChained(row, prevHash) {
  const { user_id, action, entity_type, entity_id, details, ts } = row;
  const keyId = rowKeyId(row);
  const fields = keyId === KEY_ID_V1
    ? { user_id, action, entity_type, entity_id, details, ts }
    : { user_id, action, entity_type, entity_id, details, ts, key_id: keyId };
  const payload = JSON.stringify(canonicalize(fields));
  return crypto.createHmac('sha256', resolveAuditKey(keyId))
    .update(`${prevHash}\n${payload}`)
    .digest('hex');
}

function rotationCountersignature(lastV1Hmac) {
  return crypto.createHmac('sha256', resolveAuditKeyV1())
    .update(`${ROTATION_ACTION}\n${KEY_ID_V1}->${KEY_ID_V2}\n${lastV1Hmac}`)
    .digest('hex');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function rotationIsValid(row, previous) {
  const d = row.details && typeof row.details === 'object' ? row.details : {};
  return row.action === ROTATION_ACTION
    && d.from === KEY_ID_V1 && d.to === KEY_ID_V2
    && d.last_v1_hmac === previous.hmac
    && safeEqual(d.countersignature, rotationCountersignature(previous.hmac));
}

function createChainWalker(startPrev = GENESIS_HASH) {
  let expectedPrev = startPrev;
  let previous = null;
  let checked = 0;
  let firstSeq = null;
  let lastSeq = null;
  let lastHmac = null;
  let v1Rows = 0;
  let v2Rows = 0;
  const problems = [];

  const flag = (type, seq) => { problems.push({ type, seq }); };

  function feed(r) {
    if (!r.prev_hash || !r.hmac) {
      flag('post_genesis_unchained', r.seq);
      return;
    }
    if (firstSeq === null) firstSeq = Number(r.seq);
    lastSeq = Number(r.seq);
    checked++;

    const keyId = rowKeyId(r);
    if (keyId === KEY_ID_V1) v1Rows++;
    if (keyId === KEY_ID_V2) v2Rows++;
    if (r.prev_hash !== expectedPrev) {
      flag('chain_break', r.seq);
    }
    if (!KNOWN_KEY_IDS.has(keyId)) {
      flag('unknown_key_id', r.seq);
    } else {
      if (computeAuditHmacChained(r, r.prev_hash) !== r.hmac) flag('hmac_mismatch', r.seq);
      const prevKeyId = previous ? rowKeyId(previous) : null;
      if (prevKeyId === KEY_ID_V1 && keyId === KEY_ID_V2) {
        if (!rotationIsValid(r, previous)) flag('rotation_invalid', r.seq);
      } else if (prevKeyId === KEY_ID_V2 && keyId === KEY_ID_V1) {
        flag('rotation_invalid', r.seq);
      } else if (r.action === ROTATION_ACTION) {
        flag('rotation_invalid', r.seq);
      }
    }

    expectedPrev = r.hmac;
    previous = r;
    lastHmac = r.hmac;
  }

  return {
    feed,
    summary: () => ({
      checked, first_seq: firstSeq, last_seq: lastSeq, last_hmac: lastHmac, problems, v1_rows: v1Rows, v2_rows: v2Rows,
    }),
  };
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
 */
function verifyAuditChain(rows, startPrev = GENESIS_HASH) {
  const walker = createChainWalker(startPrev);
  for (const r of rows) walker.feed(r);
  const { checked, problems } = walker.summary();
  if (problems.length) {
    const first = problems[0];
    const reason = first.type === 'post_genesis_unchained' ? 'chain_break' : first.type;
    return { ok: false, reason, breakAtSeq: first.seq };
  }
  return { ok: true, checked };
}

const VERIFY_PAGE_SIZE = 1000;
const MAX_REPORTED_PROBLEMS = 200;

async function verifyAuditLog(db, { pageSize = VERIFY_PAGE_SIZE } = {}) {
  const size = Math.max(1, Math.floor(Number(pageSize)) || VERIFY_PAGE_SIZE);
  const metaRes = await db.query(
    'SELECT genesis_seq::text AS genesis_seq, rotation_seq::text AS rotation_seq FROM audit_chain_meta LIMIT 1');
  const genesisSeq = metaRes.rows[0] ? Number(metaRes.rows[0].genesis_seq) : null;
  const rotationSeq = metaRes.rows[0] && metaRes.rows[0].rotation_seq !== null
    && metaRes.rows[0].rotation_seq !== undefined ? Number(metaRes.rows[0].rotation_seq) : null;
  let anchoredRow = null;

  const walker = createChainWalker(GENESIS_HASH);
  let cursor = genesisSeq === null ? null : genesisSeq - 1;
  let sawGenesisRow = false;

  if (cursor === null) {
    const head = await db.query(
      'SELECT MIN(seq)::text AS seq FROM audit_log WHERE prev_hash IS NOT NULL');
    if (head.rows[0] && head.rows[0].seq !== null) cursor = Number(head.rows[0].seq) - 1;
  }

  if (cursor !== null) {
    for (;;) {
      const page = await db.query(
        `SELECT seq::text AS seq, user_id, action, entity_type, entity_id, details,
                created_at, prev_hash, hmac, key_id
           FROM audit_log WHERE seq > $1 ORDER BY audit_log.seq ASC LIMIT $2`, [cursor, size]);
      if (page.rows.length === 0) break;
      for (const row of page.rows) {
        if (genesisSeq !== null && Number(row.seq) === genesisSeq && row.prev_hash) sawGenesisRow = true;
        if (rotationSeq !== null && Number(row.seq) === rotationSeq) anchoredRow = row;
        walker.feed({
          ...row,
          seq: Number(row.seq),
          details: row.details ?? {},
          ts: new Date(row.created_at).toISOString(),
        });
      }
      cursor = Number(page.rows[page.rows.length - 1].seq);
      if (page.rows.length < size) break;
    }
  }

  const summary = walker.summary();
  const problems = summary.problems.slice();
  if (genesisSeq !== null && !sawGenesisRow) {
    problems.unshift({ type: 'chain_break', seq: genesisSeq });
  }
  if (rotationSeq !== null) {
    const anchorHolds = anchoredRow
      && anchoredRow.action === ROTATION_ACTION
      && anchoredRow.prev_hash
      && rowKeyId(anchoredRow) === KEY_ID_V2;
    if (!anchorHolds) problems.push({ type: 'rotation_missing', seq: rotationSeq });
  } else if (summary.v1_rows > 0 && summary.v2_rows === 0 && v2KeyConfigured()) {
    problems.push({ type: 'rotation_missing', seq: summary.last_seq });
  }

  const counts = {};
  for (const p of problems) counts[p.type] = (counts[p.type] || 0) + 1;

  return {
    ok: problems.length === 0,
    complete: true,
    genesis_seq: genesisSeq,
    checked: summary.checked,
    first_seq: summary.first_seq,
    last_seq: summary.last_seq,
    last_hmac: summary.last_hmac,
    problem_counts: counts,
    problems: problems.slice(0, MAX_REPORTED_PROBLEMS),
    problems_truncated: problems.length > MAX_REPORTED_PROBLEMS,
  };
}

// Advisory-lock key serializing chain appends. Backend and worker are SEPARATE
// processes, so an in-process mutex would not help: two writers would read the
// same tail hash and fork the chain. The lock is transaction-scoped, so it is
// released on COMMIT/ROLLBACK even if the process dies mid-append.
const AUDIT_CHAIN_LOCK = 4805921;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_ACTION_LENGTH = 50;
const MAX_ENTITY_TYPE_LENGTH = 50;

function assertAuditFields({ action, entityType, entityId }) {
  if (typeof action !== 'string' || !action || action.length > MAX_ACTION_LENGTH) {
    throw new Error(`Audit action must be a non-empty string of at most ${MAX_ACTION_LENGTH} characters`);
  }
  if (entityType !== null && entityType !== undefined
    && (typeof entityType !== 'string' || entityType.length > MAX_ENTITY_TYPE_LENGTH)) {
    throw new Error(`Audit entity type must be at most ${MAX_ENTITY_TYPE_LENGTH} characters`);
  }
  if (entityId !== null && entityId !== undefined && !UUID_PATTERN.test(String(entityId))) {
    throw new Error('Audit entity id must be a UUID or null');
  }
}

function isPool(db) {
  return Boolean(db) && typeof db.connect === 'function' && typeof db.release !== 'function';
}

async function writeChainedRow(client, { userId, action, entityType, entityId, details = {}, ipAddress = null }) {
  assertAuditKeyConfigured();
  assertAuditFields({ action, entityType, entityId });
  await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [AUDIT_CHAIN_LOCK]);

  const tailRes = await client.query(
    `SELECT seq::text AS seq, hmac, key_id FROM audit_log
      WHERE prev_hash IS NOT NULL AND hmac IS NOT NULL ORDER BY audit_log.seq DESC LIMIT 1`);
  const tail = tailRes.rows[0] || null;
  let prevHash = tail ? tail.hmac : GENESIS_HASH;

  const insertRow = async (fields, ip, previousHash) => {
    const ts = new Date().toISOString();
    const row = { ...fields, ts, key_id: KEY_ID_V2 };
    const hmac = computeAuditHmacChained(row, previousHash);
    const res = await client.query(
      `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, created_at, hmac, prev_hash, key_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING seq::text AS seq`,
      [row.user_id, row.action, row.entity_type, row.entity_id, JSON.stringify(row.details), ip, ts, hmac,
        previousHash, KEY_ID_V2]);
    return { hmac, seq: res.rows[0].seq };
  };

  let rotationSeq = null;
  if (tail && (tail.key_id || KEY_ID_V1) === KEY_ID_V1) {
    const rotation = await insertRow({
      user_id: null,
      action: ROTATION_ACTION,
      entity_type: 'system',
      entity_id: null,
      details: {
        from: KEY_ID_V1,
        to: KEY_ID_V2,
        last_v1_seq: Number(tail.seq),
        last_v1_hmac: tail.hmac,
        countersignature: rotationCountersignature(tail.hmac),
      },
    }, null, prevHash);
    prevHash = rotation.hmac;
    rotationSeq = rotation.seq;
  }

  const written = await insertRow(
    { user_id: userId, action, entity_type: entityType, entity_id: entityId, details }, ipAddress, prevHash);

  if (!tail) {
    await client.query(
      `INSERT INTO audit_chain_meta (singleton, genesis_seq) VALUES (TRUE, $1::bigint)
       ON CONFLICT (singleton) DO NOTHING`, [written.seq]);
  }
  if (rotationSeq !== null) {
    const anchored = await client.query(
      'UPDATE audit_chain_meta SET rotation_seq = $1::bigint WHERE singleton', [rotationSeq]);
    if (!anchored.rowCount) {
      await client.query(
        `INSERT INTO audit_chain_meta (singleton, genesis_seq, rotation_seq)
         SELECT TRUE, MIN(seq), $1::bigint FROM audit_log WHERE prev_hash IS NOT NULL
         ON CONFLICT (singleton) DO UPDATE SET rotation_seq = EXCLUDED.rotation_seq`, [rotationSeq]);
    }
  }

  return { hmac: written.hmac, prevHash };
}

async function appendAuditRowInTx(client, fields) {
  if (!client || typeof client.query !== 'function' || isPool(client)) {
    throw new Error('appendAuditRowInTx requires a client inside an open transaction');
  }
  return writeChainedRow(client, fields);
}

async function appendAuditRow(db, fields) {
  if (!isPool(db)) return appendAuditRowInTx(db, fields);
  assertAuditKeyConfigured();
  assertAuditFields(fields);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const result = await writeChainedRow(client, fields);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  GENESIS_HASH,
  KEY_ID_V1,
  KEY_ID_V2,
  ROTATION_ACTION,
  assertAuditKeyConfigured,
  resolveAuditKey,
  rotationCountersignature,
  verifyAuditLog,
  canonicalize,
  computeAuditHmacChained,
  verifyAuditChain,
  appendAuditRow,
  appendAuditRowInTx,
  isPool,
};
