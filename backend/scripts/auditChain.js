const { verifyAuditLog, appendAuditRow } = require('../src/services/auditChain');

const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_PROBLEMS = 2;
const EXIT_UNAVAILABLE = 3;
const EXIT_USAGE = 64;

const COMMIT_RE = /^(?:[0-9a-f]{7,40}|unknown)$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const BACKUP_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const OPERATOR_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const DIRTY_VALUES = { true: true, false: false };

function parseFlags(args) {
  const flags = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    const value = args[i + 1];
    if (!key || !key.startsWith('--') || value === undefined) return null;
    flags[key.slice(2)] = value;
  }
  return flags;
}

function recordDetails(args) {
  const flags = parseFlags(args);
  if (!flags) return null;
  const allowed = new Set(['from', 'to', 'backup', 'backup-sha256', 'anchor-before', 'operator', 'dirty']);
  if (Object.keys(flags).some((k) => !allowed.has(k))) return null;
  const { from, to, backup } = flags;
  const sha = flags['backup-sha256'];
  const anchor = flags['anchor-before'] ?? null;
  if (!COMMIT_RE.test(from || '') || !COMMIT_RE.test(to || '')) return null;
  if (!BACKUP_NAME_RE.test(backup || '') || backup.includes('..')) return null;
  if (!HEX64_RE.test(sha || '')) return null;
  if (anchor !== null && !HEX64_RE.test(anchor)) return null;
  const operator = flags.operator ?? null;
  if (operator !== null && !OPERATOR_RE.test(operator)) return null;
  if (flags.dirty !== undefined && !Object.hasOwn(DIRTY_VALUES, flags.dirty)) return null;
  const dirty = flags.dirty === undefined ? null : DIRTY_VALUES[flags.dirty];
  return {
    from_commit: from, to_commit: to, backup_file: backup, backup_sha256: sha, anchor_before: anchor, operator, dirty,
  };
}

async function chainSchemaPresent(db) {
  const res = await db.query("SELECT to_regclass('public.audit_chain_meta') IS NOT NULL AS present");
  return Boolean(res.rows[0] && res.rows[0].present);
}

function verifyAnchor(args) {
  if (args.length === 0) return { anchor: null };
  const flags = parseFlags(args);
  if (!flags || Object.keys(flags).some((k) => k !== 'anchor') || !HEX64_RE.test(flags.anchor)) return null;
  return { anchor: flags.anchor };
}

async function verify(db, out, args) {
  const parsed = verifyAnchor(args);
  if (!parsed) {
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  }
  if (!(await chainSchemaPresent(db))) {
    out(JSON.stringify({ status: 'unavailable' }));
    return EXIT_UNAVAILABLE;
  }
  const r = await verifyAuditLog(db);
  const counts = { ...r.problem_counts };
  let anchorFound;
  if (parsed.anchor) {
    const found = await db.query(
      'SELECT 1 AS found FROM audit_log WHERE hmac = $1 AND prev_hash IS NOT NULL LIMIT 1', [parsed.anchor]);
    anchorFound = found.rows.length > 0;
    if (!anchorFound) counts.anchor_missing = 1;
  }
  const ok = r.ok && anchorFound !== false;
  out(JSON.stringify({
    status: ok ? 'ok' : 'problems',
    checked: r.checked,
    last_seq: r.last_seq,
    last_hmac: r.last_hmac,
    problem_counts: counts,
    ...(anchorFound === undefined ? {} : { anchor_found: anchorFound }),
  }));
  return ok ? EXIT_OK : EXIT_PROBLEMS;
}

async function record(db, out, args) {
  const details = recordDetails(args);
  if (!details) {
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  }
  const written = await appendAuditRow(db, {
    userId: null,
    action: 'platform_update',
    entityType: 'system',
    entityId: null,
    details,
  });
  out(JSON.stringify({ status: 'recorded', hmac: written.hmac }));
  return EXIT_OK;
}

async function main(argv, { db, out }) {
  const [command, ...rest] = argv;
  try {
    if (command === 'verify') return await verify(db, out, rest);
    if (command === 'record') return await record(db, out, rest);
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  } catch (err) {
    out(JSON.stringify({ status: 'error', message: err.message }));
    return EXIT_ERROR;
  }
}

if (require.main === module) {
  const { pool } = require('../src/config/database');
  main(process.argv.slice(2), { db: pool, out: (l) => process.stdout.write(`${l}\n`) })
    .then(async (code) => {
      await pool.end().catch(() => {});
      process.exit(code);
    });
}

module.exports = { main };
