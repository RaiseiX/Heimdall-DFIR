const { appendAuditRow } = require('../src/services/auditChain');
const { verifyEvidence, isProblem } = require('../src/services/sourceArchive');

const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_PROBLEMS = 2;
const EXIT_USAGE = 64;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLUMNS = 'id, case_id, evidence_type, file_path, hash_sha256, additional_files';

function parseVerify(args) {
  const opts = { record: false, caseId: null, evidenceId: null };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--record') { opts.record = true; continue; }
    if (arg !== '--case' && arg !== '--evidence') return null;
    const value = args[i + 1];
    if (!UUID_RE.test(value || '')) return null;
    if (arg === '--case') opts.caseId = value; else opts.evidenceId = value;
    i += 1;
  }
  if (opts.caseId && opts.evidenceId) return null;
  return opts;
}

function selectRows(db, opts) {
  if (opts.caseId) return db.query(`SELECT ${COLUMNS} FROM evidence WHERE case_id = $1 ORDER BY created_at, id`, [opts.caseId]);
  if (opts.evidenceId) return db.query(`SELECT ${COLUMNS} FROM evidence WHERE id = $1`, [opts.evidenceId]);
  return db.query(`SELECT ${COLUMNS} FROM evidence ORDER BY created_at, id`);
}

async function verify(db, out, racines, args) {
  const opts = parseVerify(args);
  if (!opts) {
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  }
  const { rows } = await selectRows(db, opts);
  const results = [];
  for (const row of rows) results.push(await verifyEvidence(row, { racines }));
  const counts = {};
  for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
  let recorded;
  if (opts.record) {
    recorded = 0;
    for (const r of results) {
      await appendAuditRow(db, {
        userId: null,
        action: 'evidence_integrity_check',
        entityType: 'evidence',
        entityId: r.evidence_id,
        details: {
          case_id: r.case_id, status: r.status, expected_sha256: r.expected_sha256, computed_sha256: r.computed_sha256, target: r.target,
        },
      }).catch((err) => { throw Object.assign(err, { recorded }); });
      recorded += 1;
    }
  }
  const problems = results.some((r) => isProblem(r.status));
  out(JSON.stringify({
    status: problems ? 'problems' : 'ok',
    checked: results.length,
    counts,
    ...(recorded === undefined ? {} : { recorded }),
    results,
  }));
  return problems ? EXIT_PROBLEMS : EXIT_OK;
}

async function main(argv, { db, out, racines }) {
  const [command, ...rest] = argv;
  try {
    if (command === 'verify') return await verify(db, out, racines, rest);
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  } catch (err) {
    out(JSON.stringify({ status: 'error', message: err.message, ...(err.recorded === undefined ? {} : { recorded: err.recorded }) }));
    return EXIT_ERROR;
  }
}

if (require.main === module) {
  const { pool } = require('../src/config/database');
  const { racinesDeStockage } = require('../src/services/storagePathGuard');
  main(process.argv.slice(2), { db: pool, racines: racinesDeStockage(), out: (l) => process.stdout.write(`${l}\n`) })
    .then(async (code) => {
      await pool.end().catch(() => {});
      process.exit(code);
    });
}

module.exports = { main };
