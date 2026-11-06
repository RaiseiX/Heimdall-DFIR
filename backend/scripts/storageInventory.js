const { listStorageEntries, classifyEntries, collectRefs } = require('../src/services/storageInventory');

const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_FINDINGS = 2;
const EXIT_USAGE = 64;

const CLEAN_STATUSES = new Set(['evidence', 'import_dir']);

async function inventory(db, out, roots) {
  const refs = await collectRefs(db);
  const listed = await listStorageEntries(roots);
  const { entries, missing } = classifyEntries(listed, refs);
  const counts = {};
  const bytes = {};
  for (const entry of entries) {
    counts[entry.status] = (counts[entry.status] || 0) + 1;
    bytes[entry.status] = (bytes[entry.status] || 0) + entry.size;
  }
  const findings = missing.length > 0 || entries.some((entry) => !CLEAN_STATUSES.has(entry.status));
  out(JSON.stringify({
    status: findings ? 'findings' : 'ok',
    counts,
    bytes,
    entries,
    missing,
  }));
  return findings ? EXIT_FINDINGS : EXIT_OK;
}

async function main(argv, { db, out, roots }) {
  try {
    if (argv.length === 1 && argv[0] === 'inventory') return await inventory(db, out, roots);
    out(JSON.stringify({ status: 'usage' }));
    return EXIT_USAGE;
  } catch (err) {
    out(JSON.stringify({ status: 'error', message: err.message }));
    return EXIT_ERROR;
  }
}

if (require.main === module) {
  const { pool } = require('../src/config/database');
  const roots = {
    collectionsRoot: process.env.COLLECTIONS_DIR || '/app/collections',
    uploadRoot: process.env.UPLOAD_DIR || '/app/uploads',
  };
  main(process.argv.slice(2), { db: pool, roots, out: (l) => process.stdout.write(`${l}\n`) })
    .then(async (code) => {
      await pool.end().catch(() => {});
      process.exit(code);
    });
}

module.exports = { main };
