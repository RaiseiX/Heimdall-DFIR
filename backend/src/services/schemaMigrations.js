// Lock-safe runner for startup DDL.
//
// Plain `ALTER TABLE` waits indefinitely for its ACCESS EXCLUSIVE lock, and a
// *queued* ACCESS EXCLUSIVE blocks every request that arrives after it — even
// INSERTs that would never have conflicted with the query actually holding the
// table. One long SELECT is therefore enough to freeze the whole ingestion path
// with no CPU load and no log line. `lock_timeout` breaks that queue.
//
// The runner stays free of any dependency on the schema-degradation registry: it
// applies DDL or throws, and the caller decides what a failure means.
const { LOCK_NOT_AVAILABLE } = require('../config/database');

const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function statementSql(statement) {
  return typeof statement === 'string' ? statement : statement.sql;
}

// A CREATE INDEX CONCURRENTLY that fails leaves the index behind marked INVALID.
// `IF NOT EXISTS` then sees the name as taken and skips the rebuild forever, so
// every restart quietly inherits a dead index. Drop it before retrying.
//
// But indisvalid=false has TWO meanings: "a past build failed" and "a build is
// running right now and has not flipped the flag yet". Dropping in the second
// case blocks on the builder's ShareUpdateExclusiveLock until lock_timeout kills
// it — and a queued ACCESS EXCLUSIVE blocks every request arriving behind it,
// which is the freeze this whole module exists to prevent. Check the progress
// view first and refuse rather than fight a live build.
async function dropInvalidIndex(client, indexName) {
  if (!SAFE_IDENTIFIER.test(indexName)) {
    throw new Error(`[migration] unsafe index identifier: ${indexName}`);
  }

  const { rows: building } = await client.query(
    `SELECT 1 FROM pg_stat_progress_create_index p
       JOIN pg_class c ON c.oid = p.index_relid
      WHERE c.relname = $1`, [indexName]);
  if (building.length) {
    throw new Error(
      `[migration] ${indexName} is currently being built by another session — ` +
      `wait for that build to finish, then re-run. Refusing to drop a live build.`);
  }

  const { rows } = await client.query(
    `SELECT 1 FROM pg_class c
       JOIN pg_index i ON i.indexrelid = c.oid
      WHERE c.relname = $1 AND NOT i.indisvalid`, [indexName]);
  if (rows.length) {
    await client.query(`DROP INDEX CONCURRENTLY IF EXISTS ${indexName}`);
  }
}

// `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` acquires ACCESS EXCLUSIVE *before*
// discovering there is nothing to add. On an already-migrated database that turns
// every restart into a lock fight it does not need to win: observed in production,
// a restart during an 11-minute read disabled ingestion for a batch that was a
// pure no-op. Probing the catalog first costs one cheap query and takes no lock
// on the table at all.
async function alreadyPresent(pool, { table, columns }) {
  if (!table || !columns?.length) return false;
  const { rows } = await pool.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = $1 AND column_name = ANY($2::text[])`,
    [table, columns]);
  return rows.length === columns.length;
}

async function runGuardedMigrations(pool, {
  name,
  statements,
  lockTimeoutMs = 3000,
  statementTimeoutMs = 300000,
  maxAttempts = 5,
  backoffMs = 500,
  sleep = defaultSleep,
  logger = null,
  /** { table, columns } — when every column is already there, skip the batch
   *  entirely rather than take a lock to discover it has nothing to do. */
  skipIfPresent = null,
} = {}) {
  const log = logger || require('../config/logger').default;

  if (skipIfPresent && await alreadyPresent(pool, skipIfPresent)) {
    log.info(`[migration] ${name} already current — nothing to apply`);
    return;
  }

  const client = await pool.connect();

  try {
    await client.query(`SET lock_timeout = ${Number(lockTimeoutMs)}`);
    await client.query(`SET statement_timeout = ${Number(statementTimeoutMs)}`);

    for (const statement of statements) {
      const sql = statementSql(statement);
      const indexName = typeof statement === 'object' ? statement.indexName : null;

      for (let attempt = 1; ; attempt += 1) {
        try {
          if (indexName) await dropInvalidIndex(client, indexName);
          await client.query(sql);
          break;
        } catch (err) {
          // Anything other than lock contention is a real defect — surface it
          // immediately instead of burning retries on a syntax or type error.
          if (err.code !== LOCK_NOT_AVAILABLE || attempt >= maxAttempts) {
            const wrapped = new Error(
              `[migration] ${name} failed after ${attempt} attempt(s): ${err.message} — ${sql.trim().split('\n')[0]}`);
            wrapped.code = err.code;
            wrapped.cause = err;
            wrapped.migration = name;
            throw wrapped;
          }
          log.warn(`[migration] ${name}: lock unavailable, retry ${attempt}/${maxAttempts - 1}`);
          await sleep(backoffMs * 2 ** (attempt - 1));
        }
      }
    }
    log.info(`[migration] ${name} OK`);
  } finally {
    client.release();
  }
}

module.exports = { runGuardedMigrations };
