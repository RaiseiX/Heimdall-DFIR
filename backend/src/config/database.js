const { Pool } = require('pg');

// Postgres error codes we need to distinguish by name rather than by message.
const QUERY_CANCELED = '57014';    // statement_timeout fired
const LOCK_NOT_AVAILABLE = '55P03'; // lock_timeout fired

const READ_STATEMENT_TIMEOUT_MS = parseInt(process.env.DB_READ_STATEMENT_TIMEOUT_MS) || 60000;

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'forensiclab',
    user: process.env.DB_USER || 'forensiclab',
    password: process.env.DB_PASSWORD,
  };
}

// Write pool: deliberately unbounded. Ingestion batches, UNNEST inserts and the
// threat engine legitimately run for minutes; bounding them would truncate
// collections mid-import.
const pool = new Pool({
  ...connectionConfig(),
  max: parseInt(process.env.DB_POOL_MAX) || 30,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

// Read pool: every connection is born with a statement_timeout, applied through
// the libpq `options` startup parameter so no per-query SET is needed. A UI read
// that outlives the bound is useless anyway, and an unbounded one holds ACCESS
// SHARE — which is what let a 15h SELECT queue the startup ALTER TABLE behind it
// and, transitively, every INSERT behind that.
function createReadPool(overrides = {}) {
  const { statementTimeoutMs = READ_STATEMENT_TIMEOUT_MS, ...rest } = overrides;
  return new Pool({
    ...connectionConfig(),
    max: parseInt(process.env.DB_READ_POOL_MAX) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
    options: `-c statement_timeout=${statementTimeoutMs}`,
    ...rest,
  });
}

const readPool = createReadPool();

// Routes must map this to an explicit 504. Returning [] instead would tell the
// analyst "no network traffic in this collection" when the truth is "the query
// was cancelled".
function isStatementTimeout(err) {
  return Boolean(err) && err.code === QUERY_CANCELED;
}

function isLockTimeout(err) {
  return Boolean(err) && err.code === LOCK_NOT_AVAILABLE;
}

async function testConnection() {
  const client = await pool.connect();
  try {
    await client.query('SELECT NOW()');
  } finally {
    client.release();
  }
}

module.exports = {
  pool, readPool, createReadPool, testConnection,
  isStatementTimeout, isLockTimeout,
  QUERY_CANCELED, LOCK_NOT_AVAILABLE,
};
