const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'forensiclab',
  user: process.env.DB_USER || 'forensiclab',
  password: process.env.DB_PASSWORD,
  max: parseInt(process.env.DB_POOL_MAX) || 30,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

async function testConnection() {
  const client = await pool.connect();
  try {
    await client.query('SELECT NOW()');
  } finally {
    client.release();
  }
}

module.exports = { pool, testConnection };
