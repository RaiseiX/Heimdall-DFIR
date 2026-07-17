// Spins a throwaway postgres:16-alpine (no volumes/networks) for detection-logic
// integration tests, creates a minimal schema, and returns a pg Pool + teardown.
// Skips gracefully when Docker is unavailable so the pure suite still runs in CI.
const { execFileSync, execSync } = require('child_process');
const { Pool } = require('pg');

function dockerAvailable() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}

// Parallel-safe: Jest runs each test file in its own worker, so scope the
// container name + port by JEST_WORKER_ID (stable per worker; '1' outside Jest).
// Without this, two integration suites racing on one shared container name/port
// collide under the default `jest` (parallel) runner.
const WID = process.env.JEST_WORKER_ID || '1';
const NAME = `heimdall-detvec-test-${WID}`;

async function startPg() {
  execSync(`docker rm -f ${NAME} 2>/dev/null || true`);
  const port = 55432 + (Number(WID) - 1);
  execFileSync('docker', ['run', '--rm', '-d', '--name', NAME,
    '-e', 'POSTGRES_PASSWORD=x', '-e', 'POSTGRES_DB=det', '-e', 'POSTGRES_USER=det',
    '-p', `${port}:5432`, 'postgres:16-alpine'], { stdio: 'ignore' });
  // wait for the REAL server (gate on a query; spans the init restart)
  execSync(`for i in $(seq 60); do docker exec ${NAME} psql -U det -d det -c "SELECT 1" >/dev/null 2>&1 && exit 0; sleep 0.5; done; exit 1`);
  const pool = new Pool({ host: '127.0.0.1', port, user: 'det', password: 'x', database: 'det' });
  await pool.query(`
    CREATE TABLE cases (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      created_by uuid,
      investigator_id uuid,
      title text,
      case_number text,
      status text
    );
    CREATE TABLE users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      username text,
      role text,
      full_name text,
      password_hash text
    );
    CREATE TABLE case_sessions (
      id bigserial PRIMARY KEY,
      case_id uuid,
      user_id uuid,
      started_at timestamptz NOT NULL DEFAULT NOW(),
      ended_at timestamptz,
      duration_s integer
    );
    CREATE TABLE parser_results (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      case_id uuid,
      evidence_id uuid,
      parser_name text,
      parser_version text,
      input_file text,
      output_data jsonb NOT NULL DEFAULT '[]',
      record_count integer DEFAULT 0,
      created_by uuid
    );
    CREATE TABLE collection_timeline (
      id bigserial PRIMARY KEY,
      case_id uuid,
      result_id uuid,
      timestamp timestamptz,
      artifact_type varchar(50),
      artifact_name text,
      description text,
      source text,
      host_name text,
      user_name text,
      process_name text,
      mitre_technique_id text,
      mitre_technique_name text,
      mitre_tactic text,
      tool text,
      timestamp_kind text,
      details text,
      "path" text,
      ext text,
      event_id text,
      file_size bigint,
      raw jsonb NOT NULL DEFAULT '{}',
      evidence_id uuid,
      dedupe_hash char(16)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_ct_case_dedupe ON collection_timeline(case_id, dedupe_hash) WHERE dedupe_hash IS NOT NULL;
    CREATE TABLE case_messages (
      id bigserial PRIMARY KEY,
      case_id uuid,
      author_id uuid,
      content text,
      created_at timestamptz NOT NULL DEFAULT NOW(),
      reply_to_id bigint
    );
    CREATE TABLE report_drafts (
      case_id UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
      ydoc BYTEA NOT NULL,
      text_snapshot JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`);
  const stop = async () => { await pool.end().catch(() => {}); execSync(`docker rm -f ${NAME} 2>/dev/null || true`); };
  return { pool, stop };
}

// jest describe that no-ops when Docker is unavailable
const describeIfDocker = dockerAvailable() ? describe : describe.skip;

module.exports = { startPg, dockerAvailable, describeIfDocker };
