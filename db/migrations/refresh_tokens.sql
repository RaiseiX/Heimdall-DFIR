-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.15 — Refresh Tokens (JWT rotation + logout)   ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.15.sql

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 hex of the raw refresh token
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_user     ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires  ON refresh_tokens(expires_at) WHERE revoked = FALSE;

-- Auto-purge expired tokens (kept for audit; only non-revoked ones matter)
-- A pg_cron job or nightly cleanup via the API can remove rows older than 30 days.
