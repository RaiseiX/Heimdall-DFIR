-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.14 — Case Chat Messages + Notifications       ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.14.sql

CREATE TABLE IF NOT EXISTS case_messages (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id  UUID        NOT NULL REFERENCES users(id),
  content    TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_case ON case_messages(case_id, created_at);

CREATE TABLE IF NOT EXISTS case_notifications (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id    UUID        REFERENCES cases(id) ON DELETE CASCADE,
  type       VARCHAR(50) NOT NULL DEFAULT 'info',
  payload    JSONB       NOT NULL DEFAULT '{}',
  read       BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notif_user ON case_notifications(user_id, read, created_at DESC);
