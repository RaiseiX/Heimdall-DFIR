-- ─────────────────────────────────────────────────────────────────────────────
-- migrate_v2.19.sql — Chat v2 : réactions persistées, réponses, épinglage
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

-- 1. Support des réponses (thread léger)
ALTER TABLE case_messages
  ADD COLUMN IF NOT EXISTS reply_to_id UUID REFERENCES case_messages(id) ON DELETE SET NULL;

-- 2. Épinglage de messages
ALTER TABLE case_messages
  ADD COLUMN IF NOT EXISTS pinned     BOOLEAN      NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS pinned_by  UUID         REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS pinned_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_messages_pinned ON case_messages(case_id, pinned) WHERE pinned = TRUE;

-- 3. Réactions emoji persistées (une entrée par utilisateur × emoji × message)
CREATE TABLE IF NOT EXISTS case_message_reactions (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID        NOT NULL REFERENCES case_messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) <= 10),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_reactions_message ON case_message_reactions(message_id);

COMMIT;
