-- ╔══════════════════════════════════════════════════════════════╗
-- ║  AI Copilot — Contexte isolé par case                       ║
-- ║  Migration : 20260322120000                                  ║
-- ╚══════════════════════════════════════════════════════════════╝

-- Historique des conversations IA, cloisonné par case
CREATE TABLE IF NOT EXISTS ai_conversations (
  id          BIGSERIAL PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id),
  role        VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant')),
  content     TEXT NOT NULL,
  tokens_used INTEGER,
  model       VARCHAR(100),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  metadata    JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ai_conv_case ON ai_conversations(case_id, created_at ASC);

-- Contexte investigateur manuel, un seul enregistrement actif par case
-- Partagé entre tous les analystes du cas, persisté en DB
CREATE TABLE IF NOT EXISTS ai_investigator_context (
  id              BIGSERIAL PRIMARY KEY,
  case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  free_text       TEXT,
  updated_by      UUID REFERENCES users(id),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (case_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_ctx_case ON ai_investigator_context(case_id);
