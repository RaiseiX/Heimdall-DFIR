-- DFIQ question-sets: catalog (seeded + custom) + per-case instance/answers/evidence.
CREATE TABLE IF NOT EXISTS dfiq_scenarios (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dfiq_id     TEXT UNIQUE,                      -- upstream id (S1001…); NULL for custom
  title       TEXT NOT NULL,
  description TEXT,
  tags        TEXT[] NOT NULL DEFAULT '{}',
  is_custom   BOOLEAN NOT NULL DEFAULT FALSE,
  source      TEXT NOT NULL DEFAULT 'dfiq',
  raw         JSONB NOT NULL DEFAULT '{}',
  created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT dfiq_scenarios_custom_no_dfiqid CHECK (NOT is_custom OR dfiq_id IS NULL)
);
CREATE TABLE IF NOT EXISTS dfiq_questions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id   UUID NOT NULL REFERENCES dfiq_scenarios(id) ON DELETE CASCADE,
  dfiq_id       TEXT,
  facet_dfiq_id TEXT,
  facet_name    TEXT,
  text          TEXT NOT NULL,
  position      INTEGER NOT NULL DEFAULT 0,
  is_custom     BOOLEAN NOT NULL DEFAULT FALSE,
  raw           JSONB NOT NULL DEFAULT '{}',
  UNIQUE (scenario_id, dfiq_id),
  CONSTRAINT dfiq_questions_custom_no_dfiqid CHECK (NOT is_custom OR dfiq_id IS NULL)
);
CREATE TABLE IF NOT EXISTS dfiq_approaches (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question_id UUID NOT NULL REFERENCES dfiq_questions(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT,
  data_sources TEXT[] NOT NULL DEFAULT '{}',
  refs        TEXT[] NOT NULL DEFAULT '{}',
  position    INTEGER NOT NULL DEFAULT 0,
  raw         JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS case_dfiq (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  scenario_id UUID NOT NULL REFERENCES dfiq_scenarios(id) ON DELETE CASCADE,
  started_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (case_id, scenario_id)
);
CREATE TABLE IF NOT EXISTS case_dfiq_answers (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_dfiq_id UUID NOT NULL REFERENCES case_dfiq(id) ON DELETE CASCADE,
  question_id  UUID NOT NULL REFERENCES dfiq_questions(id) ON DELETE CASCADE,
  status       VARCHAR(20) NOT NULL DEFAULT 'todo',
  note         TEXT,
  answered_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  answered_at  TIMESTAMPTZ,
  UNIQUE (case_dfiq_id, question_id)
);
CREATE TABLE IF NOT EXISTS case_dfiq_evidence (
  case_dfiq_answer_id UUID NOT NULL REFERENCES case_dfiq_answers(id) ON DELETE CASCADE,
  bookmark_id         UUID NOT NULL REFERENCES timeline_bookmarks(id) ON DELETE CASCADE,
  added_by            UUID REFERENCES users(id) ON DELETE SET NULL,
  added_at            TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (case_dfiq_answer_id, bookmark_id)
);
CREATE INDEX IF NOT EXISTS idx_dfiq_questions_scenario ON dfiq_questions(scenario_id, position);
CREATE INDEX IF NOT EXISTS idx_case_dfiq_case ON case_dfiq(case_id);
CREATE INDEX IF NOT EXISTS idx_case_dfiq_answers_inst ON case_dfiq_answers(case_dfiq_id);
