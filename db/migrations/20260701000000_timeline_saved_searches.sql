-- db/migrations/20260701000000_timeline_saved_searches.sql
-- Timeline saved searches: named, re-applicable filter states, optionally case-shared.

CREATE TABLE IF NOT EXISTS timeline_saved_searches (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    UUID NOT NULL REFERENCES cases(id)  ON DELETE CASCADE,
  author_id  UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  name       VARCHAR(120) NOT NULL,
  scope      VARCHAR(10)  NOT NULL DEFAULT 'personal' CHECK (scope IN ('personal','case')),
  query      JSONB        NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, author_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tss_case_author ON timeline_saved_searches(case_id, author_id);
CREATE INDEX IF NOT EXISTS idx_tss_case_shared ON timeline_saved_searches(case_id) WHERE scope = 'case';
