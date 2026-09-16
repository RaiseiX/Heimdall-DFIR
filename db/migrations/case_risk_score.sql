-- Migration 007: Case Risk Score
-- Adds risk_score and risk_level computed columns cache on the cases table.
-- The riskScoreService.ts computes the score and writes here.
-- Redis caches the result for 5 minutes; this table provides persistence.

ALTER TABLE cases
  ADD COLUMN IF NOT EXISTS risk_score   SMALLINT,
  ADD COLUMN IF NOT EXISTS risk_level   VARCHAR(10),
  ADD COLUMN IF NOT EXISTS risk_computed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cases_risk_level ON cases(risk_level);

COMMENT ON COLUMN cases.risk_score IS 'Computed risk score 0–100 (NULL = not yet computed)';
COMMENT ON COLUMN cases.risk_level IS 'CRITICAL | HIGH | MEDIUM | LOW (NULL = not yet computed)';
COMMENT ON COLUMN cases.risk_computed_at IS 'Timestamp of last risk score computation';
