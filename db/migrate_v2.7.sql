-- ╔══════════════════════════════════════════════════════════════╗
-- ║         ForensicLab – Migration v2.6 → v2.7                 ║
-- ║                                                              ║
-- ║  Changes:                                                    ║
-- ║  1. parser_results.output_data default '{}' → '[]'          ║
-- ║     (array required for streaming batch appends)             ║
-- ║  2. parser_results adds updated_at column                    ║
-- ║                                                              ║
-- ║  Usage:                                                      ║
-- ║    docker exec -i forensiclab-db psql -U forensiclab         ║
-- ║      forensiclab < db/migrate_v2.7.sql                      ║
-- ╚══════════════════════════════════════════════════════════════╝

BEGIN;

-- 1. Add updated_at if missing
ALTER TABLE parser_results
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- 2. Fix existing rows that have '{}' default (object, not array)
UPDATE parser_results
SET output_data = '[]'::jsonb
WHERE jsonb_typeof(output_data) = 'object'
  AND output_data = '{}'::jsonb;

-- 3. Change column default to JSONB array
ALTER TABLE parser_results
    ALTER COLUMN output_data SET DEFAULT '[]';

-- 4. GIN index on output_data for fast JSONB queries on large result sets
CREATE INDEX IF NOT EXISTS idx_parser_results_data ON parser_results USING GIN (output_data);
CREATE INDEX IF NOT EXISTS idx_parser_results_evidence ON parser_results(evidence_id);

COMMIT;

-- Verify
SELECT
    column_name,
    data_type,
    column_default
FROM information_schema.columns
WHERE table_name = 'parser_results'
ORDER BY ordinal_position;
