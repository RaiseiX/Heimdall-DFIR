-- Migration 008: IOC Cross-Case Correlation View
-- Creates a view that identifies IOC values seen across multiple cases.

CREATE OR REPLACE VIEW ioc_cross_case AS
SELECT
  value                             AS ioc_value,
  ioc_type,
  COUNT(DISTINCT case_id)           AS case_count,
  ARRAY_AGG(DISTINCT case_id::text) AS case_ids,
  COUNT(*)                          AS total_occurrences,
  MAX(created_at)                   AS last_seen
FROM iocs
WHERE value IS NOT NULL AND value != ''
GROUP BY value, ioc_type
HAVING COUNT(DISTINCT case_id) > 1;

COMMENT ON VIEW ioc_cross_case IS
  'IOC values seen across more than one case — used for cross-case correlation widget';
