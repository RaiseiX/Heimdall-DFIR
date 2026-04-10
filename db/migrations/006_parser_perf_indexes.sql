-- Migration 006 — Parser performance indexes
-- Adds missing indexes identified during the parsing pipeline audit (2026-03-21).
-- Run with: docker exec heimdall-db psql -U postgres -d forensiclab -f /docker-entrypoint-initdb.d/migrations/006_parser_perf_indexes.sql

-- ── collection_timeline ────────────────────────────────────────────────────
-- Most timeline queries sort by timestamp DESC for a given case.
-- The existing idx_ct_case_ts covers (case_id, timestamp ASC).
-- This index covers ORDER BY timestamp DESC queries without sorting.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_case_ts_desc
  ON collection_timeline(case_id, timestamp DESC);

-- ── parser_results ─────────────────────────────────────────────────────────
-- Lookups by parser_name are frequent (e.g. "has Hayabusa been run on this case?").
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pr_case_name
  ON parser_results(case_id, parser_name);
