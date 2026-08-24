-- ─── Replace full-jsonb GIN with a top-level-keys GIN ─────────────────────────
--
-- The previous idx_ct_raw_gin (default jsonb_ops opclass) indexes EVERY key AND
-- every nested value of `raw`. For EVTX rows whose `raw` carries deeply nested
-- EventData, that is a large number of index entries per row, and maintaining
-- them is the dominant cost of each 5000-row UNNEST insert — which is what
-- stalled parsing at the 5000/15000 batch boundaries.
--
-- Every consumer of that index only tests *top-level key existence*:
--   network.js  `raw ?| ARRAY[...]`  (remote host / IP field names)
--   cases.js    `raw ? 'DriverName' OR raw ? 'DriverId'`  (Amcache)
-- None of them reads nested values, so a full jsonb_ops index is wasted work.
--
-- jsonb_path_ops is smaller but drops support for the key-exists operators
-- (?, ?|, ?&), so it cannot serve those predicates. Instead we index only the
-- set of top-level keys as a text[], and rewrite the predicates:
--     raw ?| ARRAY[...]            →  jsonb_top_keys(raw) && ARRAY[...]
--     raw ? 'DriverName' OR ...    →  jsonb_top_keys(raw) && ARRAY['DriverName', ...]
-- These are exactly equivalent for the JSON objects stored in `raw` (the `?|`
-- array-element case can never match an object), and the index is a tiny GIN
-- over just the keys — no nested values, no per-key/per-value entry pairs.

SET lock_timeout = '10s';

-- Immutable helper: the set of top-level keys of a jsonb object, as text[].
-- Defensive against non-object inputs (returns empty), although `raw` is always
-- an object (`NOT NULL DEFAULT '{}'`, written from normalised records).
CREATE OR REPLACE FUNCTION jsonb_top_keys(j jsonb)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
  SELECT CASE jsonb_typeof(j)
           WHEN 'object' THEN ARRAY(SELECT jsonb_object_keys(j))
           ELSE '{}'::text[]
         END
$$;

-- CONCURRENTLY so dropping the old (large) index cannot block ingestion, and
-- building the new one cannot either.
DROP INDEX CONCURRENTLY IF EXISTS idx_ct_raw_gin;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_raw_keys_gin
  ON collection_timeline USING GIN (jsonb_top_keys(raw));

RESET lock_timeout;
