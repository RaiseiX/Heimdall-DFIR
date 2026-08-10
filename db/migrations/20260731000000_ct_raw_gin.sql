-- ─── GIN index on collection_timeline.raw ────────────────────────────────────
--
-- Why: the network map filtered rows with `raw->>'RemoteHost' IS NOT NULL` and
-- six sibling predicates. `->>` is a function call, so no index applies and
-- Postgres deserialises every row. On a case holding 1.3M rows that SELECT ran
-- for 15h while holding ACCESS SHARE; the startup ALTER TABLE queued behind it
-- in ACCESS EXCLUSIVE and — because a *queued* ACCESS EXCLUSIVE blocks every
-- later arrival — every INSERT queued behind that. Symptoms were 5% CPU, no log
-- output, and nothing written to the database.
--
-- The routes now use `raw ?| ARRAY[...]` (key existence), which GIN can serve.
-- The predicate is a superset of the old one — it also admits keys whose value
-- is JSON null — and the queries keep their outer WHERE, which rejects those.
--
-- jsonb_path_ops produces a smaller index but supports only @>, not ?|, so this
-- deliberately uses the default jsonb_ops opclass.

SET lock_timeout = '10s';

-- An interrupted CONCURRENTLY build leaves the index behind marked INVALID.
-- `IF NOT EXISTS` would then see the name as taken and skip the rebuild forever,
-- so every restart would quietly inherit a dead index.
--
-- indisvalid = false has two meanings, though: "a past build failed" and "a
-- build is running right now and has not flipped the flag yet". Running this
-- migration twice concurrently hits the second case, and the DROP then blocks on
-- the builder's ShareUpdateExclusiveLock until lock_timeout kills it. Detect a
-- live build and stop with an actionable message instead.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM pg_stat_progress_create_index p
      JOIN pg_class c ON c.oid = p.index_relid
     WHERE c.relname = 'idx_ct_raw_gin'
  ) THEN
    RAISE EXCEPTION
      'idx_ct_raw_gin is currently being built by another session. Wait for it to finish (SELECT phase, blocks_done, blocks_total FROM pg_stat_progress_create_index), then re-run this migration.';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_class c
      JOIN pg_index i ON i.indexrelid = c.oid
     WHERE c.relname = 'idx_ct_raw_gin' AND NOT i.indisvalid
  ) THEN
    EXECUTE 'DROP INDEX idx_ct_raw_gin';
  END IF;
END $$;

-- CONCURRENTLY: a plain CREATE INDEX holds SHARE for the whole build (minutes on
-- a large table), blocking exactly the INSERTs this migration exists to protect.
-- psql runs each statement in autocommit, so CONCURRENTLY is legal here.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_raw_gin
  ON collection_timeline USING GIN (raw);

RESET lock_timeout;
