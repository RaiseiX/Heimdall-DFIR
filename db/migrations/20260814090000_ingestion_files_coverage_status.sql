-- db/migrations/20260814090000_ingestion_files_coverage_status.sql
-- ingestion_files becomes the coverage ledger of a collection: one row per file,
-- written before any parsing is attempted. Two outcomes had no status.
--
-- 'unsupported'      the file was seen, no parser claims it. 63 files of the
--                    reference collection, 33.1 MB, previously indistinguishable
--                    from files that do not exist.
-- 'archive_expanded' the archive was opened and its members registered separately.
--
-- The spec's 'failed' maps onto the existing 'error': one meaning, one status.
ALTER TABLE ingestion_files DROP CONSTRAINT IF EXISTS ingestion_files_status_check;
ALTER TABLE ingestion_files ADD CONSTRAINT ingestion_files_status_check CHECK (status IN (
  'received','extracting','classified','queued','parsing',
  'parsed','empty','degraded','error','quarantined','skipped_duplicate',
  'unsupported','archive_expanded'));
