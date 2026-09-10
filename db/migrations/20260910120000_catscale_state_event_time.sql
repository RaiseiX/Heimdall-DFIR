-- catscale_state held only collected_at: the moment the collection ran. Artifacts
-- that record a time of their own had nowhere to put it, so `dmesg -T` — 2,110
-- dated lines on the reference host, spanning 07:22:07 to 13:56:57 — entered the
-- SuperTimeline with a NULL timestamp and was invisible chronologically.
--
-- event_time is the wall-clock time the artifact itself recorded, never the
-- collection time. NULL keeps its existing meaning: the object exists, its age is
-- unknown. event_time_kind names the artifact the clock came from, so the grid's
-- TS Type column says which one produced it.

ALTER TABLE catscale_state
  ADD COLUMN IF NOT EXISTS event_time timestamptz,
  ADD COLUMN IF NOT EXISTS event_time_kind varchar(32);

CREATE INDEX IF NOT EXISTS idx_cs_state_event_time
  ON catscale_state (case_id, event_time)
  WHERE event_time IS NOT NULL;
