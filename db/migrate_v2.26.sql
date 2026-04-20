-- v2.26 — Threat Engine: per-row detection results
-- Adds a structured detections column so the UI can render severity-coloured
-- indicators without reverse-mapping from flat tag strings.

ALTER TABLE collection_timeline
  ADD COLUMN IF NOT EXISTS detections JSONB DEFAULT NULL;

-- GIN index with jsonb_path_ops for fast severity / category / mitre filtering.
CREATE INDEX IF NOT EXISTS idx_ct_detections
  ON collection_timeline USING GIN (detections jsonb_path_ops);

-- Partial index for the "hits only" quick filter.
CREATE INDEX IF NOT EXISTS idx_ct_has_detections
  ON collection_timeline (case_id)
  WHERE detections IS NOT NULL AND jsonb_array_length(detections) > 0;
