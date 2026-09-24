-- Durable parse queue: a parse survives an odin restart.
-- One row per /parse request; the payload carries what the job needs without
-- the original HTTP request. Rows still queued/running at startup are resumed.
CREATE TABLE IF NOT EXISTS parse_queue (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  result_id    UUID NOT NULL REFERENCES parser_results(id) ON DELETE CASCADE,
  status       TEXT NOT NULL DEFAULT 'queued'
    CONSTRAINT parse_queue_status_check CHECK (status IN ('queued', 'running', 'done', 'error')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  payload      JSONB NOT NULL,
  error        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_parse_queue_pending
  ON parse_queue (created_at, id) WHERE status IN ('queued', 'running');
