CREATE TABLE IF NOT EXISTS case_deletion_operations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  idempotency_key TEXT NOT NULL UNIQUE,
  case_id UUID NOT NULL,
  case_number TEXT,
  operation_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'ready_to_commit', 'incomplete', 'completed')),
  requested_by UUID,
  request_ip TEXT,
  context JSONB NOT NULL DEFAULT '{}',
  error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS case_deletion_items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  operation_id UUID NOT NULL REFERENCES case_deletion_operations(id) ON DELETE CASCADE,
  item_key CHAR(64) NOT NULL,
  ordinal INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('disk', 'minio', 'elasticsearch')),
  locator TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'deleted', 'already_absent', 'failed')),
  method TEXT,
  error_code TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(operation_id, item_key)
);

CREATE INDEX IF NOT EXISTS idx_case_deletion_operations_case_status
  ON case_deletion_operations(case_id, status);

CREATE INDEX IF NOT EXISTS idx_case_deletion_items_operation_status
  ON case_deletion_items(operation_id, status);
