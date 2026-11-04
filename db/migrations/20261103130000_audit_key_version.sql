SET lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'audit_log' AND column_name = 'key_id') THEN
    ALTER TABLE audit_log ADD COLUMN key_id VARCHAR(16);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS audit_chain_meta (
  singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  genesis_seq BIGINT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'audit_chain_meta' AND column_name = 'rotation_seq') THEN
    ALTER TABLE audit_chain_meta ADD COLUMN rotation_seq BIGINT;
  END IF;
END $$;

INSERT INTO audit_chain_meta (singleton, genesis_seq)
SELECT TRUE, MIN(seq) FROM audit_log WHERE prev_hash IS NOT NULL
HAVING MIN(seq) IS NOT NULL
ON CONFLICT (singleton) DO NOTHING;

UPDATE audit_log SET key_id = 'v1' WHERE prev_hash IS NOT NULL AND key_id IS NULL;
