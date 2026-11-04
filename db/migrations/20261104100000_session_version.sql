SET lock_timeout = '5s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'session_version') THEN
    ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0;
  END IF;
END $$;
