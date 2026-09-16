-- ─────────────────────────────────────────────────────────────────────────────
-- migrate_v2.21.sql — VolWeb : colonnes volweb_* sur cases et evidence
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

-- cases : lien vers le cas VolWeb correspondant
ALTER TABLE cases
  ADD COLUMN IF NOT EXISTS volweb_case_id INTEGER;

-- evidence : suivi du pipeline VolWeb par evidence
ALTER TABLE evidence
  ADD COLUMN IF NOT EXISTS volweb_evidence_id INTEGER,
  ADD COLUMN IF NOT EXISTS volweb_status TEXT
    CHECK (volweb_status IN ('uploading', 'processing', 'complete', 'error'));

CREATE INDEX IF NOT EXISTS idx_evidence_volweb ON evidence(volweb_status) WHERE volweb_status IS NOT NULL;

COMMIT;
