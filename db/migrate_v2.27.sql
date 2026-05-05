-- v2.27 — Fix workbench FK types: INTEGER → UUID
-- Corrects a type mismatch introduced in v2.25 where case_id/pinned_by/actor_id
-- were declared as INTEGER instead of UUID, causing FK violations on every INSERT.
-- Idempotent: ALTER COLUMN ... TYPE is a no-op if the column is already UUID.

BEGIN;

-- workbench_evidence_pins
ALTER TABLE workbench_evidence_pins
  ALTER COLUMN case_id  TYPE UUID USING case_id::text::UUID,
  ALTER COLUMN pinned_by TYPE UUID USING pinned_by::text::UUID;

-- workbench_evidence_audit
ALTER TABLE workbench_evidence_audit
  ALTER COLUMN case_id  TYPE UUID USING case_id::text::UUID,
  ALTER COLUMN actor_id TYPE UUID USING actor_id::text::UUID;

COMMIT;
