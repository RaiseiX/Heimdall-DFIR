-- 20260727000000_audit_chain — Audit log tamper evidence: ordinal sequence + hash chain.
--
-- WHY: the per-row HMAC added earlier proves a row was not EDITED, but not that
-- the log is COMPLETE. Anyone with DB write access could DELETE rows and every
-- surviving HMAC would still verify. `prev_hash` binds each row to its
-- predecessor so a removal breaks its successor's link.
--
-- Rows written before this migration keep prev_hash = NULL and stay verifiable
-- under the legacy per-row scheme. We do NOT back-fill a chain over them: a
-- chain computed after the fact proves nothing and would fake continuity.
--
-- Idempotent: safe to re-run (manifest-driven migrate.sh records it once).

-- Monotonic ordinal. NOTE: a rolled-back INSERT still consumes a value, so gaps
-- in seq are normal and are NOT evidence of deletion — only a broken prev_hash is.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq BIGSERIAL;

-- NULL  => legacy row (pre-chain, verified per-row)
-- 000…0 => genesis, first link of the chain
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64);

-- Serves the hot path: "read the tail of the chain" on every append.
CREATE INDEX IF NOT EXISTS idx_audit_log_chain
  ON audit_log (seq DESC) WHERE prev_hash IS NOT NULL;
