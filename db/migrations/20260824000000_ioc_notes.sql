-- ╔══════════════════════════════════════════════════════════════╗
-- ║   Migration — Notes analyste sur les IOCs                    ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Adds a free-text analyst note to each IOC (already referenced by
-- POST /iocs/:id/confirm but never created by a migration).

ALTER TABLE iocs
  ADD COLUMN IF NOT EXISTS notes TEXT;
