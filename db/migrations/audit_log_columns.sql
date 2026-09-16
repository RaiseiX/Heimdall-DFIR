-- ╔══════════════════════════════════════════════════════════════╗
-- ║        Migration v2.8 — Audit Log Integrity (HMAC)          ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.8.sql

-- 1. Champ HMAC-SHA256 sur chaque entrée d'audit (intégrité)
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hmac VARCHAR(64);

-- 2. Index sur entity_id pour les requêtes par cas (GET /api/cases/:id/audit)
CREATE INDEX IF NOT EXISTS idx_audit_entity_id ON audit_log(entity_id);
