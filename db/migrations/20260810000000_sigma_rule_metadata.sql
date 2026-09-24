-- 20260810000000_sigma_rule_metadata — extract severity level, MITRE ATT&CK
-- techniques and upstream status from each rule's own YAML, instead of
-- discarding them at import (Task 4 of docs/superpowers/plans/2026-08-07-
-- sigma-platform-scoping-and-honest-counts.md).
--
-- WHY: sigmaService.ts already parses logsource but never touched `level:`
-- or the rule's own `tags:`. Measured on the live DB, 2026-08-07:
-- 3999/3999 active rules declare a level (critical 189, high 1826,
-- medium 1590, low 364, informational 30) and 3994/3999 carry attack.* tags
-- — none of it extracted. Hunt results are therefore returned in
-- alphabetical order: a critical credential-dumping detection sits between
-- two `low` rules and the analyst has to open all forty matches to find it.
--
-- level: 'critical'|'high'|'medium'|'low'|'informational'|NULL. NULL means
-- the rule's YAML declares no `level:` (or an unrecognised value) — never a
-- default guessed by this migration or by sigmaService.ts::parseRule.
--
-- mitre_techniques: TEXT[], upper-case 'T####' / 'T####.###' form, holding
-- BOTH a sub-technique and its parent (so a query scoped to the parent
-- technique also finds rules tagged only with a sub-technique of it).
-- Sigma's `attack.*` tag namespace mixes four unrelated things under one
-- prefix — attack.s0003 (software), attack.persistence (tactic), attack.
-- t1546.004 (sub-technique) — extraction keeps only tags matching
-- attack\.t\d{4}(\.\d{3})?, so tactics, software, groups and campaigns never
-- end up in this column. See sigmaService.ts::extractMitreTechniques.
--
-- upstream_status: 'stable'|'test'|'experimental'|'deprecated'|'unsupported'
-- |NULL, mirroring Sigma's own `status:` field. threatHunting.ts's hunt
-- scoping (Task 3 of this same plan) used to evaluate this with a Postgres
-- regex over the whole `content` column on every hunt, which cannot anchor
-- to a line start cheaply and misses a quoted value (`status: "deprecated"`)
-- — this column replaces that regex (STATUS_EXCLUDES_HUNT) with a plain
-- column check.
--
-- Schema only: this migration does not touch existing rows' data — every
-- row (including the 3999 that already exist) gets level = NULL,
-- mitre_techniques = '{}', upstream_status = NULL until backfilled. The
-- retroactive re-parse of stored `content` is a separate step —
-- backend/scripts/backfillSigmaMetadata.js — because it needs the same
-- YAML-aware extraction sigmaService.ts uses (js-yaml), which a plain SQL
-- migration would have to re-implement as regexes over raw text, at real
-- risk of drifting from the extractor used at import/update time. Same
-- house pattern as backend/scripts/seedDfiq.js. Run it once after this
-- migration applies:
--   docker compose exec backend node scripts/backfillSigmaMetadata.js
--
-- Idempotent: safe to re-run (manifest-driven migrate.sh records it once);
-- ADD COLUMN IF NOT EXISTS makes a second manual run a no-op too.
ALTER TABLE sigma_rules
  ADD COLUMN IF NOT EXISTS level VARCHAR(20)
    CONSTRAINT sigma_rules_level_check
      CHECK (level IS NULL OR level IN ('critical', 'high', 'medium', 'low', 'informational')),
  ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS upstream_status VARCHAR(20)
    CONSTRAINT sigma_rules_upstream_status_check
      CHECK (upstream_status IS NULL OR upstream_status IN ('stable', 'test', 'experimental', 'deprecated', 'unsupported'));
