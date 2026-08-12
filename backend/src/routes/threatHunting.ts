
import express from 'express';
import * as nodeHttps from 'https';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import logger from '../config/logger';
import type { Pool } from 'pg';
import { authenticate, requireRole, auditLog, JWT_SECRET } from '../middleware/auth';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import type { AuthRequest } from '../types/index';
import { validateRule, scanEvidence } from '../services/yaraService';
import { parseRule, buildQuery } from '../services/sigmaService';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { platformForArtifactType } = require('../services/artifactPlatform');

const router = express.Router();

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { caseAccessParam } = require('../middleware/caseAccess');
router.use(authenticate as any);
router.param('caseId', caseAccessParam);

function getPool(req: express.Request): Pool {
  return (req as any).app.locals.pool as Pool;
}

async function ensureTables(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS yara_rules (
      id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      name        VARCHAR(200) NOT NULL,
      description TEXT,
      content     TEXT NOT NULL,
      author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
      tags        VARCHAR[] DEFAULT '{}',
      is_active   BOOLEAN DEFAULT true,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS yara_scan_results (
      id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      evidence_id     UUID REFERENCES evidence(id) ON DELETE CASCADE,
      case_id         UUID REFERENCES cases(id) ON DELETE CASCADE,
      rule_id         UUID REFERENCES yara_rules(id) ON DELETE CASCADE,
      rule_name       VARCHAR(200) NOT NULL,
      matched_strings JSONB DEFAULT '[]',
      scanned_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_yara_scan_case     ON yara_scan_results(case_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_yara_scan_evidence ON yara_scan_results(evidence_id)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sigma_rules (
      id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      name                VARCHAR(200) NOT NULL,
      description         TEXT,
      content             TEXT NOT NULL,
      author_id           UUID REFERENCES users(id) ON DELETE SET NULL,
      logsource_category  VARCHAR(100),
      logsource_product   VARCHAR(100),
      tags                VARCHAR[] DEFAULT '{}',
      level               VARCHAR(20),
      mitre_techniques    TEXT[] NOT NULL DEFAULT '{}',
      upstream_status     VARCHAR(20),
      is_active           BOOLEAN DEFAULT true,
      created_at          TIMESTAMPTZ DEFAULT NOW(),
      updated_at          TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sigma_hunt_results (
      id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      case_id         UUID REFERENCES cases(id) ON DELETE CASCADE,
      rule_id         UUID REFERENCES sigma_rules(id) ON DELETE CASCADE,
      rule_name       VARCHAR(200) NOT NULL,
      match_count     INTEGER DEFAULT 0,
      matched_events  JSONB DEFAULT '[]',
      hunted_at       TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sigma_hunt_case ON sigma_hunt_results(case_id)`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sysmon_library (
      config_key   VARCHAR(80) PRIMARY KEY,
      name         VARCHAR(200) NOT NULL,
      author       VARCHAR(120),
      license      VARCHAR(120),
      source_url   TEXT,
      content      TEXT NOT NULL,
      imported_by  UUID REFERENCES users(id) ON DELETE SET NULL,
      imported_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at   TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

let migrationDone = false;
function withMigration(pool: Pool): Pool {
  if (!migrationDone) {
    migrationDone = true;
    ensureTables(pool).catch((e) =>
      logger.warn('[ThreatHunting] migration warning:', e.message),
    );
  }
  return pool;
}

function poolMig(req: express.Request): Pool {
  return withMigration(getPool(req));
}

router.get('/yara/rules', authenticate, async (req, res) => {
  try {
    const result = await poolMig(req).query(
      `SELECT r.id, r.name, r.description, r.content, r.tags, r.is_active, r.created_at, r.updated_at,
              u.username AS author_username, u.full_name AS author_name
         FROM yara_rules r
         LEFT JOIN users u ON u.id = r.author_id
        ORDER BY r.created_at DESC`,
    );
    res.json({ rules: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/yara/rules', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { name, description, content, tags } = req.body;
    if (!name || !content) return res.status(400).json({ error: 'name et content sont requis' });

    const validation = await validateRule(content);
    if (!validation.valid) return res.status(400).json({ error: validation.error });

    const userId = (req as AuthRequest).user?.id;
    const tagsArr = Array.isArray(tags) ? tags : [];
    const result = await poolMig(req).query(
      `INSERT INTO yara_rules (name, description, content, author_id, tags)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, description, tags, is_active, created_at`,
      [name.trim(), description ?? null, content, userId, tagsArr],
    );
    res.status(201).json({ rule: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/yara/rules/:id', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const { name, description, content, tags, is_active } = req.body;

    if (content !== undefined) {
      const validation = await validateRule(content);
      if (!validation.valid) return res.status(400).json({ error: validation.error });
    }

    const pool = poolMig(req);
    const current = await pool.query('SELECT * FROM yara_rules WHERE id = $1', [id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Règle introuvable' });

    const r = current.rows[0];
    const result = await pool.query(
      `UPDATE yara_rules
          SET name = $1, description = $2, content = $3, tags = $4, is_active = $5, updated_at = NOW()
        WHERE id = $6
        RETURNING id, name, description, tags, is_active, updated_at`,
      [
        name ?? r.name,
        description !== undefined ? description : r.description,
        content ?? r.content,
        Array.isArray(tags) ? tags : r.tags,
        is_active !== undefined ? is_active : r.is_active,
        id,
      ],
    );
    res.json({ rule: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/yara/rules/:id', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const result = await poolMig(req).query(
      'DELETE FROM yara_rules WHERE id = $1 RETURNING id',
      [id],
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Règle introuvable' });
    res.json({ deleted: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/yara/scan/:evidenceId', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { evidenceId } = req.params;
    const pool = poolMig(req);

    const evResult = await pool.query(
      'SELECT id, case_id, file_path, name FROM evidence WHERE id = $1',
      [evidenceId],
    );
    if (evResult.rows.length === 0) return res.status(404).json({ error: 'Evidence introuvable' });
    const ev = evResult.rows[0];

    const rulesResult = await pool.query(
      'SELECT id, name, content FROM yara_rules WHERE is_active = true',
    );
    if (rulesResult.rows.length === 0) {
      return res.json({ matches: [], message: 'Aucune règle YARA active' });
    }

    await pool.query('DELETE FROM yara_scan_results WHERE evidence_id = $1', [evidenceId]);

    const matches: any[] = [];
    for (const rule of rulesResult.rows) {
      const scanResult = await scanEvidence(ev.file_path, rule.content);
      if (scanResult.error) {
        logger.warn(`[YARA] Scan error (${rule.name}): ${scanResult.error}`);
        continue;
      }
      if (scanResult.matched) {
        await pool.query(
          `INSERT INTO yara_scan_results (evidence_id, case_id, rule_id, rule_name, matched_strings)
           VALUES ($1, $2, $3, $4, $5)`,
          [evidenceId, ev.case_id, rule.id, rule.name, JSON.stringify(scanResult.strings)],
        );
        matches.push({ rule_id: rule.id, rule_name: rule.name, strings: scanResult.strings });
      }
    }

    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_yara_scan', 'evidence', evidenceId,
      { evidence_name: ev.name, rules_checked: rulesResult.rows.length, match_count: matches.length }, req.ip);

    res.json({
      evidence_id: evidenceId,
      evidence_name: ev.name,
      rules_checked: rulesResult.rows.length,
      matches,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/yara/scan-case/:caseId', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  const send = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const { caseId } = req.params;
    const pool = poolMig(req);

    const [evResult, rulesResult] = await Promise.all([
      pool.query('SELECT id, file_path, name, file_size, evidence_type FROM evidence WHERE case_id = $1', [caseId]),
      pool.query('SELECT id, name, content FROM yara_rules WHERE is_active = true'),
    ]);

    if (rulesResult.rows.length === 0) {
      send({ type: 'done', summary: [], files_scanned: 0, files_skipped: 0, message: 'Aucune règle YARA active' });
      return res.end();
    }

    // Skip classification computed BEFORE `start` is sent (YARA/Tout lancer
    // scope-band rebuild, 2026-08-11) — previously each evidence row's
    // memory-dump/oversize check ran lazily inside the loop, so the scope
    // band had no way to say how many of `total` evidence files would
    // actually be scanned until the run was already underway. Same shape as
    // Sigma's `skipped_platform` precomputation in `/sigma/scan-case`: the
    // decision that will exclude a row is made once, up front, and reused —
    // never recomputed a second time inside the loop below.
    const YARA_MAX_SIZE = 500 * 1024 * 1024;
    const skipReason = (ev: any): string | null => {
      if (ev.evidence_type === 'memory') return 'dump mémoire';
      if (Number(ev.file_size) > YARA_MAX_SIZE) return 'fichier > 500 MB';
      return null;
    };
    const skippedMemory = evResult.rows.filter((ev: any) => ev.evidence_type === 'memory').length;
    const skippedSize = evResult.rows.filter(
      (ev: any) => ev.evidence_type !== 'memory' && Number(ev.file_size) > YARA_MAX_SIZE,
    ).length;
    const filesToScan = evResult.rows.length - skippedMemory - skippedSize;

    // `files_to_scan`/`skipped_memory`/`skipped_size` are additive to the
    // pre-existing `total`/`rules` fields — no field renamed or removed, so
    // an older frontend build reading only `total`/`rules` keeps working
    // unchanged (same additive contract Sigma's `start` event already
    // established with `rules_to_run`/`skipped_platform`).
    send({
      type: 'start',
      total: evResult.rows.length,
      rules: rulesResult.rows.length,
      files_to_scan: filesToScan,
      skipped_memory: skippedMemory,
      skipped_size: skippedSize,
    });

    await pool.query('DELETE FROM yara_scan_results WHERE case_id = $1', [caseId]);

    const summary: any[] = [];
    // Live tally for the UI's progress band (mirrors Sigma's `matched_so_far`/
    // `critical_so_far` — see `/sigma/scan-case` above), cumulative over every
    // evidence file fully scanned BEFORE the one this `progress` frame names.
    // YARA carries no severity axis, so the second figure is "files flagged"
    // rather than a severity count.
    let matchesSoFar = 0;
    let filesFlaggedSoFar = 0;
    for (let i = 0; i < evResult.rows.length; i++) {
      const ev = evResult.rows[i];
      send({
        type: 'progress', current: i + 1, total: evResult.rows.length, name: ev.name,
        matches_so_far: matchesSoFar, files_flagged_so_far: filesFlaggedSoFar,
      });

      const reason = skipReason(ev);
      if (reason) {
        logger.info(`[YARA] Skip ${ev.name}: ${reason}`);
        summary.push({ evidence_id: ev.id, evidence_name: ev.name, matches: [], skipped: true, reason });
        continue;
      }

      const fileMatches: any[] = [];
      for (const rule of rulesResult.rows) {
        const scanResult = await scanEvidence(ev.file_path, rule.content);
        if (scanResult.error) {
          logger.warn(`[YARA] ${ev.name} / ${rule.name}: ${scanResult.error}`);
          continue;
        }
        if (scanResult.matched) {
          await pool.query(
            `INSERT INTO yara_scan_results (evidence_id, case_id, rule_id, rule_name, matched_strings)
             VALUES ($1, $2, $3, $4, $5)`,
            [ev.id, caseId, rule.id, rule.name, JSON.stringify(scanResult.strings)],
          );
          fileMatches.push({ rule_name: rule.name, count: scanResult.strings.length });
        }
      }
      summary.push({ evidence_id: ev.id, evidence_name: ev.name, matches: fileMatches });
      matchesSoFar += fileMatches.length;
      if (fileMatches.length > 0) filesFlaggedSoFar++;
    }

    const scanned = summary.filter(s => !s.skipped).length;
    const skipped = summary.filter(s => s.skipped).length;
    const filesFlagged = summary.filter(s => !s.skipped && s.matches.length > 0).length;
    const totalMatches = summary.reduce((acc, s) => acc + s.matches.length, 0);
    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_yara_scan', 'case', caseId,
      { files_scanned: scanned, files_skipped: skipped, rules_checked: rulesResult.rows.length, match_count: totalMatches }, req.ip);

    // `rules_checked`/`files_flagged`/`total_rule_matches` are additive on
    // `done`, same rule as `start` above — `files_scanned`/`files_skipped`/
    // `summary`/`case_id` are all untouched.
    send({
      type: 'done', case_id: caseId, files_scanned: scanned, files_skipped: skipped,
      rules_checked: rulesResult.rows.length, files_flagged: filesFlagged, total_rule_matches: totalMatches,
      summary,
    });
    res.end();
  } catch (e: any) {
    send({ type: 'error', error: e.message });
    res.end();
  }
});

router.get('/yara/results/:caseId', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await poolMig(req).query(
      `SELECT s.id, s.evidence_id, s.rule_id, s.rule_name, s.matched_strings, s.scanned_at,
              e.name AS evidence_name, e.file_path
         FROM yara_scan_results s
         JOIN evidence e ON e.id = s.evidence_id
        WHERE s.case_id = $1
        ORDER BY s.scanned_at DESC`,
      [caseId],
    );
    res.json({ results: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/yara/results/evidence/:evidenceId', authenticate, async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const result = await poolMig(req).query(
      `SELECT id, rule_id, rule_name, matched_strings, scanned_at
         FROM yara_scan_results
        WHERE evidence_id = $1
        ORDER BY scanned_at DESC`,
      [evidenceId],
    );
    res.json({ results: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// Per-rule aggregation across every case a rule has ever run against — "has
// this rule ever matched anything?" Rules with zero matches are simply absent
// (never a fabricated zero row: the frontend treats absence as zero). No JOIN
// to yara_rules: a rule row can be deleted (ON DELETE CASCADE normally takes
// its results with it) without this query needing to know it ever existed.
router.get('/yara/rule-stats', authenticate, async (req, res) => {
  try {
    const result = await poolMig(req).query(
      `SELECT rule_id,
              COUNT(*)::int                AS match_count,
              COUNT(DISTINCT case_id)::int AS case_count,
              MAX(scanned_at)              AS last_matched_at
         FROM yara_scan_results
        WHERE rule_id IS NOT NULL
        GROUP BY rule_id`,
    );
    res.json({ stats: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/sigma/rules', authenticate, async (req, res) => {
  try {
    // level / mitre_techniques / upstream_status added here (Sigma hunt UI
    // rebuild, 2026-08-11) — purely additive columns on an existing SELECT.
    // SigmaRulesTab.jsx (the caller left untouched by this change) simply
    // ignores the extra fields; the Sigma hunt tab's rule picker and its
    // results table are the actual consumers, and need them to show
    // severity/technique without shipping the raw rule content.
    const result = await poolMig(req).query(
      `SELECT r.id, r.name, r.description, r.content, r.logsource_category, r.logsource_product,
              r.tags, r.level, r.mitre_techniques, r.upstream_status, r.is_active, r.created_at, r.updated_at,
              u.username AS author_username
         FROM sigma_rules r
         LEFT JOIN users u ON u.id = r.author_id
        ORDER BY r.created_at DESC`,
    );
    res.json({ rules: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/sigma/rules', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { name, content, tags } = req.body;
    if (!name || !content) return res.status(400).json({ error: 'name et content sont requis' });

    const validation = parseRule(content);
    if (!validation.valid) return res.status(400).json({ error: validation.error });

    const userId = (req as AuthRequest).user?.id;
    // tagsArr is import provenance (e.g. ['github', 'sigmahq']), supplied by
    // the caller — never overwritten by the rule's own YAML tags, which are
    // extracted separately into mitre_techniques below (Task 4 of the
    // platform-scoping plan). See sigmaService.ts::extractMitreTechniques.
    const tagsArr = Array.isArray(tags) ? tags : [];
    const result = await poolMig(req).query(
      `INSERT INTO sigma_rules
         (name, description, content, author_id, logsource_category, logsource_product, tags,
          level, mitre_techniques, upstream_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, name, description, logsource_category, logsource_product, tags,
                 level, mitre_techniques, upstream_status, is_active, created_at`,
      [
        name.trim(),
        validation.parsed?.description ?? null,
        content,
        userId,
        validation.logsourceCategory ?? null,
        validation.logsourceProduct ?? null,
        tagsArr,
        validation.level ?? null,
        validation.mitreTechniques ?? [],
        validation.upstreamStatus ?? null,
      ],
    );
    res.status(201).json({ rule: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/sigma/rules/:id', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const { name, content, tags, is_active } = req.body;

    let logsourceCat: string | null = null;
    let logsourceProd: string | null = null;
    let level: string | null = null;
    let mitreTechniques: string[] = [];
    let upstreamStatus: string | null = null;
    if (content !== undefined) {
      const validation = parseRule(content);
      if (!validation.valid) return res.status(400).json({ error: validation.error });
      logsourceCat    = validation.logsourceCategory ?? null;
      logsourceProd   = validation.logsourceProduct ?? null;
      level           = validation.level ?? null;
      mitreTechniques = validation.mitreTechniques ?? [];
      upstreamStatus  = validation.upstreamStatus ?? null;
    }

    const pool = poolMig(req);
    const current = await pool.query('SELECT * FROM sigma_rules WHERE id = $1', [id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Règle introuvable' });

    const r = current.rows[0];
    const result = await pool.query(
      `UPDATE sigma_rules
          SET name = $1, content = $2, tags = $3, is_active = $4,
              logsource_category = $5, logsource_product = $6,
              level = $7, mitre_techniques = $8, upstream_status = $9,
              updated_at = NOW()
        WHERE id = $10
        RETURNING id, name, description, logsource_category, logsource_product, tags,
                  level, mitre_techniques, upstream_status, is_active, updated_at`,
      [
        name ?? r.name,
        content ?? r.content,
        Array.isArray(tags) ? tags : r.tags,
        is_active !== undefined ? is_active : r.is_active,
        content ? logsourceCat : r.logsource_category,
        content ? logsourceProd : r.logsource_product,
        content ? level : r.level,
        content ? mitreTechniques : r.mitre_techniques,
        content ? upstreamStatus : r.upstream_status,
        id,
      ],
    );
    res.json({ rule: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/sigma/rules/:id', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const result = await poolMig(req).query(
      'DELETE FROM sigma_rules WHERE id = $1 RETURNING id',
      [id],
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Règle introuvable' });
    res.json({ deleted: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// Task 3 (docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-honest-
// counts.md): scope a Sigma scan-case hunt to the platforms actually present
// in the case, instead of evaluating all 3999 active rules against every
// case regardless of what it holds.
//
// The platform is a SET, not a scalar (2026-08-07 correction to this plan): a
// hunt runs per CASE, and a case commonly holds more than one collection — a
// compromised Linux server *and* the Windows workstation it was reached from.
// Electing one winning platform would leave the other half of the evidence
// unhunted, a silent false negative. So this derives every platform present,
// from every distinct collection_timeline.artifact_type in the case.
//
// parser_results.platform (Task 2) is provenance/fallback, not the source of
// truth: it is consulted only when the timeline itself yields nothing
// recognisable (e.g. a case with no timeline rows yet, or artifact types this
// map doesn't cover) — never overriding a platform actually observed in the
// timeline.
async function casePlatforms(pool: Pool, caseId: string): Promise<Set<string>> {
  const timelineTypes = await pool.query(
    `SELECT DISTINCT artifact_type FROM collection_timeline WHERE case_id = $1`,
    [caseId],
  );
  const platforms = new Set<string>();
  for (const row of timelineTypes.rows) {
    const platform = platformForArtifactType(row.artifact_type);
    if (platform) platforms.add(platform);
  }
  if (platforms.size > 0) return platforms;

  // Fallback only — parser_results.platform (Task 2) is provenance, never the
  // source of truth. Guarded separately: that column only exists once
  // db/migrations/20260807010000_collection_platform.sql has run, and this
  // hunt must not hard-fail on a database where it hasn't (or hasn't yet on
  // every environment) — the whole point of this policy is that "unknown" is
  // handled by running everything, never by erroring out.
  try {
    // Task 2's own report flagged this: parser_results also holds rows from
    // other parsers (Hayabusa, CSV imports, ...) with parser_name !=
    // 'MagnetRESPONSE_Import'. Only the collection-import row ever gets a
    // non-NULL platform written today, so `platform IS NOT NULL` alone would
    // happen to scope correctly — but naming the parser explicitly means this
    // stays correct even if some other parser starts writing a platform
    // later, instead of relying on that incidental fact.
    const imported = await pool.query(
      `SELECT DISTINCT platform FROM parser_results
        WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import' AND platform IS NOT NULL`,
      [caseId],
    );
    for (const row of imported.rows) if (row.platform) platforms.add(row.platform);
  } catch (e: any) {
    logger.warn('[ThreatHunting] parser_results.platform fallback unavailable:', e.message);
  }
  return platforms;
}

// SigmaHQ marks a rule 'deprecated' or 'unsupported' almost always because of
// excessive false positives — a detection that can't be defended is worthless
// in an evidentiary context, so these are skipped regardless of platform.
// 'experimental' rules run: they often cover a recent technique, and the cost
// of a false positive there is lower than the cost of an uncovered technique.
//
// Task 4 (docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-honest-
// counts.md) added sigma_rules.upstream_status, extracted at import/update
// from the rule's own YAML `status:` field (sigmaService.ts::parseRule) and
// backfilled for the pre-existing rules by scripts/backfillSigmaMetadata.js.
// This used to be a Postgres regex over the raw `content` column — cheaper
// than loading all 3999 rows into Node to re-parse YAML, but a heuristic that
// couldn't anchor to a line start cheaply and missed a quoted value
// (`status: "deprecated"`). An equality check on the parsed column has none
// of those edge cases, so this replaces the regex now that the column exists.
// NULL (no `status:` in the YAML) is treated as "not known-bad" — same
// behaviour as before this column existed.
const STATUS_EXCLUDES_HUNT = `(upstream_status IS NULL OR upstream_status NOT IN ('deprecated', 'unsupported'))`;

// Both Sigma hunt paths below used to run ONE query bounded by `LIMIT 200`
// and store `rows.length` as `match_count` — so a rule matching more than 200
// events silently reported exactly 200, presenting a SQL limit as a detection
// result. This splits the concern: an unbounded `COUNT(*)` for the true
// total, and a small bounded sample (`LIMIT 50` — the most `matched_events`
// ever renders) for the preview. Both queries share this one function so the
// WHERE/params can never drift between the count and the sample — each call
// site builds `shiftedWhere`/`allParams` once and passes them in here rather
// than reconstructing the predicate a second time.
async function huntMatches(
  pool: Pool,
  caseId: string,
  shiftedWhere: string,
  allParams: unknown[],
): Promise<{ matchCount: number; sample: any[] }> {
  const [countResult, sampleResult] = await Promise.all([
    pool.query(
      `SELECT COUNT(*)::int AS count
         FROM collection_timeline
        WHERE case_id = $1 AND (${shiftedWhere})`,
      allParams,
    ),
    pool.query(
      // Task 5 (docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-
      // honest-counts.md): `id` is selected here — it wasn't before — because
      // without it `matched_events` cannot point at any collection_timeline
      // row, making a click-through pivot impossible even though the table
      // has always had an `id` column. This is additive only: existing
      // consumers of `events`/`matched_events` read fields off the object by
      // name, so one more field on each row changes nothing for them.
      `SELECT id, timestamp, artifact_type, source, description, raw
         FROM collection_timeline
        WHERE case_id = $1 AND (${shiftedWhere})
        ORDER BY timestamp ASC
        LIMIT 50`,
      allParams,
    ),
  ]);
  return { matchCount: countResult.rows[0].count, sample: sampleResult.rows };
}

router.post('/sigma/hunt/:caseId', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { caseId } = req.params;
    const { ruleId } = req.body;
    if (!ruleId) return res.status(400).json({ error: 'ruleId est requis' });

    const pool = poolMig(req);

    const ruleResult = await pool.query(
      'SELECT * FROM sigma_rules WHERE id = $1',
      [ruleId],
    );
    if (ruleResult.rows.length === 0) return res.status(404).json({ error: 'Règle Sigma introuvable' });
    const rule = ruleResult.rows[0];

    const parsed = parseRule(rule.content);
    if (!parsed.valid || !parsed.parsed) {
      return res.status(400).json({ error: `Règle invalide : ${parsed.error}` });
    }

    const { where, params } = buildQuery(parsed.parsed);

    const allParams: unknown[] = [caseId, ...params];

    const shiftedWhere = where.replace(/\$(\d+)/g, (_m, n) => `$${parseInt(n) + 1}`);

    const { matchCount, sample: matchedEvents } = await huntMatches(pool, caseId, shiftedWhere, allParams);
    const sampleSize = matchedEvents.length;

    await pool.query(
      `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events, sample_size)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [caseId, ruleId, rule.name, matchCount, JSON.stringify(matchedEvents), sampleSize],
    );

    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_sigma_hunt', 'case', caseId,
      { rule_id: ruleId, rule_name: rule.name, match_count: matchCount }, req.ip);

    res.json({
      rule_name:  rule.name,
      match_count: matchCount,
      events:      matchedEvents,
      sample_size: sampleSize,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// Task 5 (docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-honest-
// counts.md): pivot from one hunt match into the full set of
// collection_timeline rows that produced it, for the "click a match, land on
// the SuperTimeline filtered to it" flow.
//
// `matched_events` (and the `/sigma/hunt` response's `events`) only ever
// carries a bounded sample — `sample_size`, capped at 50 by huntMatches()
// above. A rule that matched 5 342 events must not silently hand the caller
// 50 ids and let it believe that's everything: that's the exact
// LIMIT-as-result defect Task 1 fixed for the count. So this route does NOT
// read matched_events — it re-parses the rule that produced this hunt and
// replays its predicate against collection_timeline right now, unbounded.
// That's what makes the full id set (not just the sample) available, and
// nothing here is ever passed back through a URL: the caller gets it in the
// response body.
//
// This also means the answer reflects the CURRENT timeline, not a frozen
// snapshot from when the hunt ran. If rows were purged since (evidence
// re-ingested, a collection deleted, a case pruned), the id set legitimately
// shrinks — possibly to zero. Zero is reported explicitly (`count: 0` plus a
// human-readable `message`), never as a bare empty array a UI could render as
// a blank screen with no explanation.
//
// `:caseId` already runs through router.param('caseId', caseAccessParam)
// declared at the top of this file, so authentication and case-level access
// control are enforced before this handler ever executes. The query below
// additionally scopes the hunt lookup to that case_id — a caller with access
// to case A cannot use a hunt id belonging to case B to read case B's ids.
router.get('/sigma/hunt/:caseId/:huntId/timeline-ids', authenticate, async (req: express.Request, res: express.Response) => {
  try {
    const { caseId, huntId } = req.params;
    const pool = poolMig(req);

    const huntResult = await pool.query(
      `SELECT h.id, h.rule_id, h.rule_name, r.content
         FROM sigma_hunt_results h
         JOIN sigma_rules r ON r.id = h.rule_id
        WHERE h.id = $1 AND h.case_id = $2`,
      [huntId, caseId],
    );
    if (huntResult.rows.length === 0) {
      return res.status(404).json({ error: 'Chasse introuvable pour ce cas.' });
    }
    const hunt = huntResult.rows[0];

    const parsed = parseRule(hunt.content);
    if (!parsed.valid || !parsed.parsed) {
      return res.status(500).json({ error: `Règle invalide au moment du pivot : ${parsed.error}` });
    }

    const { where, params } = buildQuery(parsed.parsed);
    const allParams: unknown[] = [caseId, ...params];
    const shiftedWhere = where.replace(/\$(\d+)/g, (_m, n) => `$${parseInt(n, 10) + 1}`);

    const idsResult = await pool.query(
      `SELECT id FROM collection_timeline
        WHERE case_id = $1 AND (${shiftedWhere})
        ORDER BY timestamp ASC`,
      allParams,
    );
    const ids = idsResult.rows.map((r: any) => r.id);

    res.json({
      hunt_id:   hunt.id,
      rule_id:   hunt.rule_id,
      rule_name: hunt.rule_name,
      ids,
      count: ids.length,
      message: ids.length === 0
        ? "Aucun événement de la timeline ne correspond actuellement à cette chasse — ils ont peut-être été supprimés depuis."
        : null,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/sigma/scan-case/:caseId', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  const send = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const { caseId } = req.params;
    const pool = poolMig(req);

    const totalActiveResult = await pool.query('SELECT COUNT(*)::int AS count FROM sigma_rules WHERE is_active = true');
    const totalActive: number = totalActiveResult.rows[0].count;
    if (totalActive === 0) {
      send({ type: 'done', summary: [], rules_checked: 0, rules_matched: 0, total_matches: 0, message: 'Aucune règle Sigma active' });
      return res.end();
    }

    const platforms = await casePlatforms(pool, caseId);
    // Sorted so `collection_platform` in the `start` event (and the array
    // bound into the SQL below) has a stable order — `SELECT DISTINCT` makes
    // no ordering guarantee, and a UI/test comparing this array shouldn't
    // have to care about Postgres's scan order.
    const platformList = [...platforms].sort();
    // No recognisable platform anywhere in the case's evidence (a case with
    // no timeline yet, or one imported before platform detection existed):
    // do not guess which OS to scope to — apply no platform predicate at all,
    // rather than risk a false negative by excluding a real platform. The
    // `start` event still says so explicitly.
    //
    // Status is a different axis and stays applied even here: a rule marked
    // deprecated/unsupported upstream is defective regardless of which OS is
    // being hunted (SigmaHQ retires a rule almost always for excessive false
    // positives) — not knowing the platform is no reason to also run rules
    // already known to be bad.
    const noKnownPlatform = platformList.length === 0;

    let rulesResult;
    let skippedPlatform = 0;
    if (noKnownPlatform) {
      rulesResult = await pool.query(
        `SELECT * FROM sigma_rules
          WHERE is_active = true
            AND ${STATUS_EXCLUDES_HUNT}`,
      );
    } else {
      const platformMatchCount = await pool.query(
        `SELECT COUNT(*)::int AS count FROM sigma_rules
          WHERE is_active = true
            AND (logsource_product IS NULL OR logsource_product = ANY($1::text[]))`,
        [platformList],
      );
      skippedPlatform = totalActive - platformMatchCount.rows[0].count;

      rulesResult = await pool.query(
        `SELECT * FROM sigma_rules
          WHERE is_active = true
            AND (logsource_product IS NULL OR logsource_product = ANY($1::text[]))
            AND ${STATUS_EXCLUDES_HUNT}`,
        [platformList],
      );
    }

    // `start` carries the full picture — total active rules, how many were
    // scoped out by platform, and the platform set the decision was made
    // against — BEFORE checking whether anything is left to iterate. A rule
    // skipped in silence is indistinguishable from a rule that found nothing;
    // reporting 0-rules-evaluated without saying 3999 existed and N were
    // skipped for platform reasons would reintroduce exactly that defect.
    //
    // `rules_to_run` (Sigma hunt UI rebuild, 2026-08-11) is `rulesResult.rows
    // .length` — the exact count this run will iterate over, already
    // computed above. It's deliberately NOT derived by the UI as
    // `total - skipped_platform`: that arithmetic only accounts for the
    // platform axis and would overstate the true count whenever a
    // deprecated/unsupported rule (STATUS_EXCLUDES_HUNT, a separate axis)
    // also happens to match the case's platform. Sending the real number
    // costs nothing extra — the query already ran — and is what lets the
    // scope band state "406 rules will be evaluated, out of 3999" honestly.
    send({
      type: 'start',
      total: totalActive,
      rules_to_run: rulesResult.rows.length,
      skipped_platform: skippedPlatform,
      collection_platform: noKnownPlatform ? null : platformList,
    });

    if (rulesResult.rows.length === 0) {
      send({
        type: 'done', summary: [], rules_checked: 0, rules_matched: 0, total_matches: 0,
        message: 'Aucune règle Sigma applicable à la plateforme de ce cas',
      });
      return res.end();
    }

    const summary: any[] = [];
    // Live tally for the UI's progress band — Sigma hunt UI rebuild,
    // 2026-08-11. A multi-minute sweep over 400+ rules used to tell the
    // analyst only "264/425 — rule_name": no way to judge, mid-run, whether
    // anything worth stopping for has been found yet. `matched_so_far` /
    // `critical_so_far` are cumulative counts over every rule fully
    // evaluated BEFORE the one this `progress` frame names (the current
    // rule's own outcome isn't known until after it runs) — deliberately
    // additive to the existing `progress` payload so nothing that reads
    // current/total/name today breaks.
    let matchedSoFar = 0;
    let criticalSoFar = 0;
    for (let i = 0; i < rulesResult.rows.length; i++) {
      const rule = rulesResult.rows[i];
      send({
        type: 'progress', current: i + 1, total: rulesResult.rows.length, name: rule.name,
        matched_so_far: matchedSoFar, critical_so_far: criticalSoFar,
      });

      const parsed = parseRule(rule.content);
      if (!parsed.valid || !parsed.parsed) {
        summary.push({
          rule_id: rule.id, rule_name: rule.name, match_count: 0, error: parsed.error,
          level: rule.level, mitre_techniques: rule.mitre_techniques,
        });
        continue;
      }
      try {
        const { where, params } = buildQuery(parsed.parsed);
        const allParams: unknown[] = [caseId, ...params];
        const shiftedWhere = where.replace(/\$(\d+)/g, (_m: string, n: string) => `$${parseInt(n) + 1}`);

        const { matchCount, sample } = await huntMatches(pool, caseId, shiftedWhere, allParams);
        if (matchCount > 0) {
          await pool.query(
            `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events, sample_size)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [caseId, rule.id, rule.name, matchCount, JSON.stringify(sample), sample.length],
          );
          matchedSoFar++;
          if (rule.level === 'critical') criticalSoFar++;
        }
        summary.push({
          rule_id: rule.id, rule_name: rule.name, match_count: matchCount,
          level: rule.level, mitre_techniques: rule.mitre_techniques,
        });
      } catch (err: any) {
        summary.push({
          rule_id: rule.id, rule_name: rule.name, match_count: 0, error: err.message,
          level: rule.level, mitre_techniques: rule.mitre_techniques,
        });
      }
    }

    const rulesMatched = summary.filter(s => s.match_count > 0).length;
    const totalMatches = summary.reduce((acc, s) => acc + (s.match_count || 0), 0);
    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_sigma_scan_case', 'case', caseId,
      { rules_checked: rulesResult.rows.length, rules_matched: rulesMatched, total_matches: totalMatches }, req.ip);

    send({ type: 'done', case_id: caseId, rules_checked: rulesResult.rows.length, rules_matched: rulesMatched, total_matches: totalMatches, summary });
    res.end();
  } catch (e: any) {
    send({ type: 'error', error: e.message });
    res.end();
  }
});

// level / mitre_techniques joined in from sigma_rules (Sigma hunt UI rebuild,
// 2026-08-11) — the results table needs them to sort by severity and show a
// technique without shipping the full rule set (3999 rows) to the browser
// just to look two fields up client-side. LEFT JOIN, not INNER: rule_id
// cascades on delete today (so an orphan row shouldn't occur in practice),
// but a hunt result must still render — with level/mitre_techniques simply
// absent, never with the whole row silently dropped — if that ever changes.
router.get('/sigma/hunts/:caseId', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await poolMig(req).query(
      `SELECT h.id, h.rule_id, h.rule_name, h.match_count, h.matched_events, h.sample_size, h.hunted_at,
              r.level, r.mitre_techniques
         FROM sigma_hunt_results h
         LEFT JOIN sigma_rules r ON r.id = h.rule_id
        WHERE h.case_id = $1
        ORDER BY h.hunted_at DESC
        LIMIT 50`,
      [caseId],
    );
    res.json({ hunts: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

const GITHUB_REPOS_CONFIG: Record<string, Array<{
  owner: string; repo: string; branch: string; label: string; description: string;
}>> = {
  yara: [
    { owner: 'Neo23x0',    repo: 'signature-base', branch: 'master',
      label: 'Neo23x0 / signature-base',
      description: 'Référence YARA par Florian Roth — malware, exploits, APT (1 000+ règles)' },
    { owner: 'Yara-Rules', repo: 'rules',           branch: 'master',
      label: 'Yara-Rules / rules',
      description: 'Collection communautaire officielle — crypto, CVE, malware (800+ règles)' },
  ],
  sigma: [
    { owner: 'SigmaHQ', repo: 'sigma', branch: 'master',
      label: 'SigmaHQ / sigma',
      description: 'Règles Sigma officielles — Windows, Linux, Cloud, Web (3 000+ règles)' },
  ],
};

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    'User-Agent': 'ForensicLab-Heimdall/1.0',
    'Accept':     'application/vnd.github.v3+json',
  };
  if (process.env.GITHUB_TOKEN) {
    h['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return h;
}

function fetchJson(url: string, headers: Record<string, string>): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = nodeHttps.get(url, { headers }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchJson(res.headers.location!, headers).then(resolve).catch(reject);
        res.resume(); return;
      }
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode! >= 200 && res.statusCode! < 300) {
          try { resolve(JSON.parse(body)); } catch { resolve(body); }
        } else {
          reject(new Error(`GitHub API ${res.statusCode}: ${body.slice(0, 300)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, () => { req.destroy(); reject(new Error('Timeout GitHub API')); });
  });
}

function fetchText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = nodeHttps.get(url, { headers: { 'User-Agent': 'ForensicLab-Heimdall/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchText(res.headers.location!).then(resolve).catch(reject);
        res.resume(); return;
      }
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode! >= 200 && res.statusCode! < 300) resolve(body);
        else reject(new Error(`HTTP ${res.statusCode} — ${url}`));
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Timeout téléchargement règle')); });
  });
}

router.get('/github/repos', authenticate, (req, res) => {
  const type = (req.query.type as string) === 'sigma' ? 'sigma' : 'yara';
  res.json({ repos: GITHUB_REPOS_CONFIG[type] ?? [] });
});

router.get('/github/tree', authenticate, async (req, res) => {
  try {
    const { owner, repo, type } = req.query as Record<string, string>;
    const branch = (req.query.branch as string) || 'master';
    if (!owner || !repo) return res.status(400).json({ error: 'owner et repo sont requis' });

    const headers = ghHeaders();

    const branchData = await fetchJson(
      `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`,
      headers,
    );
    const sha = branchData?.commit?.sha as string | undefined;
    if (!sha) return res.status(400).json({ error: `Branche "${branch}" introuvable dans ${owner}/${repo}` });

    const treeData = await fetchJson(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${sha}?recursive=1`,
      headers,
    );

    const exts = type === 'sigma' ? ['.yml', '.yaml'] : ['.yar', '.yara'];
    const files: Array<{ path: string; name: string; size: number }> = ((treeData.tree as any[]) || [])
      .filter((f: any) => f.type === 'blob' && exts.some((e) => f.path.toLowerCase().endsWith(e)))
      .map((f: any) => ({
        path: f.path as string,
        name: (f.path as string).split('/').pop()!,
        size: (f.size as number) ?? 0,
      }));

    res.json({ files, truncated: treeData.truncated ?? false, total: files.length });
  } catch (e: any) {
    logger.warn('[GitHub] tree error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post('/github/import', authenticate, (requireRole as any)('admin'),
  async (req: express.Request, res: express.Response) => {
  try {
    const { owner, repo, type } = req.body as Record<string, any>;
    const branch: string = req.body.branch ?? 'master';
    const paths: string[] = req.body.paths ?? [];

    if (!owner || !repo || !type) return res.status(400).json({ error: 'owner, repo et type sont requis' });
    if (!Array.isArray(paths) || paths.length === 0) return res.status(400).json({ error: 'paths est requis' });
    if (paths.length > 50) return res.status(400).json({ error: 'Maximum 50 règles par import' });

    const userId = (req as AuthRequest).user?.id;
    const pool   = poolMig(req);

    let imported = 0;
    let skipped  = 0;
    const errors: string[] = [];

    for (const filePath of paths) {
      const ruleName = filePath.split('/').pop()?.replace(/\.(yar|yara|yml|yaml)$/i, '') ?? filePath;
      try {
        const rawUrl  = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
        const content = await fetchText(rawUrl);

        if (type === 'yara') {
          const v = await validateRule(content);
          if (!v.valid) { skipped++; errors.push(`${ruleName}: ${v.error}`); continue; }
          await pool.query(
            `INSERT INTO yara_rules (name, description, content, author_id, tags)
             VALUES ($1, $2, $3, $4, $5)`,
            [ruleName, `Importé depuis ${owner}/${repo}`, content, userId,
             ['github', owner.toLowerCase()]],
          );
        } else {
          const v = parseRule(content);
          if (!v.valid) { skipped++; errors.push(`${ruleName}: ${v.error}`); continue; }
          await pool.query(
            `INSERT INTO sigma_rules (name, description, content, author_id, logsource_category, logsource_product, tags,
                                       level, mitre_techniques, upstream_status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [ruleName,
             (v.parsed as any)?.description ?? `Importé depuis ${owner}/${repo}`,
             content, userId,
             v.logsourceCategory ?? null, v.logsourceProduct ?? null,
             ['github', owner.toLowerCase()],
             v.level ?? null, v.mitreTechniques ?? [], v.upstreamStatus ?? null],
          );
        }
        imported++;
      } catch (e: any) {
        skipped++;
        errors.push(`${filePath.split('/').pop()}: ${e.message}`);
      }
    }

    await auditLog(userId, `github_import_${type}`, 'system', null as any,
      { repo: `${owner}/${repo}`, branch, imported, skipped }, req.ip);

    res.json({ imported, skipped, errors });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

function downloadZip(url: string, dest: string, hops = 0): Promise<void> {
  if (hops > 5) return Promise.reject(new Error('Trop de redirections'));
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const cleanup = () => { try { fs.unlinkSync(dest); } catch {} };
    nodeHttps.get(url, { headers: { 'User-Agent': 'ForensicLab-Heimdall/1.0' } }, (res) => {
      const loc = res.headers.location;
      if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) && loc) {
        file.close(); cleanup();
        downloadZip(loc, dest, hops + 1).then(resolve).catch(reject);
        res.resume(); return;
      }
      if (res.statusCode !== 200) {
        file.close(); cleanup();
        reject(new Error(`HTTP ${res.statusCode}`));
        res.resume(); return;
      }
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', (e) => { cleanup(); reject(e); });
    }).on('error', (e) => { cleanup(); reject(e); })
      .setTimeout(180_000, function (this: any) { this.destroy(); reject(new Error('Timeout téléchargement ZIP')); });
  });
}

const SKIP_DIRS = new Set(['.github', '.git', 'tests', 'test', 'docs', 'documentation', 'examples', 'example']);

function walkFiles(dir: string, exts: string[]): string[] {
  const results: string[] = [];
  function walk(current: string) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(current, e.name);
      if (e.isDirectory()) {

        if (e.name.startsWith('.') || SKIP_DIRS.has(e.name.toLowerCase())) continue;
        walk(full);
      } else if (exts.some(x => e.name.toLowerCase().endsWith(x))) {
        results.push(full);
      }
    }
  }
  walk(dir);
  return results;
}

router.post('/github/import-zip', authenticate, (requireRole as any)('admin'),
  async (req: express.Request, res: express.Response) => {
    const { owner, repo, type } = req.body as Record<string, any>;
    const branch: string = req.body.branch ?? 'master';

    if (!owner || !repo || !type) {
      return res.status(400).json({ error: 'owner, repo et type sont requis' });
    }

    const userId = (req as AuthRequest).user?.id;
    const pool   = poolMig(req);

    const tmpZip = path.join(os.tmpdir(), `heimdall_${uuidv4()}.zip`);
    const tmpDir = path.join(os.tmpdir(), `heimdall_${uuidv4()}`);

    try {

      const zipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball/${branch}`;
      logger.info(`[ZipImport] Téléchargement ${zipUrl}`);
      await downloadZip(zipUrl, tmpZip);

      fs.mkdirSync(tmpDir, { recursive: true });
      const unzipResult = spawnSync('unzip', ['-q', tmpZip, '-d', tmpDir], { timeout: 120_000 });
      if (unzipResult.status !== 0) {
        return res.status(500).json({ error: 'Échec de l\'extraction ZIP' });
      }

      const exts  = type === 'sigma' ? ['.yml', '.yaml'] : ['.yar', '.yara'];
      const files = walkFiles(tmpDir, exts);
      logger.info(`[ZipImport] ${files.length} fichiers trouvés dans ${owner}/${repo}`);

      let imported = 0;
      let skipped  = 0;
      const errors: string[] = [];

      for (const filePath of files) {
        const ruleName = path.basename(filePath, path.extname(filePath));
        try {
          const content = fs.readFileSync(filePath, 'utf8');

          if (type === 'yara') {
            const v = await validateRule(content);
            if (!v.valid) { skipped++; if (errors.length < 50) errors.push(`${ruleName}: ${v.error}`); continue; }
            await pool.query(
              `INSERT INTO yara_rules (name, description, content, author_id, tags)
               VALUES ($1, $2, $3, $4, $5)`,
              [ruleName, `Importé depuis ${owner}/${repo}`, content, userId, ['github', owner.toLowerCase()]],
            );
          } else {
            const v = parseRule(content);
            if (!v.valid) { skipped++; if (errors.length < 50) errors.push(`${ruleName}: ${v.error}`); continue; }
            await pool.query(
              `INSERT INTO sigma_rules (name, description, content, author_id, logsource_category, logsource_product, tags,
                                         level, mitre_techniques, upstream_status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
              [
                ruleName,
                (v.parsed as any)?.description ?? `Importé depuis ${owner}/${repo}`,
                content, userId,
                v.logsourceCategory ?? null,
                v.logsourceProduct  ?? null,
                ['github', owner.toLowerCase()],
                v.level ?? null,
                v.mitreTechniques ?? [],
                v.upstreamStatus ?? null,
              ],
            );
          }
          imported++;
        } catch (e: any) {
          skipped++;
          if (errors.length < 50) errors.push(`${ruleName}: ${e.message}`);
        }
      }

      await auditLog(userId, `github_zip_import_${type}`, 'system', null as any,
        { repo: `${owner}/${repo}`, branch, total: files.length, imported, skipped }, req.ip);

      logger.info(`[ZipImport] Terminé — ${imported} importées, ${skipped} ignorées`);
      res.json({ total: files.length, imported, skipped, errors });

    } catch (e: any) {
      logger.error('[ZipImport] Erreur :', e.message);
      res.status(500).json({ error: e.message });
    } finally {
      try { fs.unlinkSync(tmpZip); } catch {}
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  },
);

// ── Sysmon community config proxy (avoids browser CORS/CSP to github.com) ────
// Server-side fetch with a strict allowlist (no arbitrary URL → no SSRF).
const SYSMON_CATALOG: Record<string, { url: string; filename: string; name: string; author: string; license: string }> = {
  'swiftonsecurity':           { url: 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',       filename: 'swiftonsecurity-sysmonconfig.xml',          name: 'SwiftOnSecurity · sysmon-config',            author: '@SwiftOnSecurity',    license: 'Domaine public (CC0-like)' },
  'sysmon-modular':            { url: 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml',                  filename: 'sysmon-modular-sysmonconfig.xml',           name: 'Olaf Hartong · sysmon-modular',              author: '@olafhartong',        license: 'GPL-3.0' },
  'neo23x0':                   { url: 'https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export.xml',                filename: 'neo23x0-sysmonconfig.xml',                  name: 'Florian Roth · Neo23x0/sysmon-config',       author: '@Neo23x0 (Nextron)',  license: 'Fork SwiftOnSecurity' },
  'ion-storm':                 { url: 'https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml',              filename: 'ion-storm-sysmonconfig.xml',                name: 'ion-storm · sysmon-config',                  author: '@ion-storm',          license: 'CC BY 4.0' },
  'sysmon-modular-filedelete': { url: 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-with-filedelete.xml', filename: 'sysmon-modular-filedelete-sysmonconfig.xml', name: 'Olaf Hartong · sysmon-modular (file-delete)', author: '@olafhartong',       license: 'GPL-3.0' },
};

function httpsGetText(url: string, redirects = 0): Promise<string> {
  return new Promise((resolve, reject) => {
    nodeHttps.get(url, { headers: { 'User-Agent': 'Heimdall-DFIR' } }, (resp) => {
      const sc = resp.statusCode || 0;
      if (sc >= 300 && sc < 400 && resp.headers.location && redirects < 3) {
        resp.resume();
        return httpsGetText(resp.headers.location, redirects + 1).then(resolve, reject);
      }
      if (sc !== 200) { resp.resume(); return reject(new Error('HTTP ' + sc)); }
      let data = '';
      resp.setEncoding('utf8');
      resp.on('data', (c) => { data += c; });
      resp.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Import a community Sysmon config INTO the platform library (server-side store).
router.post('/sysmon/configs/:key/import', authenticate, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const cfg = SYSMON_CATALOG[req.params.key];
  if (!cfg) return res.status(404).json({ error: 'Configuration Sysmon inconnue' });
  try {
    const pool = getPool(req);
    await ensureTables(pool);
    const xml = await httpsGetText(cfg.url);
    if (!xml || !xml.toLowerCase().includes('<sysmon')) throw new Error('Contenu inattendu (XML Sysmon non détecté)');
    await pool.query(
      `INSERT INTO sysmon_library (config_key, name, author, license, source_url, content, imported_by, imported_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())
       ON CONFLICT (config_key) DO UPDATE SET content = $6, source_url = $5, imported_by = $7, updated_at = NOW()`,
      [req.params.key, cfg.name, cfg.author, cfg.license, cfg.url, xml, req.user!.id]
    );
    await auditLog(req.user!.id, 'download_sysmon_config', 'sysmon', req.params.key, { url: cfg.url, action: 'import', bytes: xml.length }, req.ip);
    res.json({ ok: true, key: req.params.key, bytes: xml.length });
  } catch (e: any) {
    logger.error('[sysmon import]', e.message);
    res.status(502).json({ error: 'Import impossible depuis github.com : ' + e.message });
  }
});

// List imported Sysmon configs (platform library).
router.get('/sysmon/library', authenticate, async (req: AuthRequest, res: any) => {
  try {
    const r = await getPool(req).query(
      `SELECT config_key, name, author, license, source_url, length(content) AS size, imported_at, updated_at
       FROM sysmon_library ORDER BY imported_at DESC`
    );
    res.json({ configs: r.rows });
  } catch (e: any) {
    logger.error('[sysmon library]', e.message);
    res.json({ configs: [] });
  }
});

// Download the STORED content (e.g. to deploy on an endpoint).
router.get('/sysmon/library/:key/content', authenticate, async (req: AuthRequest, res: any) => {
  try {
    const r = await getPool(req).query('SELECT name, content FROM sysmon_library WHERE config_key = $1', [req.params.key]);
    if (!r.rows.length) return res.status(404).json({ error: 'Non importé' });
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.key}-sysmonconfig.xml"`);
    res.send(r.rows[0].content);
  } catch (e: any) { res.status(500).json({ error: 'Erreur serveur' }); }
});

router.delete('/sysmon/library/:key', authenticate, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  try { await getPool(req).query('DELETE FROM sysmon_library WHERE config_key = $1', [req.params.key]); res.json({ ok: true }); }
  catch (e: any) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ── "Run all" — background orchestration of every engine on one case ─────────
// Orchestrator lives in services/runAllService so the parsing pipeline can also
// auto-launch it (shared job state). Detached server-side job; survives leaving
// the page; reuses existing endpoints via internal HTTP with a short-lived JWT.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { startRunAll, getRunAllJob } = require('../services/runAllService');

// "Tout lancer" UI rebuild (2026-08-11) — its central defect was launching
// nine engines without ever saying what any of them would actually run
// against. Two of those nine — YARA and Sigma — have a "N rules over M
// items" substrate the other seven (Hayabusa, persistence, etc.) don't carry
// (they are fixed built-in analyses, not a user-editable rule corpus), so
// this preview is scoped to exactly those two rather than inventing a
// figure for engines that have none. Read-only: no scan runs, no
// yara_scan_results/sigma_hunt_results row is written, nothing is deleted —
// safe to call on every case switch, before the analyst has decided to
// launch anything.
//
// Sigma's half reuses `casePlatforms()`/`STATUS_EXCLUDES_HUNT` — the exact
// same scoping policy `/sigma/scan-case/:caseId` applies at run time (see its
// own comment above) — so the number shown here is never a separate guess
// that could drift from what a launch would actually evaluate.
router.get('/run-all/:caseId/scope', authenticate, async (req: express.Request, res: express.Response) => {
  try {
    const { caseId } = req.params;
    const pool = poolMig(req);

    const [yaraRulesResult, evidenceCountResult, sigmaTotalResult, timelineCountResult] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS count FROM yara_rules WHERE is_active = true'),
      pool.query('SELECT COUNT(*)::int AS count FROM evidence WHERE case_id = $1', [caseId]),
      pool.query('SELECT COUNT(*)::int AS count FROM sigma_rules WHERE is_active = true'),
      pool.query('SELECT COUNT(*)::int AS count FROM collection_timeline WHERE case_id = $1', [caseId]),
    ]);

    const totalActiveSigma: number = sigmaTotalResult.rows[0].count;
    let rulesToRun = 0;
    let collectionPlatform: string[] | null = null;
    if (totalActiveSigma > 0) {
      const platforms = await casePlatforms(pool, caseId);
      const platformList = [...platforms].sort();
      const noKnownPlatform = platformList.length === 0;
      collectionPlatform = noKnownPlatform ? null : platformList;

      const rulesToRunResult = noKnownPlatform
        ? await pool.query(`SELECT COUNT(*)::int AS count FROM sigma_rules WHERE is_active = true AND ${STATUS_EXCLUDES_HUNT}`)
        : await pool.query(
            `SELECT COUNT(*)::int AS count FROM sigma_rules
              WHERE is_active = true
                AND (logsource_product IS NULL OR logsource_product = ANY($1::text[]))
                AND ${STATUS_EXCLUDES_HUNT}`,
            [platformList],
          );
      rulesToRun = rulesToRunResult.rows[0].count;
    }

    res.json({
      yara: {
        rules: yaraRulesResult.rows[0].count,
        evidence_files: evidenceCountResult.rows[0].count,
      },
      sigma: {
        rules_to_run: rulesToRun,
        total_active: totalActiveSigma,
        skipped: Math.max(0, totalActiveSigma - rulesToRun),
        total_events: timelineCountResult.rows[0].count,
        collection_platform: collectionPlatform,
      },
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/run-all/:caseId', authenticate, (requireRole as any)('analyst', 'admin'), async (req: AuthRequest, res: any) => {
  const { caseId } = req.params;
  const existing = await getRunAllJob(caseId);
  if (existing && existing.status === 'running') return res.json(existing);
  const job = await startRunAll(caseId, req.user, 'manual');
  await auditLog(req.user!.id, 'run_yara_scan', 'case', caseId, { action: 'run_all_engines' }, req.ip);
  res.status(202).json(job);
});

router.get('/run-all/:caseId/status', authenticate, async (req: AuthRequest, res: any) => {
  res.json(await getRunAllJob(req.params.caseId));
});

export = router;
