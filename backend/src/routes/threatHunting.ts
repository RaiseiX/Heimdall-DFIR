
import express from 'express';
import * as nodeHttps from 'https';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import logger from '../config/logger';
import type { Pool } from 'pg';
import { authenticate, requireRole, auditLog } from '../middleware/auth';
import type { AuthRequest } from '../types/index';
import { validateRule, scanEvidence } from '../services/yaraService';
import { parseRule, buildQuery } from '../services/sigmaService';

const router = express.Router();

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

    const validation = validateRule(content);
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
      const validation = validateRule(content);
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
      const scanResult = scanEvidence(ev.file_path, rule.content);
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

    send({ type: 'start', total: evResult.rows.length, rules: rulesResult.rows.length });

    await pool.query('DELETE FROM yara_scan_results WHERE case_id = $1', [caseId]);

    const YARA_MAX_SIZE = 500 * 1024 * 1024;
    const summary: any[] = [];
    for (let i = 0; i < evResult.rows.length; i++) {
      const ev = evResult.rows[i];
      send({ type: 'progress', current: i + 1, total: evResult.rows.length, name: ev.name });

      if (ev.evidence_type === 'memory' || Number(ev.file_size) > YARA_MAX_SIZE) {
        const reason = ev.evidence_type === 'memory' ? 'dump mémoire' : 'fichier > 500 MB';
        logger.info(`[YARA] Skip ${ev.name}: ${reason}`);
        summary.push({ evidence_id: ev.id, evidence_name: ev.name, matches: [], skipped: true, reason });
        continue;
      }

      const fileMatches: any[] = [];
      for (const rule of rulesResult.rows) {
        const scanResult = scanEvidence(ev.file_path, rule.content);
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
    }

    const scanned = summary.filter(s => !s.skipped).length;
    const skipped = summary.filter(s => s.skipped).length;
    const totalMatches = summary.reduce((acc, s) => acc + s.matches.length, 0);
    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_yara_scan', 'case', caseId,
      { files_scanned: scanned, files_skipped: skipped, rules_checked: rulesResult.rows.length, match_count: totalMatches }, req.ip);

    send({ type: 'done', case_id: caseId, files_scanned: scanned, files_skipped: skipped, summary });
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

router.get('/sigma/rules', authenticate, async (req, res) => {
  try {
    const result = await poolMig(req).query(
      `SELECT r.id, r.name, r.description, r.content, r.logsource_category, r.logsource_product,
              r.tags, r.is_active, r.created_at, r.updated_at,
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
    const tagsArr = Array.isArray(tags) ? tags : [];
    const result = await poolMig(req).query(
      `INSERT INTO sigma_rules
         (name, description, content, author_id, logsource_category, logsource_product, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, description, logsource_category, logsource_product, tags, is_active, created_at`,
      [
        name.trim(),
        validation.parsed?.description ?? null,
        content,
        userId,
        validation.logsourceCategory ?? null,
        validation.logsourceProduct ?? null,
        tagsArr,
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
    if (content !== undefined) {
      const validation = parseRule(content);
      if (!validation.valid) return res.status(400).json({ error: validation.error });
      logsourceCat  = validation.logsourceCategory ?? null;
      logsourceProd = validation.logsourceProduct ?? null;
    }

    const pool = poolMig(req);
    const current = await pool.query('SELECT * FROM sigma_rules WHERE id = $1', [id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Règle introuvable' });

    const r = current.rows[0];
    const result = await pool.query(
      `UPDATE sigma_rules
          SET name = $1, content = $2, tags = $3, is_active = $4,
              logsource_category = $5, logsource_product = $6, updated_at = NOW()
        WHERE id = $7
        RETURNING id, name, description, logsource_category, logsource_product, tags, is_active, updated_at`,
      [
        name ?? r.name,
        content ?? r.content,
        Array.isArray(tags) ? tags : r.tags,
        is_active !== undefined ? is_active : r.is_active,
        content ? logsourceCat : r.logsource_category,
        content ? logsourceProd : r.logsource_product,
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

    const query = `
      SELECT timestamp, artifact_type, source, description, raw
        FROM collection_timeline
       WHERE case_id = $1 AND (${shiftedWhere})
       ORDER BY timestamp ASC
       LIMIT 200
    `;

    const huntResult = await pool.query(query, allParams);
    const matchCount  = huntResult.rows.length;
    const matchedEvents = huntResult.rows.slice(0, 50);

    await pool.query(
      `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events)
       VALUES ($1, $2, $3, $4, $5)`,
      [caseId, ruleId, rule.name, matchCount, JSON.stringify(matchedEvents)],
    );

    const userId = (req as AuthRequest).user?.id;
    await auditLog(userId, 'run_sigma_hunt', 'case', caseId,
      { rule_id: ruleId, rule_name: rule.name, match_count: matchCount }, req.ip);

    res.json({
      rule_name:  rule.name,
      match_count: matchCount,
      events:      huntResult.rows,
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

    const rulesResult = await pool.query('SELECT * FROM sigma_rules WHERE is_active = true');
    if (rulesResult.rows.length === 0) {
      send({ type: 'done', summary: [], rules_checked: 0, rules_matched: 0, total_matches: 0, message: 'Aucune règle Sigma active' });
      return res.end();
    }

    send({ type: 'start', total: rulesResult.rows.length });

    const summary: any[] = [];
    for (let i = 0; i < rulesResult.rows.length; i++) {
      const rule = rulesResult.rows[i];
      send({ type: 'progress', current: i + 1, total: rulesResult.rows.length, name: rule.name });

      const parsed = parseRule(rule.content);
      if (!parsed.valid || !parsed.parsed) {
        summary.push({ rule_id: rule.id, rule_name: rule.name, match_count: 0, error: parsed.error });
        continue;
      }
      try {
        const { where, params } = buildQuery(parsed.parsed);
        const allParams: unknown[] = [caseId, ...params];
        const shiftedWhere = where.replace(/\$(\d+)/g, (_m: string, n: string) => `$${parseInt(n) + 1}`);

        const huntResult = await pool.query(
          `SELECT timestamp, artifact_type, source, description, raw
             FROM collection_timeline
            WHERE case_id = $1 AND (${shiftedWhere})
            ORDER BY timestamp ASC
            LIMIT 200`,
          allParams,
        );
        const matchCount = huntResult.rows.length;
        if (matchCount > 0) {
          await pool.query(
            `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events)
             VALUES ($1, $2, $3, $4, $5)`,
            [caseId, rule.id, rule.name, matchCount, JSON.stringify(huntResult.rows.slice(0, 50))],
          );
        }
        summary.push({ rule_id: rule.id, rule_name: rule.name, match_count: matchCount });
      } catch (err: any) {
        summary.push({ rule_id: rule.id, rule_name: rule.name, match_count: 0, error: err.message });
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

router.get('/sigma/hunts/:caseId', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await poolMig(req).query(
      `SELECT id, rule_id, rule_name, match_count, matched_events, hunted_at
         FROM sigma_hunt_results
        WHERE case_id = $1
        ORDER BY hunted_at DESC
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

router.post('/github/import', authenticate, (requireRole as any)('analyst', 'admin'),
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
          const v = validateRule(content);
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
            `INSERT INTO sigma_rules (name, description, content, author_id, logsource_category, logsource_product, tags)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [ruleName,
             (v.parsed as any)?.description ?? `Importé depuis ${owner}/${repo}`,
             content, userId,
             v.logsourceCategory ?? null, v.logsourceProduct ?? null,
             ['github', owner.toLowerCase()]],
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
      .setTimeout(180_000, function () { this.destroy(); reject(new Error('Timeout téléchargement ZIP')); });
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

router.post('/github/import-zip', authenticate, (requireRole as any)('analyst', 'admin'),
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
            const v = validateRule(content);
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
              `INSERT INTO sigma_rules (name, description, content, author_id, logsource_category, logsource_product, tags)
               VALUES ($1, $2, $3, $4, $5, $6, $7)`,
              [
                ruleName,
                (v.parsed as any)?.description ?? `Importé depuis ${owner}/${repo}`,
                content, userId,
                v.logsourceCategory ?? null,
                v.logsourceProduct  ?? null,
                ['github', owner.toLowerCase()],
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

export = router;
