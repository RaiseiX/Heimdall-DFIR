
import { Pool } from 'pg';
import logger from '../config/logger';
import { scanEvidence } from './yaraService';
import { parseRule, buildQuery } from './sigmaService';
import { correlateCase } from './taxiiService';
import { computeTriageScores, saveTriageScores } from './triageScoreService';

export interface SoarRunResult {
  case_id:                  string;
  triggered_by:             string;
  alerts_generated:         number;
  yara_matches:             number;
  sigma_matches:            number;
  threat_intel_correlations: number;
  triage_criticals:         number;
  duration_ms:              number;
}

interface AlertRow {
  type:         string;
  severity:     string;
  title:        string;
  description:  string;
  details:      Record<string, unknown>;
  source:       string;
  triggered_by: string;
}

async function runYara(
  caseId: string,
  pool: Pool,
  triggeredBy: string,
): Promise<{ alerts: AlertRow[]; matches: number }> {
  const [evRes, rulesRes] = await Promise.all([
    pool.query(
      `SELECT id, file_path, name FROM evidence
       WHERE case_id = $1 AND scan_status != 'quarantined'
         AND file_path IS NOT NULL`,
      [caseId],
    ),
    pool.query(`SELECT id, name, content FROM yara_rules WHERE is_active = TRUE`),
  ]);

  if (!rulesRes.rows.length || !evRes.rows.length) return { alerts: [], matches: 0 };

  const ruleMap = new Map<string, { ruleId: string; evidence: string[]; count: number }>();
  let totalMatches = 0;

  for (const ev of evRes.rows) {
    for (const rule of rulesRes.rows) {
      try {
        const result = scanEvidence(ev.file_path, rule.content);
        if (!result.matched) continue;

        totalMatches++;
        await pool.query(
          `INSERT INTO yara_scan_results (evidence_id, case_id, rule_id, rule_name, matched_strings)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT DO NOTHING`,
          [ev.id, caseId, rule.id, rule.name, JSON.stringify(result.strings)],
        );

        const existing = ruleMap.get(rule.name) || { ruleId: rule.id, evidence: [], count: 0 };
        existing.evidence.push(ev.name);
        existing.count++;
        ruleMap.set(rule.name, existing);
      } catch (_e) {}
    }
  }

  const alerts: AlertRow[] = [];
  for (const [ruleName, info] of ruleMap) {
    alerts.push({
      type: 'yara',
      severity: 'high',
      title: `YARA: ${ruleName}`,
      description: `Règle "${ruleName}" détectée sur ${info.count} fichier${info.count > 1 ? 's' : ''}.`,
      details: { rule_name: ruleName, evidence_names: info.evidence, match_count: info.count },
      source: ruleName,
      triggered_by: triggeredBy,
    });
  }
  return { alerts, matches: totalMatches };
}

async function runSigma(
  caseId: string,
  pool: Pool,
  triggeredBy: string,
): Promise<{ alerts: AlertRow[]; matches: number }> {
  const rulesRes = await pool.query(
    `SELECT id, name, content, tags FROM sigma_rules WHERE is_active = TRUE`,
  );
  if (!rulesRes.rows.length) return { alerts: [], matches: 0 };

  const alerts: AlertRow[] = [];
  let totalMatches = 0;

  for (const rule of rulesRes.rows) {
    try {
      const parsed = parseRule(rule.content);
      if (!parsed.valid || !parsed.parsed) continue;

      const { where, params } = buildQuery(parsed.parsed as any);
      if (!where) continue;

      const shiftedWhere = where.replace(/\$(\d+)/g, (_: string, n: string) => `$${parseInt(n, 10) + 1}`);

      const res = await pool.query(
        `SELECT timestamp, artifact_type, source, description, raw
         FROM collection_timeline
         WHERE case_id = $1 AND (${shiftedWhere})
         LIMIT 50`,
        [caseId, ...params],
      );
      if (!res.rows.length) continue;

      totalMatches += res.rows.length;

      await pool.query(
        `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING`,
        [caseId, rule.id, rule.name, res.rows.length, JSON.stringify(res.rows.slice(0, 50))],
      );

      const tags: string[] = Array.isArray(rule.tags) ? rule.tags : [];
      const severity = tags.some((t: string) => t.includes('critical')) ? 'critical'
                     : tags.some((t: string) => t.includes('high'))     ? 'high'
                     : 'medium';

      alerts.push({
        type: 'sigma',
        severity,
        title: `Sigma: ${rule.name}`,
        description: `Règle "${rule.name}" a matché ${res.rows.length} événement${res.rows.length > 1 ? 's' : ''}.`,
        details: { rule_name: rule.name, match_count: res.rows.length, sample_events: res.rows.slice(0, 3) },
        source: rule.name,
        triggered_by: triggeredBy,
      });
    } catch (e: any) {
      logger.warn(`[SOAR/Sigma] "${rule.name}": ${e.message}`);
    }
  }
  return { alerts, matches: totalMatches };
}

export async function runSoar(
  caseId: string,
  pool: Pool,
  triggeredBy = 'manual',
  io?: any,
): Promise<SoarRunResult> {
  const t0 = Date.now();
  let yaraMatches = 0;
  let sigmaMatches = 0;
  let threatIntelCorrelations = 0;
  let triageCriticals = 0;
  const allAlerts: AlertRow[] = [];

  await Promise.all([

    runYara(caseId, pool, triggeredBy)
      .then(r => { yaraMatches = r.matches; allAlerts.push(...r.alerts); })
      .catch(e => logger.warn('[SOAR/YARA]', e.message)),

    runSigma(caseId, pool, triggeredBy)
      .then(r => { sigmaMatches = r.matches; allAlerts.push(...r.alerts); })
      .catch(e => logger.warn('[SOAR/Sigma]', e.message)),

    correlateCase(caseId, pool)
      .then(n => {
        threatIntelCorrelations = n;
        if (n > 0) {
          allAlerts.push({
            type: 'threat_intel',
            severity: 'high',
            title: `${n} IOC${n > 1 ? 's' : ''} corrélé${n > 1 ? 's' : ''} avec Threat Intel`,
            description: `${n} correspondance${n > 1 ? 's' : ''} entre les artefacts du cas et les indicateurs TAXII/STIX.`,
            details: { correlation_count: n },
            source: 'TAXII/STIX',
            triggered_by: triggeredBy,
          });
        }
      })
      .catch(e => logger.warn('[SOAR/ThreatIntel]', e.message)),

    computeTriageScores(pool, caseId)
      .then(async result => {
        await saveTriageScores(pool, caseId, result).catch(e => logger.warn('[SOAR/save-triage]', e.message));
        for (const m of result.machines) {
          if (m.score < 60) continue;
          triageCriticals++;
          allAlerts.push({
            type: 'triage',
            severity: m.score >= 80 ? 'critical' : 'high',
            title: `${m.risk_level}: ${m.hostname} (${m.score}/100)`,
            description: `Machine "${m.hostname}" présente des indicateurs de compromission élevés (score ${m.score}/100).`,
            details: { hostname: m.hostname, score: m.score, breakdown: m.breakdown },
            source: m.hostname,
            triggered_by: triggeredBy,
          });
        }
      })
      .catch(e => logger.warn('[SOAR/Triage]', e.message)),
  ]);

  let alertsGenerated = 0;
  if (allAlerts.length > 0) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const a of allAlerts) {
        const r = await client.query(
          `INSERT INTO automated_hunt_alerts
             (case_id, type, severity, title, description, details, source, triggered_by, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
           ON CONFLICT (case_id, type, source) DO UPDATE
             SET severity     = EXCLUDED.severity,
                 title        = EXCLUDED.title,
                 description  = EXCLUDED.description,
                 details      = EXCLUDED.details,
                 triggered_by = EXCLUDED.triggered_by,
                 created_at   = NOW(),
                 acknowledged = FALSE,
                 acknowledged_by = NULL,
                 acknowledged_at = NULL
           RETURNING id`,
          [caseId, a.type, a.severity, a.title, a.description,
           JSON.stringify(a.details), a.source, a.triggered_by],
        );
        if (r.rows.length) alertsGenerated++;
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  const result: SoarRunResult = {
    case_id: caseId,
    triggered_by: triggeredBy,
    alerts_generated: alertsGenerated,
    yara_matches: yaraMatches,
    sigma_matches: sigmaMatches,
    threat_intel_correlations: threatIntelCorrelations,
    triage_criticals: triageCriticals,
    duration_ms: Date.now() - t0,
  };

  io?.to(caseId).emit('soar:complete', result);
  logger.info(`[SOAR] ${caseId} | by=${triggeredBy} | alerts=${alertsGenerated} | ${result.duration_ms}ms`);
  return result;
}

export function runSoarAsync(caseId: string, pool: Pool, triggeredBy = 'auto', io?: any): void {
  runSoar(caseId, pool, triggeredBy, io).catch(e => logger.warn('[SOAR] runSoarAsync error:', e.message));
}
