
import { Pool } from 'pg';
import logger from '../config/logger';
import { scanEvidenceWithRules } from './yaraService';
import { correlateCase } from './taxiiService';
import { computeTriageScores, saveTriageScores } from './triageScoreService';
import { readPool } from '../config/database';

export interface SoarRunResult {
  case_id:                  string;
  triggered_by:             string;
  alerts_generated:         number;
  yara_matches:             number;
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
    const passe = await scanEvidenceWithRules(ev.file_path, rulesRes.rows);
    if (passe.saute) logger.info(`[SOAR/YARA] ${ev.name} sautée : ${passe.saute}`);
    if (passe.erreur) logger.warn(`[SOAR/YARA] ${ev.name} : ${passe.erreur}`);
    if (passe.regles_en_erreur.length) logger.warn(`[SOAR/YARA] ${passe.regles_en_erreur.length} règle(s) non compilable(s) écartée(s)`);
    if (passe.regles_lentes?.length) logger.warn(`[SOAR/YARA] ${passe.regles_lentes.length} règle(s) lente(s) écartée(s) de la passe automatique`);

    for (const [index, chaines] of passe.correspondances) {
      const rule = rulesRes.rows[index];
      if (!rule) continue;
      totalMatches++;
      await pool.query(
        `INSERT INTO yara_scan_results (evidence_id, case_id, rule_id, rule_name, matched_strings)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING`,
        [ev.id, caseId, rule.id, rule.name, JSON.stringify(chaines)],
      );
      const existing = ruleMap.get(rule.name) || { ruleId: rule.id, evidence: [] as string[], count: 0 };
      existing.evidence.push(ev.name);
      existing.count++;
      ruleMap.set(rule.name, existing);
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

export async function runSoar(
  caseId: string,
  pool: Pool,
  triggeredBy = 'manual',
  io?: any,
): Promise<SoarRunResult> {
  const t0 = Date.now();
  let yaraMatches = 0;
  let threatIntelCorrelations = 0;
  let triageCriticals = 0;
  const allAlerts: AlertRow[] = [];

  await Promise.all([

    runYara(caseId, pool, triggeredBy)
      .then(r => { yaraMatches = r.matches; allAlerts.push(...r.alerts); })
      .catch(e => logger.warn('[SOAR/YARA]', e.message)),

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

    // Read-only and very heavy — bounded by the read pool's statement_timeout so
    // it cannot hold ACCESS SHARE long enough to starve the startup DDL.
    computeTriageScores(readPool, caseId)
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
