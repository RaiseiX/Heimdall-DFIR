import type { Pool } from 'pg';
import logger from '../config/logger';

const { getRedis } = require('../config/redis') as { getRedis: () => import('ioredis').Redis | null };

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RiskScore {
  score:       number;
  level:       RiskLevel;
  breakdown:   RiskBreakdown;
  computed_at: string;
}

interface RiskBreakdown {
  malicious_iocs:          number;
  critical_triage_machines: number;
  yara_matches:            number;
  sigma_matches:           number;
  threat_correlations:     number;
  open_days:               number;
}

const WEIGHTS = {
  malicious_ioc:           10,
  critical_machine:        15,
  yara_match:               5,
  sigma_match:              3,
  threat_correlation:       5,
  open_days_per_30:         5,
};

function cap(value: number, max: number): number {
  return Math.min(value, max);
}

function levelFromScore(score: number): RiskLevel {
  if (score >= 70) return 'CRITICAL';
  if (score >= 40) return 'HIGH';
  if (score >= 20) return 'MEDIUM';
  return 'LOW';
}

const CACHE_TTL = 5 * 60;

function cacheKey(caseId: string): string {
  return `risk:case:${caseId}`;
}

export async function computeRiskScore(pool: Pool, caseId: string): Promise<RiskScore> {

  const [iocRow, triageRow, yaraRow, sigmaRow, correlRow, caseRow] = await Promise.all([

    pool.query<{ cnt: string }>(
      `SELECT COUNT(*) AS cnt FROM iocs WHERE case_id = $1 AND is_malicious = true`,
      [caseId],
    ),

    pool.query<{ cnt: string }>(
      `SELECT COUNT(*) AS cnt FROM triage_scores
       WHERE case_id = $1 AND risk_level = 'CRITIQUE'`,
      [caseId],
    ).catch(() => ({ rows: [{ cnt: '0' }] })),

    pool.query<{ cnt: string }>(
      `SELECT COUNT(*) AS cnt FROM yara_scan_results WHERE case_id = $1`,
      [caseId],
    ).catch(() => ({ rows: [{ cnt: '0' }] })),

    pool.query<{ cnt: string }>(
      `SELECT COUNT(*) AS cnt FROM sigma_hunt_results WHERE case_id = $1`,
      [caseId],
    ).catch(() => ({ rows: [{ cnt: '0' }] })),

    pool.query<{ cnt: string }>(
      `SELECT COUNT(*) AS cnt FROM threat_correlations WHERE case_id = $1`,
      [caseId],
    ).catch(() => ({ rows: [{ cnt: '0' }] })),

    pool.query<{ created_at: Date }>(
      `SELECT created_at FROM cases WHERE id = $1`,
      [caseId],
    ),
  ]);

  const maliciousIocs      = parseInt(iocRow.rows[0]?.cnt ?? '0', 10);
  const criticalMachines   = parseInt(triageRow.rows[0]?.cnt ?? '0', 10);
  const yaraMatches        = parseInt(yaraRow.rows[0]?.cnt ?? '0', 10);
  const sigmaMatches       = parseInt(sigmaRow.rows[0]?.cnt ?? '0', 10);
  const threatCorrelations = parseInt(correlRow.rows[0]?.cnt ?? '0', 10);

  const caseCreatedAt = caseRow.rows[0]?.created_at ?? new Date();
  const openDays = Math.max(0, (Date.now() - new Date(caseCreatedAt).getTime()) / 86_400_000);

  const score = Math.min(100, Math.round(
    cap(maliciousIocs      * WEIGHTS.malicious_ioc,    30) +
    cap(criticalMachines   * WEIGHTS.critical_machine, 30) +
    cap(yaraMatches        * WEIGHTS.yara_match,       20) +
    cap(sigmaMatches       * WEIGHTS.sigma_match,      15) +
    cap(threatCorrelations * WEIGHTS.threat_correlation, 15) +
    cap(Math.floor(openDays / 30) * WEIGHTS.open_days_per_30, 10),
  ));

  const level = levelFromScore(score);

  const result: RiskScore = {
    score,
    level,
    breakdown: {
      malicious_iocs:           maliciousIocs,
      critical_triage_machines: criticalMachines,
      yara_matches:             yaraMatches,
      sigma_matches:            sigmaMatches,
      threat_correlations:      threatCorrelations,
      open_days:                Math.round(openDays),
    },
    computed_at: new Date().toISOString(),
  };

  pool.query(
    `UPDATE cases
     SET risk_score = $1, risk_level = $2, risk_computed_at = NOW()
     WHERE id = $3`,
    [score, level, caseId],
  ).catch((err: any) => logger.warn('[riskScore] DB update failed', { caseId, error: err.message }));

  return result;
}

export async function getRiskScore(pool: Pool, caseId: string): Promise<RiskScore> {

  const redis = getRedis();
  if (redis) {
    try {
      const cached = await redis.get(cacheKey(caseId));
      if (cached) return JSON.parse(cached) as RiskScore;
    } catch {

    }
  }

  const result = await computeRiskScore(pool, caseId);

  if (redis) {
    try {
      await redis.set(cacheKey(caseId), JSON.stringify(result), 'EX', CACHE_TTL);
    } catch {

    }
  }

  return result;
}

export async function invalidateRiskScore(caseId: string): Promise<void> {
  const redis = getRedis();
  if (!redis) return;
  try {
    await redis.del(cacheKey(caseId));
  } catch {

  }
}
