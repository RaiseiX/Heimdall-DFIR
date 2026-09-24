import { parseRule, buildQuery, huntPlan } from './sigmaService';

export const SIGMA_REGLE_TIMEOUT_MS = 120_000;
const QUERY_CANCELED = '57014';

interface Requetable {
  query: (text: string, values?: unknown[]) => Promise<any>;
}

export function requetesBornees(pool: { connect: () => Promise<any> }, delaiMs: number): Requetable {
  return {
    async query(text: string, values?: unknown[]) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL statement_timeout = ${Number(delaiMs)}`);
        const resultat = await client.query(text, values);
        await client.query('COMMIT');
        return resultat;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

export interface EvaluationRegle {
  pool:                Requetable;
  lecture:             Requetable;
  huntMatches:         (pool: any, caseId: string, where: string, params: unknown[]) => Promise<{ matchCount: number; sample: any[] }>;
  markTimelineForRule: (pool: any, caseId: string, rule: any, where: string, params: unknown[], matchCount: number) => Promise<number>;
  caseId:              string;
  rule:                any;
  presentFields:       Set<string> | null;
  avertir?:            (message: string) => void;
}

export async function evaluerRegleSigma({
  pool, lecture, huntMatches, markTimelineForRule, caseId, rule, presentFields, avertir = () => {},
}: EvaluationRegle): Promise<any> {
  const base = { rule_id: rule.id, rule_name: rule.name, level: rule.level, mitre_techniques: rule.mitre_techniques };

  const parsed = parseRule(rule.content);
  if (!parsed.valid || !parsed.parsed) return { ...base, match_count: 0, error: parsed.error };

  try {
    const { where, params, unsupported, fields } = buildQuery(parsed.parsed as any);
    if (unsupported) return { ...base, match_count: 0, error: unsupported };

    const plan = huntPlan(fields, presentFields);
    if (!plan.run) return { ...base, match_count: 0, unreachable: true, missing_fields: plan.missingFields };

    const allParams: unknown[] = [caseId, ...params];
    const shiftedWhere = where.replace(/\$(\d+)/g, (_m: string, n: string) => `$${parseInt(n, 10) + 1}`);
    const { matchCount, sample } = await huntMatches(lecture, caseId, shiftedWhere, allParams);

    let marquageIncomplet = false;
    try {
      await markTimelineForRule(lecture, caseId, rule, where, params, matchCount);
    } catch (e: any) {
      marquageIncomplet = true;
      avertir(`[sigma] marquage timeline impossible (${rule.name}): ${e.message}`);
    }

    if (matchCount > 0) {
      await pool.query(
        `INSERT INTO sigma_hunt_results (case_id, rule_id, rule_name, match_count, matched_events, sample_size)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [caseId, rule.id, rule.name, matchCount, JSON.stringify(sample), sample.length],
      );
    }
    return { ...base, match_count: matchCount, ...(marquageIncomplet ? { marquage_incomplet: true } : {}) };
  } catch (err: any) {
    if (err?.code === QUERY_CANCELED) {
      return { ...base, match_count: 0, error: `durée maximale dépassée (${SIGMA_REGLE_TIMEOUT_MS / 1000} s)`, timed_out: true };
    }
    return { ...base, match_count: 0, error: err.message };
  }
}
