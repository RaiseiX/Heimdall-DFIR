export interface HuntDetection {
  id:        string;
  name:      string;
  mitre?:    string[];
  severity?: string;
  source:    string;
  [k: string]: unknown;
}

function asArray(existing: unknown): any[] {
  return Array.isArray(existing) ? existing.filter((d) => d && typeof d === 'object') : [];
}

export function withoutRuleDetections(existing: unknown, source: string, id: string): any[] {
  return asArray(existing).filter((d: any) => !(d.source === source && d.id === id));
}

export function mergeRuleDetection(existing: unknown, detection: HuntDetection): any[] {
  return [...withoutRuleDetections(existing, detection.source, detection.id), detection];
}

export const GRID_SEVERITIES = ['critical', 'high'] as const;

export function hitsOnlyPredicate(): string {
  const clauses = GRID_SEVERITIES.map(
    (s) => `detections @> '[{"severity":"${s}"}]'::jsonb`,
  );
  return `(detections IS NOT NULL AND (${clauses.join(' OR ')}))`;
}

export interface SqlQuery { text: string; values: unknown[]; }

export function clearRuleDetections(caseId: string, source: string, id: string): SqlQuery {
  return {
    text: `UPDATE collection_timeline
              SET detections = COALESCE((
                    SELECT jsonb_agg(d)
                      FROM jsonb_array_elements(detections) d
                     WHERE NOT (d->>'source' = $2 AND d->>'id' = $3)
                  ), '[]'::jsonb)
            WHERE case_id = $1
              AND detections IS NOT NULL
              AND jsonb_array_length(detections) > 0
              AND detections @> jsonb_build_array(jsonb_build_object('source', $2::text, 'id', $3::text))`,
    values: [caseId, source, id],
  };
}

export function applyRuleDetection(
  caseId: string, where: string, whereValues: unknown[], detection: HuntDetection,
): SqlQuery {
  const shifted = where.replace(/\$(\d+)/g, (_m, n) => `$${parseInt(n, 10) + 2}`);
  return {
    text: `UPDATE collection_timeline
              SET detections = COALESCE((
                    SELECT jsonb_agg(d)
                      FROM jsonb_array_elements(COALESCE(detections, '[]'::jsonb)) d
                     WHERE NOT (d->>'source' = ($2::jsonb->>'source') AND d->>'id' = ($2::jsonb->>'id'))
                  ), '[]'::jsonb) || jsonb_build_array($2::jsonb)
            WHERE case_id = $1 AND (${shifted})`,
    values: [caseId, JSON.stringify(detection), ...whereValues],
  };
}
