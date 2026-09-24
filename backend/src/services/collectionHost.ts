import { resolveNodeIdentity } from './networkIdentity';

export interface HostObservation { host: string | null | undefined; events: number }

export function establishedHosts(rows: HostObservation[]): string[] {
  const out = new Set<string>();
  for (const r of rows || []) {
    const h = String(r?.host ?? '').trim();
    if (h) out.add(h);
  }
  return [...out].sort();
}

export function collectionHost(rows: HostObservation[]): { host: string; events: number } | null {
  const byKey = new Map<string, { host: string; events: number }>();
  for (const r of rows || []) {
    const h = String(r?.host ?? '').trim();
    if (!h) continue;
    const ident = resolveNodeIdentity(h);
    const key = ident.kind === 'host' && ident.key ? ident.key : h;
    const seen = byKey.get(key);
    if (seen) {
      seen.events += Number(r.events) || 0;
      if ((Number(r.events) || 0) > 0 && h.length > seen.host.length) seen.host = h;
    } else {
      byKey.set(key, { host: h, events: Number(r.events) || 0 });
    }
  }
  if (byKey.size !== 1) return null;
  return [...byKey.values()][0];
}

export function establishedHostsQuery(caseId: string): { text: string; values: unknown[] } {
  return {
    text: `SELECT pr.evidence_id::text AS evidence_id,
                  ct.raw->>'Computer'  AS host,
                  COUNT(*)::int        AS events
             FROM collection_timeline ct
             JOIN parser_results pr ON pr.id = ct.result_id
            WHERE ct.case_id = $1
              AND pr.evidence_id IS NOT NULL
              AND ct.artifact_type IN ('evtx', 'hayabusa')
              AND ct.raw->>'Computer' IS NOT NULL
              AND ct.raw->>'Computer' <> ''
            GROUP BY 1, 2`,
    values: [caseId],
  };
}

export interface CollectionMachine { evidence_id: string; host: string }

export function resolvedHostExpr(
  machines: CollectionMachine[],
  established: string[],
  paramStart: number,
): { sql: string; params: unknown[] } {
  const plain = { sql: 'host_name', params: [] as unknown[] };
  if (!machines?.length || !established?.length) return plain;

  const ids = machines.map(m => m.evidence_id);
  const hosts = machines.map(m => m.host);
  const a = paramStart, b = paramStart + 1, c = paramStart + 2;

  return {
    sql: `CASE WHEN host_name = ANY($${a}::text[]) THEN host_name
               ELSE COALESCE(
                 (SELECT m.h FROM unnest($${b}::uuid[], $${c}::text[]) AS m(e, h)
                   WHERE m.e = evidence_id LIMIT 1),
                 host_name)
          END`,
    params: [established, ids, hosts],
  };
}
