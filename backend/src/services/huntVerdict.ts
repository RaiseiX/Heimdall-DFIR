import crypto from 'crypto';

export const VERDICT_STATUSES = ['in_review', 'confirmed', 'false_positive'] as const;
export type VerdictStatus = typeof VERDICT_STATUSES[number];

export type VerdictState = 'none' | 'active' | 'stale';

export interface HuntVerdict {
  status:            VerdictStatus;
  rule_fingerprint?: string | null;
  note?:             string | null;
  decided_by_name?:  string | null;
  decided_at?:       string | null;
}

export function isValidVerdictStatus(s: unknown): boolean {
  return typeof s === 'string' && (VERDICT_STATUSES as readonly string[]).includes(s);
}

export function ruleFingerprint(content: unknown): string {
  const normalised = String(content ?? '').replace(/\r\n/g, '\n').trim();
  return crypto.createHash('sha256').update(normalised).digest('hex').slice(0, 16);
}

export function huntVerdictState(
  verdict: HuntVerdict | null | undefined,
  currentFingerprint: string,
): VerdictState {
  if (!verdict) return 'none';
  if (!verdict.rule_fingerprint) return 'stale';
  return verdict.rule_fingerprint === currentFingerprint ? 'active' : 'stale';
}

export function huntHistoryQuery(caseId: string, limit?: number): { text: string; values: unknown[] } {
  const n = Number(limit);
  const safeLimit = !Number.isFinite(n) || n <= 0 ? 50 : Math.min(Math.trunc(n), 500);

  return {
    text: `SELECT * FROM (
             SELECT DISTINCT ON ( h.rule_id )
                    h.id, h.rule_id, h.rule_name, h.match_count, h.matched_events,
                    h.sample_size, h.hunted_at,
                    COUNT(*) OVER (PARTITION BY h.rule_id) AS run_count,
                    r.level, r.mitre_techniques, r.content AS rule_content,
                    v.status AS verdict_status_raw, v.rule_fingerprint AS verdict_fingerprint,
                    v.note AS verdict_note_raw, v.decided_at AS verdict_decided_at,
                    u.username AS verdict_by_name
               FROM sigma_hunt_results h
               LEFT JOIN sigma_rules r ON r.id = h.rule_id
               LEFT JOIN hunt_verdicts v ON v.case_id = h.case_id AND v.rule_id = h.rule_id
               LEFT JOIN users u ON u.id = v.decided_by
              WHERE h.case_id = $1
              ORDER BY h.rule_id, h.hunted_at DESC
           ) derniers
           ORDER BY hunted_at DESC
           LIMIT $2`,
    values: [caseId, safeLimit],
  };
}

export function decorateHit<T extends object>(
  hit: T,
  verdict: HuntVerdict | null | undefined,
  currentFingerprint: string,
): T & {
  verdict_status: string;
  verdict_stale:  boolean;
  verdict_note:   string | null;
  verdict_by:     string | null;
} {
  const state = huntVerdictState(verdict, currentFingerprint);
  return {
    ...hit,
    verdict_status: state === 'none' ? 'new' : (verdict as HuntVerdict).status,
    verdict_stale:  state === 'stale',
    verdict_note:   verdict?.note ?? null,
    verdict_by:     verdict?.decided_by_name ?? null,
  };
}
