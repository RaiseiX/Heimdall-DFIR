export const HAYABUSA_REPORT_LEVELS = ['critical', 'high'];

export const HAYABUSA_REPORT_FILTER_SQL = HAYABUSA_REPORT_LEVELS
  .map((niveau) => `description LIKE '[${niveau}]%'`)
  .join(' OR ');

export const HAYABUSA_REPORT_ORDER_SQL = `CASE ${HAYABUSA_REPORT_LEVELS
  .map((niveau, i) => `WHEN description LIKE '[${niveau}]%' THEN ${i + 1}`)
  .join(' ')} ELSE ${HAYABUSA_REPORT_LEVELS.length + 1} END`;

const PREFIX = /^\[([a-z]+)\]\s*(.*)$/s;

interface HayabusaRow {
  description?: string | null;
  raw?: Record<string, unknown> | null;
}

export function hayabusaSeverity(description?: string | null): string | null {
  if (typeof description !== 'string') return null;
  const m = PREFIX.exec(description);
  return m ? m[1] : null;
}

export function hayabusaRuleTitle(row?: HayabusaRow | null): string | null {
  const raw = row && typeof row.raw === 'object' && row.raw !== null ? row.raw : {};
  for (const cle of ['RuleTitle', 'rule_title', 'hayabusa_rule']) {
    const valeur = raw[cle];
    if (typeof valeur === 'string' && valeur.trim()) return valeur.trim();
  }
  const m = typeof row?.description === 'string' ? PREFIX.exec(row.description) : null;
  if (!m) return null;
  const titre = m[2].split(' — ')[0].trim();
  return titre || null;
}

export function hayabusaReportRow(row?: HayabusaRow | null) {
  return {
    level: hayabusaSeverity(row?.description),
    rule_title: hayabusaRuleTitle(row),
    description: row?.description ?? null,
  };
}
