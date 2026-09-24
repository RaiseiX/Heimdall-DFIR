export const TACTIC_LABEL: Record<string, string> = {
  'reconnaissance':       'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access':       'Initial Access',
  'execution':            'Execution',
  'persistence':          'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion':      'Defense Evasion',
  'credential-access':    'Credential Access',
  'discovery':            'Discovery',
  'lateral-movement':     'Lateral Movement',
  'collection':           'Collection',
  'command-and-control':  'Command and Control',
  'exfiltration':         'Exfiltration',
  'impact':               'Impact',
};

const TAG = /attack\.([a-z0-9_.-]+)/gi;
const TECHNIQUE = /^t\d{4}(\.\d{3})?$/i;

export interface AttackTags {
  techniques: string[];
  tactics: string[];
}

export function parseAttackTags(content: string | null | undefined): AttackTags {
  const techniques = new Set<string>();
  const tactics = new Set<string>();
  const text = String(content ?? '');

  TAG.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TAG.exec(text)) !== null) {
    const raw = m[1];
    if (TECHNIQUE.test(raw)) { techniques.add(raw.toUpperCase()); continue; }
    const slug = raw.toLowerCase().replace(/_/g, '-');
    if (TACTIC_LABEL[slug]) tactics.add(slug);
  }

  return { techniques: [...techniques], tactics: [...tactics] };
}

export function caseTechniquesQuery(caseId: string): { text: string; values: unknown[] } {
  return {
    text: `SELECT r.id, r.rule_name, r.match_count, r.hunted_at, sr.content, sr.level
             FROM sigma_hunt_results r
             JOIN sigma_rules sr ON sr.id = r.rule_id
            WHERE r.case_id = $1 AND r.match_count > 0
            ORDER BY r.hunted_at ASC`,
    values: [caseId],
  };
}

export interface HuntRow {
  id: string;
  rule_name: string;
  match_count: number;
  hunted_at: string;
  content: string;
  level?: string | null;
}

export interface TechniqueNode {
  technique_id: string;
  tactic: string;
  hunts: number;
  widest_match: number;
  narrowest_match: number | null;
  rules: string[];
  first_seen: string | null;
  last_seen: string | null;
  level: string | null;
}

const LEVEL_RANK = ['informational', 'low', 'medium', 'high', 'critical'];

export function techniquesFromHunts(rows: HuntRow[]): TechniqueNode[] {
  const byTechnique = new Map<string, TechniqueNode>();

  for (const row of rows || []) {
    const { techniques, tactics } = parseAttackTags(row?.content);
    if (!techniques.length) continue;
    const tactic = tactics.length ? TACTIC_LABEL[tactics[0]] : '';

    for (const id of techniques) {
      const key = `${id}|${tactic}`;
      let node = byTechnique.get(key);
      if (!node) {
        node = { technique_id: id, tactic, hunts: 0, widest_match: 0, narrowest_match: null,
                 rules: [], first_seen: null, last_seen: null, level: null };
        byTechnique.set(key, node);
      }
      node.hunts += 1;
      const matched = Number(row.match_count) || 0;
      if (matched > node.widest_match) node.widest_match = matched;
      if (node.narrowest_match === null || matched < node.narrowest_match) node.narrowest_match = matched;
      if (row.rule_name && !node.rules.includes(row.rule_name)) node.rules.push(row.rule_name);
      const at = row.hunted_at || null;
      if (at && (!node.first_seen || at < node.first_seen)) node.first_seen = at;
      if (at && (!node.last_seen || at > node.last_seen)) node.last_seen = at;
      const lvl = String(row.level || '').toLowerCase();
      if (LEVEL_RANK.includes(lvl) && LEVEL_RANK.indexOf(lvl) > LEVEL_RANK.indexOf(node.level || '')) {
        node.level = lvl;
      }
    }
  }

  return [...byTechnique.values()].sort((a, b) => b.hunts - a.hunts || a.technique_id.localeCompare(b.technique_id));
}
