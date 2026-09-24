// Build the description shown for a Hayabusa detection.
//
// Hayabusa is invoked with `-p all-field-info`, which emits an AllFieldInfo map
// instead of Hayabusa's own curated `Details` column — that is why nothing in the
// codebase reads `Details`. The full record is preserved in collection_timeline.raw
// (Hayabusa rows deliberately skip buildSlimRaw), and the detail panel can show it.
//
// But the description is what the timeline grid renders per row, and "[high]
// Suspicious Service Installation" tells an analyst that something matched without
// saying what it matched on. Triage happens in the grid, so the nouns that make a
// hit actionable — the service installed, the command line executed, the account
// involved — belong in the description too.

/** Bound so one detection cannot dominate the description column. */
const MAX_LEN = 600;
const MAX_VALUE_LEN = 220;

/**
 * Fields worth promoting, in the order an analyst reads them: what it touched,
 * then what ran, then who. Each entry lists the aliases Hayabusa emits across
 * channels — the same fact is named differently by Security, System and Sysmon.
 */
const SALIENT = [
  { label: 'Svc',  keys: ['ServiceName', 'ServiceFileName', 'ImagePath'] },
  { label: 'Cmd',  keys: ['CommandLine', 'ProcessCommandLine', 'Cmdline', 'NewProcessName'] },
  { label: 'Proc', keys: ['Image', 'ProcessName', 'ParentImage'] },
  { label: 'User', keys: ['TargetUserName', 'SubjectUserName', 'AccountName', 'User'] },
  { label: 'Host', keys: ['TargetServerName', 'WorkstationName'] },
];

/** Values Hayabusa uses for "nothing here" — printing them is worse than silence. */
const EMPTY = new Set(['', '-', 'n/a', 'null', 'undefined']);

function firstUsable(info, keys) {
  for (const k of keys) {
    const v = info[k];
    if (v === null || v === undefined) continue;
    const s = String(v).trim();
    if (s && !EMPTY.has(s.toLowerCase())) return s;
  }
  return null;
}

/**
 * @param {{level: string, ruleTitle: string, allFieldInfo: object|string|null}} input
 * @returns {string}
 */
function buildHayabusaDescription({ level, ruleTitle, allFieldInfo }) {
  const head = `[${level}] ${ruleTitle}`;
  if (!allFieldInfo || typeof allFieldInfo !== 'object' || Array.isArray(allFieldInfo)) {
    return head;
  }

  const parts = [];
  for (const { label, keys } of SALIENT) {
    const value = firstUsable(allFieldInfo, keys);
    if (!value) continue;
    // Mark truncation at the VALUE, not just at the end of the line: an analyst
    // who reads a cut command line as the whole command line draws the wrong
    // conclusion, and a base64 PowerShell payload cuts long before the line does.
    const shown = value.length > MAX_VALUE_LEN ? `${value.slice(0, MAX_VALUE_LEN)}…` : value;
    parts.push(`${label}: ${shown}`);
  }
  if (parts.length === 0) return head;

  const full = `${head} — ${parts.join(' · ')}`;
  return full.length <= MAX_LEN ? full : `${full.slice(0, MAX_LEN - 1)}…`;
}

module.exports = { buildHayabusaDescription };
