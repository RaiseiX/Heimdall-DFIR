import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const srcDir = path.join(root, 'src');
export const frPath = path.join(srcDir, 'i18n', 'fr.json');
export const enPath = path.join(srcDir, 'i18n', 'en.json');

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function flatten(value, prefix = '', out = {}) {
  for (const [key, child] of Object.entries(value)) {
    const next = prefix ? `${prefix}.${key}` : key;
    if (child && typeof child === 'object' && !Array.isArray(child)) {
      flatten(child, next, out);
    } else {
      out[next] = child;
    }
  }
  return out;
}

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, files);
    } else if (/\.(jsx|tsx|js|ts)$/.test(entry.name) && !entry.name.endsWith('.bak')) {
      files.push(fullPath);
    }
  }
  return files;
}

// Status belongs to the component (e.g. Toast variant="success"), not the
// string — same defect as severity written `[low]` as a text prefix.
// Ceiling only goes down: each migration lot purges its share, in both
// locales at once (see src/designSystem.test.js for the FR/EN symmetry
// assertion that keeps one locale from being purged without the other).
//
// Exported (not just used locally) so `src/designSystem.test.js` — the
// scanned tree for the design-system drift ratchet — can import this logic
// instead of holding its own copy. A copy inside `src/` previously carried
// its own positive-control fixture (a literal pictogram character written
// into the test to prove the regex works) plus a `✓` in a doc comment; both
// got counted by `check-design-system.mjs`'s `pictogramCode` source-code
// scan, which walks every file under `src/` looking for exactly these
// unicode ranges. That guard has no way to distinguish "a pictogram used as
// UI status" from "a pictogram fixture proving a *different* guard works" —
// so the fixture must live outside `src/` by construction, same reasoning
// that already keeps `check-design-system.mjs`'s own FIXTURES in `scripts/`.
export const PICTOGRAM_RE = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}]/u;
export const PICTOGRAM_CEILING = 110; // measured 2026-08-04 — lower with every lot

// Encoded via code point rather than written as a literal character —
// consistent with `FIXTURES.violating` in check-design-system.mjs, and it
// means a future `rg` for pictogram characters restricted to `src/` isn't
// the only thing keeping this file's fixture out of the count: there is no
// literal character here to begin with. U+2705 is the "✅" white heavy
// check mark used for the positive control; the negative control is a
// pictogram-free string with only an em dash and digits.
export const PICTOGRAM_FIXTURES = {
  positive: `${String.fromCodePoint(0x2705)} Enregistré`,
  negative: 'Enregistré — 12 preuves',
};

/** Dotted keys (already sorted) whose flattened value matches PICTOGRAM_RE. */
export function pictogramKeys(flatDict) {
  return Object.entries(flatDict)
    .filter(([, value]) => typeof value === 'string' && PICTOGRAM_RE.test(value))
    .map(([key]) => key)
    .sort();
}

/** Convenience wrapper: read + flatten a locale JSON file, then pictogramKeys() it. */
export function pictogramKeysInFile(file) {
  return pictogramKeys(flatten(readJson(file)));
}

// ---------------------------------------------------------------------------
// Pluralisation
//
// i18next 23 runs the "v4" JSON format: plural forms are resolved through
// Intl.PluralRules, so the suffix must be a CLDR category — `_one` / `_other`
// (plus `_many` for French at >= 1e6). The v2/v3 `_plural` suffix, and the
// homegrown `_pl` used in parts of this codebase, are NOT resolved: i18next
// silently ignores the suffixed entry and `t(key, { count })` returns the bare
// `key` value for every count. That failure is invisible — no warning, no
// missing-key error, just the singular form forever.
//
// Resolution order is `key_<category>` -> bare `key` -> the raw key string, so
// a family that omits a category the locale actually uses renders the literal
// dotted key in the UI. French uses three categories, not two: `one` (0 and 1),
// `other`, and `many` — which fires only on exact multiples of a million
// (1000000 and 2000000 are `many`; 1500000 is `other`). This project's shape is
// `_one` + `_other` with no bare alias, so that exact-million case is a known,
// accepted gap: `t('iocs.ports_count', { count: 1000000 })` renders
// "iocs.ports_count". Judged not worth duplicating a string into every family;
// revisit by adding `_many` (not a bare alias) if a real screen ever hits it.
//
// Enum values are deliberately exempt: `feedback.type_other` ("Autre") is the
// "Other" choice next to `type_bug` / `type_suggestion`, not a plural form.
// A family only counts as a plural family when it carries a count-bearing
// suffix, which an enum never does — that is the whole disambiguation rule.
export const DEAD_PLURAL_SUFFIXES = ['plural', 'pl'];
const COUNT_BEARING = ['zero', 'one', 'two', 'few', 'many'];
const SUFFIX_RE = new RegExp(`_(${[...DEAD_PLURAL_SUFFIXES, ...COUNT_BEARING, 'other'].join('|')})$`);

/** base key -> Set of suffixes seen, for every suffixed key in the dictionary. */
export function pluralFamilies(flatDict) {
  const families = new Map();
  for (const key of Object.keys(flatDict)) {
    const match = key.match(SUFFIX_RE);
    if (!match) continue;
    const base = key.slice(0, -match[0].length);
    if (!families.has(base)) families.set(base, new Set());
    families.get(base).add(match[1]);
  }
  return families;
}

/** Human-readable problems, sorted; empty array means the dictionary is clean. */
export function pluralFamilyProblems(flatDict) {
  const problems = [];
  for (const [base, suffixes] of pluralFamilies(flatDict)) {
    const dead = DEAD_PLURAL_SUFFIXES.filter(s => suffixes.has(s));
    for (const suffix of dead) {
      problems.push(`${base}_${suffix}: i18next v4 ignores "_${suffix}" — use _one/_other`);
    }
    if (!COUNT_BEARING.some(s => suffixes.has(s))) continue; // enum family, or nothing to check
    if (!suffixes.has('other')) {
      problems.push(`${base}: has ${[...suffixes].sort().join('/')} but no _other — t() returns the raw key for every count outside those categories`);
    }
  }
  return problems.sort();
}

function main() {
  const auditHardcoded = process.argv.includes('--hardcoded');

  const fr = flatten(readJson(frPath));
  const en = flatten(readJson(enPath));
  const frKeys = new Set(Object.keys(fr));
  const enKeys = new Set(Object.keys(en));

  const failures = [];

  const missingInEn = [...frKeys].filter(key => !enKeys.has(key)).sort();
  const missingInFr = [...enKeys].filter(key => !frKeys.has(key)).sort();
  const emptyEn = Object.entries(en)
    .filter(([, value]) => typeof value === 'string' && value.trim() === '')
    .map(([key]) => key)
    .sort();
  const emptyFr = Object.entries(fr)
    .filter(([, value]) => typeof value === 'string' && value.trim() === '')
    .map(([key]) => key)
    .sort();

  if (missingInEn.length) failures.push(`Missing English keys:\n${missingInEn.join('\n')}`);
  if (missingInFr.length) failures.push(`Missing French keys:\n${missingInFr.join('\n')}`);
  if (emptyEn.length) failures.push(`Empty English values:\n${emptyEn.join('\n')}`);
  if (emptyFr.length) failures.push(`Empty French values:\n${emptyFr.join('\n')}`);

  // See pluralFamilyProblems() above for why `_plural` is dead weight. `_pl`
  // is the same defect wearing a different suffix, and it hid here far longer
  // because its call sites pluralise by hand — `t(n > 1 ? 'k_pl' : 'k', { n })`
  // — which the `usedKeys` regex below cannot see, so nothing ever flagged it.
  const pluralProblems = [
    ...pluralFamilyProblems(fr).map(p => `fr: ${p}`),
    ...pluralFamilyProblems(en).map(p => `en: ${p}`),
  ];
  if (pluralProblems.length) {
    failures.push(`Broken plural key families:\n${pluralProblems.join('\n')}`);
  }

  // `\s*[,)]` after the closing quote requires the string to be the *whole*
  // argument (`t('key')` or `t('key', ...)`), not a fragment glued to a
  // runtime value (`t('investigation.status_' + s.status)`). Without this,
  // dynamic-prefix call sites report their literal prefix as a "used key",
  // which never exists in the locale files and was never meant to — the
  // full key only exists at runtime after concatenation. See
  // src/components/investigation/{FindingsPanel,WorkflowTracker,KanbanBoard/KanbanBoard}.jsx
  // for the call sites this excludes. Trade-off: a call built by
  // concatenating two string literals (`t('a' + 'b')`) — not used anywhere
  // in this codebase — would no longer be checked either; and the resulting
  // runtime keys of dynamic-prefix calls (e.g. investigation.status_todo)
  // are not cross-checked against the locale files by this loop — only
  // direct `t('investigation.status_todo')` call sites are.
  const usedKeys = new Set();
  for (const file of walk(srcDir)) {
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/\bt\(\s*['"]([^'"]+)['"]\s*[,)]/g)) {
      usedKeys.add(match[1]);
    }
  }

  // A literal `t('some.key', { count })` call site is legitimately satisfied
  // by `some.key_other` (i18next's plural resolution appends the CLDR
  // category at runtime) even when the bare `some.key` no longer exists —
  // which is exactly the shape every `_plural` -> `_one`/`_other` migration
  // produces. Without this, converting a key off the dead `_plural` suffix
  // would make this very script flag its own literal call site as "missing".
  const hasKey = (keys, key) => keys.has(key) || keys.has(`${key}_other`);
  const missingUsed = [...usedKeys]
    .filter(key => !hasKey(frKeys, key) || !hasKey(enKeys, key))
    .sort();
  if (missingUsed.length) {
    failures.push(`Used translation keys missing from locale files:\n${missingUsed.join('\n')}`);
  }

  if (auditHardcoded) {
    const frenchPattern = /[À-ÿ]|\b(Paramètres|Rechercher|Supprimer|Modifier|Sauvegarder|Annuler|Chargement|Erreur|Succès|Aucun|Toutes|Créer|Importer|Exporter|Analyse|Preuves|Collecte|Cas|Rapport|Utilisateur|Mot de passe|Connexion|Déconnexion|Clôturé|En cours|Fermer|Actualiser|Filtrer|Sélectionner|Détails|Échec|Terminé|Forensique|Sévérité|Menace|Réseau|Mémoire)\b/g;
    const ignored = [
      `${path.sep}i18n${path.sep}`,
      `${path.sep}constants${path.sep}nodeTypes.js`,
      `${path.sep}pages${path.sep}documentation${path.sep}`,
    ];
    const rows = [];
    for (const file of walk(srcDir)) {
      if (ignored.some(part => file.includes(part))) continue;
      const source = fs.readFileSync(file, 'utf8');
      const matches = source.match(frenchPattern);
      if (matches?.length) rows.push([path.relative(root, file), matches.length]);
    }
    rows.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    if (rows.length) {
      failures.push(`Hardcoded French-like UI strings found:\n${rows.map(([file, count]) => `${file}: ${count}`).join('\n')}`);
    }
  }

  const withPictogram = [
    ...pictogramKeys(fr).map(k => `fr:${k}`),
    ...pictogramKeys(en).map(k => `en:${k}`),
  ];

  if (withPictogram.length > PICTOGRAM_CEILING) {
    failures.push(
      `Pictograms in translation values: ${withPictogram.length} > ceiling ${PICTOGRAM_CEILING}.\n` +
      `Status belongs to the component, not the string.\n${withPictogram.join('\n')}`,
    );
  }

  if (failures.length) {
    console.error(failures.join('\n\n'));
    process.exit(1);
  }

  console.log(`i18n check passed: ${frKeys.size} French keys, ${enKeys.size} English keys, ${usedKeys.size} literal t() keys.`);
}

// Guarded exactly like scripts/check-design-system.mjs: importing this module
// (from src/designSystem.test.js) must not trigger the CLI check itself —
// including its process.exit(1) — as a side effect of the import.
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
