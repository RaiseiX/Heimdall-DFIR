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

  const missingUsed = [...usedKeys].filter(key => !frKeys.has(key) || !enKeys.has(key)).sort();
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
