import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const srcDir = path.join(root, 'src');
const frPath = path.join(srcDir, 'i18n', 'fr.json');
const enPath = path.join(srcDir, 'i18n', 'en.json');
const auditHardcoded = process.argv.includes('--hardcoded');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function flatten(value, prefix = '', out = {}) {
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

const usedKeys = new Set();
for (const file of walk(srcDir)) {
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/\bt\(\s*['"]([^'"]+)['"]/g)) {
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

if (failures.length) {
  console.error(failures.join('\n\n'));
  process.exit(1);
}

console.log(`i18n check passed: ${frKeys.size} French keys, ${enKeys.size} English keys, ${usedKeys.size} literal t() keys.`);
