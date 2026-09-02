#!/usr/bin/env node
/**
 * Retrait des commentaires du code de production — 2026-09-01.
 *
 * Contexte. La règle du projet est qu'aucun commentaire ne vit dans `src/` : le
 * « pourquoi » appartient au coffre Obsidian, pas au fichier. 1 313 lignes s'y étaient
 * accumulées sur 57 fichiers. Un agent a d'abord été chargé de les retirer à la main :
 * il a supprimé 181 lignes de code de `ThreatHuntPage.jsx`, 115 de
 * `GlobalNetworkMapPage.jsx`, et déclaré la tâche réussie. Le build passait — le code
 * perdu était de l'UI non couverte par les tests, donc cassée à l'exécution seulement.
 *
 * D'où ce script. Il ne RÉIMPRIME jamais le code : il parse pour obtenir les plages
 * d'octets des commentaires et les retire de la source d'origine. Reformater, réindenter
 * ou perdre du code est impossible par construction.
 *
 * L'invariant. Avant d'écrire un fichier, le flux de jetons du résultat doit être
 * exactement égal au flux d'origine privé des jetons tombant dans les plages supprimées.
 * Un fichier qui rompt l'invariant n'est pas écrit et le script sort en erreur. C'est
 * cette vérification qui a bloqué 35 fichiers au premier passage.
 *
 * La seule relaxation admise concerne le texte JSX purement blanc : retirer un
 * `{/* … *\/}` entre deux éléments fusionne les nœuds de texte qui l'entouraient, et
 * React ne rend pas un texte blanc contenant un saut de ligne.
 *
 * Usage :
 *   node scripts/strip-comments.mjs                 # contrôle, n'écrit rien
 *   node scripts/strip-comments.mjs --write         # applique
 *   node scripts/strip-comments.mjs --write src/pages
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { parse } from '@babel/parser';

const DEFAUT = ['src'];
const EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx']);
const IGNORE_FICHIER = /\.test\.|\.spec\./;
const IGNORE_DOSSIER = new Set(['node_modules', 'dist', '__tests__', '__snapshots__']);

const GARDER = /(^|\s)(eslint-|ts-ignore|ts-expect-error|ts-nocheck|prettier-ignore|@ts-|webpackChunkName|c8 ignore|istanbul ignore|v8 ignore)/;

const OPTIONS = {
  sourceType: 'module',
  allowReturnOutsideFunction: true,
  plugins: ['jsx', 'typescript', 'classProperties', 'objectRestSpread',
            'optionalChaining', 'nullishCoalescingOperator', 'dynamicImport',
            'topLevelAwait', 'decorators-legacy'],
};

const analyser = (code) => parse(code, { ...OPTIONS, tokens: true });

function conteneursJsxVides(ast) {
  const plages = [];
  const visiter = (n) => {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { n.forEach(visiter); return; }
    if (n.type === 'JSXExpressionContainer' && n.expression?.type === 'JSXEmptyExpression') {
      plages.push([n.start, n.end]);
      return;
    }
    for (const k of Object.keys(n)) {
      if (k === 'loc' || k.endsWith('Comments')) continue;
      visiter(n[k]);
    }
  };
  visiter(ast.program);
  return plages;
}

function fusionner(plages) {
  const out = [];
  for (const p of [...plages].sort((a, b) => a[0] - b[0])) {
    const d = out[out.length - 1];
    if (d && p[0] <= d[1]) d[1] = Math.max(d[1], p[1]);
    else out.push([...p]);
  }
  return out;
}

const dans = (plages, a, b) => plages.some(([x, y]) => a >= x && b <= y);

const significatif = (t) => {
  const label = t.type?.label ?? t.type;
  return label !== 'jsxText' || !/^\s*$/.test(t.value ?? '');
};

const empreinte = (tokens, plages) => tokens
  .filter(t => t.type !== 'CommentLine' && t.type !== 'CommentBlock')
  .filter(t => !plages || !dans(plages, t.start, t.end))
  .filter(significatif)
  .map(t => `${t.type?.label ?? t.type} ${t.value ?? ''}`);

export function stripComments(code) {
  const ast = analyser(code);

  const commentaires = (ast.comments || [])
    .filter(c => !GARDER.test(c.value))
    .filter(c => !(c.start === 0 && code.startsWith('#!')));

  const plages = fusionner([
    ...commentaires.map(c => [c.start, c.end]),
    ...conteneursJsxVides(ast),
  ]);
  if (!plages.length) return { code, retires: 0, lignes: 0 };

  const etendues = plages.map(([a, b]) => {
    let i = a - 1;
    while (i >= 0 && (code[i] === ' ' || code[i] === '\t')) i--;
    let fin = b;
    if (i < 0 || code[i] === '\n') {
      if (code[fin] === '\r') fin++;
      if (code[fin] === '\n') fin++;
    }
    return [i + 1, fin];
  });

  let out = '';
  let curseur = 0;
  for (const [a, b] of fusionner(etendues)) { out += code.slice(curseur, a); curseur = b; }
  out += code.slice(curseur);
  out = out.replace(/\n{3,}/g, '\n\n');

  const attendus = empreinte(ast.tokens || [], plages);
  const obtenus = empreinte(analyser(out).tokens || [], null);
  if (attendus.length !== obtenus.length) {
    throw new Error(`invariant rompu : ${attendus.length} jetons attendus, ${obtenus.length} obtenus`);
  }
  for (let i = 0; i < attendus.length; i++) {
    if (attendus[i] !== obtenus[i]) {
      throw new Error(`invariant rompu au jeton ${i} : « ${attendus[i]} » devient « ${obtenus[i]} »`);
    }
  }

  return { code: out, retires: plages.length, lignes: code.split('\n').length - out.split('\n').length };
}

function fichiers(racine, acc = []) {
  for (const e of readdirSync(racine)) {
    if (IGNORE_DOSSIER.has(e)) continue;
    const p = join(racine, e);
    if (statSync(p).isDirectory()) fichiers(p, acc);
    else if (EXTENSIONS.has(extname(p)) && !IGNORE_FICHIER.test(e)) acc.push(p);
  }
  return acc;
}

const args = process.argv.slice(2);
const ecrire = args.includes('--write');
const cibles = args.filter(a => !a.startsWith('--'));

let modifies = 0, lignes = 0;
const refuses = [];

for (const racine of (cibles.length ? cibles : DEFAUT)) {
  for (const f of fichiers(racine)) {
    let r;
    try { r = stripComments(readFileSync(f, 'utf8')); }
    catch (e) { refuses.push(`${f} : ${e.message}`); continue; }
    if (!r.retires) continue;
    modifies++; lignes += r.lignes;
    if (ecrire) writeFileSync(f, r.code);
    else console.log(`  ${f} — ${r.retires} commentaires, ${r.lignes} lignes`);
  }
}

const verbe = ecrire ? 'nettoyés' : 'à nettoyer';
console.log(`strip-comments : ${modifies} fichiers ${verbe}, ${lignes} lignes, ${refuses.length} refusés`);
refuses.forEach(r => console.log(`  REFUSÉ ${r}`));
if (refuses.length) process.exitCode = 1;
