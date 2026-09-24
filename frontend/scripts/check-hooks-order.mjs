#!/usr/bin/env node
/**
 * Un hook place apres un retour anticipe — 2026-09-21.
 *
 * Contexte. `CollectionProcessesTab` porte trois sorties precoces : chargement,
 * erreur, liste vide. Un `useEffect` ajoute APRES elles ne s'execute pas au
 * premier rendu et s'execute au suivant. React compte alors plus de hooks qu'au
 * tour precedent et leve l'invariant 310 — « Rendered more hooks than during
 * the previous render ». L'onglet entier disparait.
 *
 * C'est le deuxieme plantage de rendu de la meme journee, et le deuxieme que ni
 * `tsc`, ni le build, ni 952 tests n'ont vu : aucun d'eux n'execute un rendu.
 * Seul le garde-fou d'erreur l'a rapporte, a l'ecran, chez l'utilisateur.
 *
 * Ce que fait ce garde. Pour chaque fonction de composant, il parcourt les
 * instructions de premier niveau dans l'ordre. Des qu'une instruction peut
 * sortir de la fonction, toute instruction suivante contenant un appel `useXxx`
 * est signalee. C'est exactement la regle des hooks de React, appliquee au seul
 * cas qui se produit vraiment ici.
 *
 * Ce qu'il ne fait pas. Il ignore les fonctions imbriquees : un `return` dans un
 * callback ne sort pas du composant. Et il ne juge pas les hooks conditionnels
 * d'autres formes — ce garde couvre la faute constatee, pas la theorie.
 *
 * Usage :
 *   node scripts/check-hooks-order.mjs
 *   node scripts/check-hooks-order.mjs --selftest
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname, relative, resolve } from 'path';
import { fileURLToPath } from 'url';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';

const traverse = _traverse.default || _traverse;

const RACINE = 'src';
const EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx']);
const IGNORE_DOSSIER = new Set(['node_modules', 'dist', '__snapshots__']);
const IGNORE_FICHIER = /\.test\.|\.spec\./;

const OPTIONS = {
  sourceType: 'module',
  plugins: ['jsx', 'typescript', 'classProperties', 'objectRestSpread', 'decorators-legacy'],
};

function fichiers(dir, acc = []) {
  for (const entree of readdirSync(dir)) {
    if (IGNORE_DOSSIER.has(entree)) continue;
    const chemin = join(dir, entree);
    if (statSync(chemin).isDirectory()) fichiers(chemin, acc);
    else if (EXTENSIONS.has(extname(chemin)) && !IGNORE_FICHIER.test(chemin)) acc.push(chemin);
  }
  return acc;
}

function estHook(noeud) {
  return noeud.type === 'CallExpression'
    && noeud.callee.type === 'Identifier'
    && /^use[A-Z]/.test(noeud.callee.name);
}

function contient(noeud, predicat, dansFonction = false) {
  let trouve = false;
  const voir = (n, imbrique) => {
    if (trouve || !n || typeof n.type !== 'string') return;
    if (predicat(n, imbrique)) { trouve = true; return; }
    const sousFonction = imbrique
      || n.type === 'FunctionExpression'
      || n.type === 'ArrowFunctionExpression'
      || n.type === 'FunctionDeclaration';
    for (const cle of Object.keys(n)) {
      if (cle === 'loc' || cle === 'start' || cle === 'end') continue;
      const v = n[cle];
      if (Array.isArray(v)) v.forEach(x => voir(x, sousFonction));
      else if (v && typeof v.type === 'string') voir(v, sousFonction);
    }
  };
  voir(noeud, dansFonction);
  return trouve;
}

export function hooksApresRetour(source, etiquette = 'source') {
  const ast = parse(source, OPTIONS);
  const trouves = [];

  const examiner = (corps, nom) => {
    if (!corps || corps.type !== 'BlockStatement') return;
    let sortiePossible = false;
    for (const instruction of corps.body) {
      if (sortiePossible
          && contient(instruction, (n, imbrique) => !imbrique && estHook(n))) {
        trouves.push({
          fichier: etiquette,
          ligne: instruction.loc?.start.line ?? 0,
          composant: nom,
        });
      }
      if (contient(instruction, (n, imbrique) => !imbrique && n.type === 'ReturnStatement')) {
        sortiePossible = true;
      }
    }
  };

  traverse(ast, {
    FunctionDeclaration(path) { examiner(path.node.body, path.node.id?.name || 'anonyme'); },
    ArrowFunctionExpression(path) {
      const nom = path.parent?.type === 'VariableDeclarator' ? path.parent.id?.name : 'anonyme';
      examiner(path.node.body, nom);
    },
    FunctionExpression(path) { examiner(path.node.body, path.node.id?.name || 'anonyme'); },
  });

  return trouves;
}

function selftest() {
  const sain = `
    function C() {
      const [a, setA] = useState(0);
      useEffect(() => {}, []);
      if (!a) return null;
      return a;
    }`;
  const casse = `
    function C() {
      const [a, setA] = useState(0);
      if (!a) return null;
      useEffect(() => {}, []);
      return a;
    }`;
  const imbrique = `
    function C() {
      const f = () => { if (1) return 2; };
      useEffect(() => {}, []);
      return f;
    }`;

  const z = hooksApresRetour(sain, 'sain');
  const u = hooksApresRetour(casse, 'casse');
  const i = hooksApresRetour(imbrique, 'imbrique');
  const ok = z.length === 0 && u.length === 1 && i.length === 0;
  console.log(ok
    ? 'selftest : le garde voit un hook apres retour, ignore un retour imbrique, laisse passer le code sain'
    : `selftest ECHEC — sain=${z.length} casse=${u.length} imbrique=${i.length}`);
  return ok ? 0 : 1;
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();

  const tous = [];
  for (const chemin of fichiers(RACINE)) {
    try {
      tous.push(...hooksApresRetour(readFileSync(chemin, 'utf8'), relative('.', chemin)));
    } catch (e) {
      console.error(`parse impossible : ${chemin} — ${e.message}`);
      return 1;
    }
  }

  if (tous.length === 0) {
    console.log('hooks order check passed : aucun hook apres un retour anticipe');
    return 0;
  }
  for (const o of tous) {
    console.error(`${o.fichier}:${o.ligne} — hook apres un retour anticipe dans ${o.composant}`);
  }
  console.error(`\n${tous.length} hook(s) mal places. Chacun casse le rendu des que la sortie precoce est empruntee.`);
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exit(main());
