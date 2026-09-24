#!/usr/bin/env node
/**
 * Identifiants references mais jamais declares — 2026-09-18.
 *
 * Contexte. L'onglet processus du dossier de reference s'affichait entierement
 * noir. Cause : `CollectionProcessesTab.jsx:335` rendait `{nom}` alors que la
 * destructuration de la ligne fournit `name`. Un renommage applique a un seul
 * endroit. A l'execution, `ReferenceError: nom is not defined` pendant le rendu,
 * React 18 demonte l'arbre entier, et l'analyste perd toute l'interface.
 *
 * Pourquoi rien ne l'a vu. La chaine du frontend est `vite build` + `tsc
 * --noEmit` + vitest + trois gardes maison. Aucun ESLint. Et `tsconfig.json`
 * porte `"allowJs": true, "checkJs": false` : `tsc` compile les `.jsx` sans y
 * verifier quoi que ce soit, alors que le frontend est presque entierement en
 * `.jsx`. esbuild, lui, ne fait pas d'analyse de portee. Une ReferenceError nue
 * traversait donc toute la chaine au vert.
 *
 * Ce que fait ce garde. Il parse chaque fichier de `src/` et demande a Babel,
 * pour chaque identifiant reference, s'il possede une liaison dans sa portee.
 * Sans liaison et hors de la liste des globales, c'est un signalement.
 *
 * ── Les globales volontairement ABSENTES de la liste ────────────────────────
 *
 * `name`, `status`, `length`, `origin`, `event`, `open`, `close`, `focus`,
 * `blur`, `find`, `scroll`, `stop`, `print`, `self`, `top`, `parent` existent
 * toutes sur `window`. Les admettre rendrait ce garde aveugle a sa propre
 * raison d'etre : `{nom}` aurait ete signale, mais un `{name}` orphelin — le
 * meme bug dans l'autre sens — serait passe. Une variable de rendu qui porte
 * l'un de ces noms doit etre declaree ; s'appuyer sur la globale du navigateur
 * dans un composant est toujours un accident.
 *
 * Usage :
 *   node scripts/check-undeclared.mjs            # controle
 *   node scripts/check-undeclared.mjs --selftest # controle positif du garde
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

const GLOBALES = new Set([
  'globalThis', 'undefined', 'NaN', 'Infinity',
  'Object', 'Array', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Function',
  'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError',
  'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Proxy', 'Reflect',
  'ArrayBuffer', 'Uint8Array', 'Int32Array', 'Float64Array', 'DataView',
  'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent',
  'decodeURIComponent', 'encodeURI', 'decodeURI', 'structuredClone', 'queueMicrotask',
  'Intl', 'TextEncoder', 'TextDecoder', 'atob', 'btoa',
  'window', 'document', 'console', 'navigator', 'location', 'history', 'screen',
  'localStorage', 'sessionStorage', 'indexedDB', 'matchMedia', 'getComputedStyle',
  'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval',
  'requestAnimationFrame', 'cancelAnimationFrame', 'requestIdleCallback',
  'fetch', 'Headers', 'Request', 'Response', 'AbortController', 'AbortSignal',
  'URL', 'URLSearchParams', 'Blob', 'File', 'FileReader', 'FormData',
  'WebSocket', 'EventSource', 'Worker', 'MessageChannel', 'BroadcastChannel',
  'IntersectionObserver', 'ResizeObserver', 'MutationObserver', 'PerformanceObserver',
  'CustomEvent', 'Event', 'KeyboardEvent', 'MouseEvent', 'DragEvent', 'ErrorEvent',
  'Node', 'Element', 'HTMLElement', 'HTMLInputElement', 'HTMLCanvasElement',
  'SVGElement', 'DOMParser', 'XMLSerializer', 'Image', 'Audio', 'Option',
  'performance', 'crypto', 'alert', 'confirm', 'prompt', 'scrollTo',
  'AudioContext', 'XMLHttpRequest', 'escape', 'unescape',
  'CompressionStream', 'DecompressionStream', 'ReadableStream', 'WritableStream',
  'process', 'Buffer', 'require', 'module', 'exports', '__dirname', '__filename',
  '__APP_VERSION__',
  'describe', 'test', 'it', 'expect', 'vi', 'beforeEach', 'afterEach',
  'beforeAll', 'afterAll', 'global',
]);

function fichiers(dir, acc = []) {
  for (const entree of readdirSync(dir)) {
    if (IGNORE_DOSSIER.has(entree)) continue;
    const chemin = join(dir, entree);
    if (statSync(chemin).isDirectory()) fichiers(chemin, acc);
    else if (EXTENSIONS.has(extname(chemin))) acc.push(chemin);
  }
  return acc;
}

const OPTIONS = {
  sourceType: 'module',
  errorRecovery: true,
  plugins: ['jsx', 'typescript', 'classProperties', 'objectRestSpread',
            'optionalChaining', 'nullishCoalescingOperator', 'topLevelAwait',
            'decorators-legacy', 'dynamicImport'],
};

export function orphelinsDe(source, etiquette = 'source') {
  const ast = parse(source, OPTIONS);
  const trouves = [];
  traverse(ast, {
    ReferencedIdentifier(path) {
      const { node } = path;
      if (node.type === 'JSXIdentifier') {
        if (/^[a-z]/.test(node.name)) return;
        if (path.parentPath?.isJSXAttribute()) return;
      }
      if (path.find(p => p.node.type.startsWith('TS'))) return;
      const nom = node.name;
      if (GLOBALES.has(nom)) return;
      if (path.scope.hasBinding(nom, true)) return;
      trouves.push({ fichier: etiquette, ligne: node.loc?.start.line ?? 0, nom });
    },
  });
  return trouves;
}

function selftest() {
  const sain = 'const a = 1; export const b = a + 1;';
  const casse = 'export function F({ name }) { return name + nom; }';
  const zero = orphelinsDe(sain, 'sain');
  const un = orphelinsDe(casse, 'casse');
  const ok = zero.length === 0 && un.length === 1 && un[0].nom === 'nom';
  console.log(ok
    ? 'selftest : le garde reconnait un identifiant fabrique et laisse passer le code sain'
    : `selftest ECHEC — sain=${JSON.stringify(zero)} casse=${JSON.stringify(un)}`);
  return ok ? 0 : 1;
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();

  const tous = [];
  for (const chemin of fichiers(RACINE)) {
    try {
      tous.push(...orphelinsDe(readFileSync(chemin, 'utf8'), relative('.', chemin)));
    } catch (e) {
      console.error(`parse impossible : ${chemin} — ${e.message}`);
      return 1;
    }
  }

  if (tous.length === 0) {
    console.log('undeclared check passed : aucun identifiant reference sans liaison');
    return 0;
  }
  for (const o of tous) console.error(`${o.fichier}:${o.ligne} — '${o.nom}' n'est declare nulle part`);
  console.error(`\n${tous.length} identifiant(s) sans liaison. Chacun est une ReferenceError a l'execution.`);
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exit(main());
