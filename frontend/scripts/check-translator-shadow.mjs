#!/usr/bin/env node
/**
 * Traducteur masque — 2026-09-22.
 *
 * Contexte. Le gestionnaire `artifact_done` du panneau d'import contenait :
 *
 *   const t = totalRef.current || data.total || 1;
 *   ...
 *   addLog(t('collection.import.log.artifact_success', { ... }));
 *
 * `const t` masque, dans ce bloc, la fonction `t` de `useTranslation()`. Le
 * second appel invoque un nombre : `TypeError: t is not a function`, a chaque
 * parseur termine avec des lignes, ignore ou en erreur. Le `setParserStates`
 * qui suit ne s'execute jamais — l'etat du parseur reste « en cours ».
 *
 * Les deux lignes sont arrivees ensemble, dans 9fb179b du 2026-07-01 : la
 * traduction des messages du journal a introduit `t(...)` dans un bloc ou `t`
 * designait deja le total. Aucun test ne rend ce panneau.
 *
 * ── La regle ────────────────────────────────────────────────────────────────
 *
 * Signale : un appel `t(...)` dont la liaison n'est pas `useTranslation()`,
 * alors que la liaison visible juste au-dessus de celle-ci l'est.
 *
 * Non signale : un `t` local jamais appele (`const t = setTimeout(...)` puis
 * `clearTimeout(t)`) — inoffensif. Ni une fonction qui recoit le traducteur en
 * parametre hors de tout composant (`getTourSteps(t)`) — rien n'est masque.
 *
 * Babel resout les portees : le garde ne devine pas, il lit la liaison reelle.
 *
 * ── Calibrage ───────────────────────────────────────────────────────────────
 *
 * `--selftest` fait passer quatre fixtures, dont le motif exact du panneau.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';

const traverse = _traverse.default || _traverse;
const RACINE = new URL('../src', import.meta.url).pathname;
const IGNORE_FICHIER = /\.test\.|\.spec\./;

function fichiers(dir, acc = []) {
  for (const nom of readdirSync(dir)) {
    const p = join(dir, nom);
    if (statSync(p).isDirectory()) fichiers(p, acc);
    else if (/\.(jsx?|tsx?)$/.test(nom) && !IGNORE_FICHIER.test(nom)) acc.push(p);
  }
  return acc;
}

function estTraducteur(liaison) {
  if (!liaison || !liaison.path.isVariableDeclarator()) return false;
  const init = liaison.path.node.init;
  if (!init || init.type !== 'CallExpression') return false;
  const c = init.callee;
  const appele = c.type === 'Identifier' ? c.name : c.type === 'MemberExpression' ? c.property?.name : null;
  return appele === 'useTranslation';
}

function analyser(source, nom) {
  const trouvailles = [];
  let ast;
  try {
    ast = parse(source, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator'],
    });
  } catch {
    return trouvailles;
  }
  traverse(ast, {
    CallExpression(chemin) {
      const c = chemin.node.callee;
      if (c.type !== 'Identifier' || c.name !== 't') return;
      const liaison = chemin.scope.getBinding('t');
      if (!liaison || estTraducteur(liaison)) return;
      const dessus = liaison.scope.parent && liaison.scope.parent.getBinding('t');
      if (!estTraducteur(dessus)) return;
      trouvailles.push({
        fichier: nom,
        ligne: chemin.node.loc?.start.line ?? 0,
        masque: liaison.path.node.loc?.start.line ?? 0,
      });
    },
  });
  return trouvailles;
}

const FIXTURES = {
  fautive: `
    function P() {
      const { t } = useTranslation();
      function h(d) {
        if (d.type === 'done') {
          const t = total || 1;
          log(t('x.y'));
        }
      }
    }`,
  saine: `
    function P() {
      const { t } = useTranslation();
      return t('a.b');
    }`,
  parametre: `
    function etapes(t) {
      return [t('a.b')];
    }`,
  masqueNonAppele: `
    function P() {
      const { t } = useTranslation();
      const f = () => { const t = setTimeout(x, 1); return () => clearTimeout(t); };
      return t('a.b');
    }`,
};

if (process.argv.includes('--selftest')) {
  const f = analyser(FIXTURES.fautive, 'fixture-fautive');
  const s = analyser(FIXTURES.saine, 'fixture-saine');
  const p = analyser(FIXTURES.parametre, 'fixture-parametre');
  const m = analyser(FIXTURES.masqueNonAppele, 'fixture-masque-non-appele');
  const ok = f.length === 1 && s.length === 0 && p.length === 0 && m.length === 0;
  console.log(ok
    ? 'selftest ok : appel du masque signale ; usage normal, parametre et masque non appele epargnes'
    : `selftest ECHOUE : fautive=${f.length} (1), saine=${s.length} (0), parametre=${p.length} (0), masque-non-appele=${m.length} (0)`);
  process.exit(ok ? 0 : 1);
}

const tous = [];
for (const p of fichiers(RACINE)) {
  tous.push(...analyser(readFileSync(p, 'utf8'), relative(RACINE, p)));
}

if (tous.length === 0) {
  console.log('translator-shadow check passed : aucun appel de t() ne vise une liaison masquante');
  process.exit(0);
}

console.error(`translator-shadow check : ${tous.length} appel(s) de t() visent une liaison qui masque le traducteur\n`);
for (const x of tous) console.error(`  ${x.fichier}:${x.ligne}  (masque declare ligne ${x.masque})`);
process.exit(1);
