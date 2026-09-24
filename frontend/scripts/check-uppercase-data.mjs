#!/usr/bin/env node
/**
 * Majuscules forcees sur de la DONNEE — 2026-09-22.
 *
 * Contexte. Le bloc d'integrite du panneau d'import portait
 * `className="text-xs font-mono uppercase tracking-widest"` sur un titre qui
 * interpole le nom du fichier. A l'ecran :
 *
 *   sur disque   LAB_Xtended-lab_2026.03.24_09.06.22.zip
 *   affiche      LAB_XTENDED-LAB_2026.03.24_09.06.22.ZIP
 *
 * La casse d'un nom de fichier est une donnee de la machine analysee. NTFS la
 * preserve. Un analyste qui recopie ce nom dans un rapport ecrit un nom qui
 * n'existe pas, et un contradicteur peut le relever.
 *
 * La charte anti-cliche bannit deja MAJUSCULES + interlettrage comme tic de
 * tableau de bord. Ce garde vise le sous-ensemble qui n'est pas une question de
 * gout : celui qui REECRIT une valeur. Un libelle statique mis en capitales est
 * laid ; une donnee mise en capitales est fausse.
 *
 * ── Ce qui est signale, et ce qui ne l'est pas ──────────────────────────────
 *
 * Signale : un element dont le style ou la classe force `uppercase` ET dont les
 * enfants contiennent une expression qui n'est pas un appel a `t(...)`.
 *
 * Non signale : `{t('...')}` seul. Une chaine de traduction est ecrite par nous,
 * pas lue sur la machine analysee ; la mettre en capitales reste un choix de
 * presentation, couvert par le cliquet de `design:check`, pas par ce garde.
 *
 * Non signale non plus : du texte statique. `<span className="uppercase">IOCs
 * </span>` ne reecrit rien.
 *
 * ── Calibrage ───────────────────────────────────────────────────────────────
 *
 * `--selftest` fait passer deux fixtures : une qui DOIT etre signalee et une
 * qui ne doit pas l'etre. Cinq zeros ne distinguent pas un balayage reussi d'un
 * detecteur casse — il faut voir le garde accuser quelque chose de connu.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';

const traverse = _traverse.default || _traverse;
const RACINE = new URL('../src', import.meta.url).pathname;
const IGNORE_FICHIER = /\.test\.|\.spec\./;

// La couche « wow » de LoginPage est un choix assume de l'utilisateur, nomme
// dans la charte anti-cliche : « ne pas la corriger sans le lui demander ».
// L'exemption est ecrite ici plutot que laissee en rouge permanent — un garde
// qui echoue toujours cesse d'etre lu, et couvre alors les vraies regressions.
const EXEMPTS = new Set(['pages/LoginPage.jsx']);

function fichiers(dir, acc = []) {
  for (const nom of readdirSync(dir)) {
    const p = join(dir, nom);
    if (statSync(p).isDirectory()) fichiers(p, acc);
    else if (/\.(jsx?|tsx?)$/.test(nom) && !IGNORE_FICHIER.test(nom)) acc.push(p);
  }
  return acc;
}

function forceMajuscules(ouverture) {
  for (const attr of ouverture.attributes || []) {
    if (attr.type !== 'JSXAttribute' || !attr.name) continue;

    if (attr.name.name === 'className') {
      const v = attr.value;
      if (v?.type === 'StringLiteral' && /\buppercase\b/.test(v.value)) return true;
      if (v?.type === 'JSXExpressionContainer') {
        const brut = JSON.stringify(v.expression);
        if (/\\"uppercase/.test(brut) || /uppercase/.test(brut)) return true;
      }
    }

    if (attr.name.name === 'style' && attr.value?.type === 'JSXExpressionContainer') {
      const brut = JSON.stringify(attr.value.expression);
      if (/textTransform/.test(brut) && /uppercase/.test(brut)) return true;
    }
  }
  return false;
}

function estAppelTraduction(expr) {
  if (!expr) return false;
  if (expr.type === 'CallExpression') {
    const c = expr.callee;
    if (c.type === 'Identifier' && c.name === 't') return true;
    if (c.type === 'MemberExpression' && c.property?.name === 't') return true;
  }
  if (expr.type === 'LogicalExpression') return estAppelTraduction(expr.left) && estAppelTraduction(expr.right);
  if (expr.type === 'ConditionalExpression') {
    return estAppelTraduction(expr.consequent) && estAppelTraduction(expr.alternate);
  }
  return false;
}

// Un identifiant nu (`{label}`, `{titre}`) est presque toujours un libelle
// recu en prop, souvent un litteral cote appelant. Ce qui REECRIT une valeur,
// c'est la lecture d'un champ sur un enregistrement : `{ev.name}`,
// `{r.host_name}`, `{row.CommandLine}`. Le garde ne vise que celle-la.
//
// Mesure du 2026-09-22 : la version large signalait 61 elements, dont
// `DetailsTab.jsx:66` — qui interpole `{label}`, alors que ses appelants
// passent \"Description\", \"Host\", \"User\". Un garde qui accuse 61 sites dont
// la plupart sont sains n'est plus lu.
function lectureDeChamp(expr) {
  if (!expr) return false;
  if (expr.type === 'MemberExpression' || expr.type === 'OptionalMemberExpression') return true;
  if (expr.type === 'LogicalExpression') return lectureDeChamp(expr.left) || lectureDeChamp(expr.right);
  if (expr.type === 'ConditionalExpression') {
    return lectureDeChamp(expr.consequent) || lectureDeChamp(expr.alternate);
  }
  if (expr.type === 'TemplateLiteral') return expr.expressions.some(lectureDeChamp);
  return false;
}

function donneeInterpolee(element) {
  for (const enfant of element.children || []) {
    if (enfant.type !== 'JSXExpressionContainer') continue;
    const e = enfant.expression;
    if (!e || e.type === 'JSXEmptyExpression') continue;
    if (estAppelTraduction(e)) continue;
    if (lectureDeChamp(e)) return true;
  }
  return false;
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
    JSXElement(chemin) {
      const n = chemin.node;
      if (!forceMajuscules(n.openingElement)) return;
      if (!donneeInterpolee(n)) return;
      trouvailles.push({ fichier: nom, ligne: n.loc?.start.line ?? 0 });
    },
  });
  return trouvailles;
}

const FIXTURES = {
  fautive: `const A = () => <span className="uppercase">{ev.name}</span>;`,
  saine: `const B = () => <span className="uppercase">{t('x.y')}</span>;`,
  labelNu: `const C = () => <span className="uppercase">{label}</span>;`,
};

if (process.argv.includes('--selftest')) {
  const f = analyser(FIXTURES.fautive, 'fixture-fautive');
  const s = analyser(FIXTURES.saine, 'fixture-saine');
  const l = analyser(FIXTURES.labelNu, 'fixture-label-nu');
  const ok = f.length === 1 && s.length === 0 && l.length === 0;
  console.log(ok
    ? 'selftest ok : lecture de champ signalee ; traduction et libelle nu epargnes'
    : `selftest ECHOUE : champ=${f.length} (1), traduction=${s.length} (0), libelle=${l.length} (0)`);
  process.exit(ok ? 0 : 1);
}

const tous = [];
for (const p of fichiers(RACINE)) {
  const rel = relative(RACINE, p);
  if (EXEMPTS.has(rel)) continue;
  tous.push(...analyser(readFileSync(p, 'utf8'), rel));
}

if (tous.length === 0) {
  console.log('uppercase-data check passed : aucune donnee reecrite en majuscules');
  process.exit(0);
}

console.error(`uppercase-data check : ${tous.length} element(s) forcent des majuscules sur une valeur interpolee\n`);
for (const t of tous) console.error(`  ${t.fichier}:${t.ligne}`);
process.exit(1);
