#!/usr/bin/env node
/**
 * Une couleur du DOM qui recopie un jeton au lieu de le lire — 2026-09-21.
 *
 * Contexte. `index.css` declare 55 couleurs en variables `--fl-*`. Mesure du
 * jour : 85 hexadecimaux ecrits en dur dans `src/` valent EXACTEMENT l'une
 * d'elles. Neuf fois `#131722`, qui est `--fl-card`. Cinq fois `#0a0c11`, qui
 * est `--fl-bg`.
 *
 * Ce n'est pas une question de proprete. `index.css` declare DEUX palettes :
 * `:root` pour le theme sombre, `body.theme-light` pour le clair, et
 * `utils/theme.jsx` expose un basculement vivant. Un hexadecimal sombre ecrit
 * en dur ne suit pas ce basculement : la surface reste sombre pendant que le
 * texte passe en fonce. Ce n'est pas une derive a venir, c'est un defaut
 * present sur tout ecran ouvert en theme clair.
 *
 * Le garde ne lit donc QUE le bloc `:root`. Une premiere version prenait la
 * premiere declaration venue et accusait `#ffffff` de recopier `--fl-panel`,
 * qui vaut `#0e1118` en sombre et `#ffffff` en clair. Deux faux positifs, vus
 * avant d'agir dessus — le selftest verrouille ce cas.
 *
 * ── Ce que ce garde ne regarde pas, et pourquoi ─────────────────────────────
 *
 * Il ne couvre que les `.jsx`, c'est-a-dire le DOM. Les 49 hexadecimaux des
 * `.js` alimentent **Cytoscape**, qui rend sur canvas et ne sait pas lire une
 * variable CSS : `cytoscapeConfig.js`, `nodeTypes.js`, `nodeTypeRegistry.js`.
 * Ces valeurs DOIVENT rester litterales, et chacune porte en plus sa variante
 * daltonienne — c'est du travail delibere, pas une derive.
 *
 * Les condamner aurait ete la faute classique : un controle qui crie a plus de
 * chances d'avoir tort que le code qu'il accuse. Elles restent un chantier
 * ouvert — les resoudre une fois au demarrage depuis la palette donnerait une
 * source unique — mais c'est un changement du rendu, pas du style.
 *
 * ── La position compte ─────────────────────────────────────────────────────
 *
 * Seuls les hexadecimaux en POSITION DE PROPRIETE CSS sont signales. Mesure :
 * `GlobalMapToolbar.jsx` porte `useState('#8b7fff')` qui alimente un
 * `<input type="color">` — cet element EXIGE un hexadecimal litteral, et un
 * `var()` le remettrait a noir. Migrer aveuglement aurait casse le selecteur
 * de couleur des regles de sous-reseau.
 *
 * L'exemption ne passe pas par un commentaire : `comments:check` les interdit
 * dans `src/`. Elle passe par la grammaire du site d'appel, qui ne ment pas.
 *
 * Usage :
 *   node scripts/check-palette-tokens.mjs
 *   node scripts/check-palette-tokens.mjs --selftest
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname, relative, resolve } from 'path';
import { fileURLToPath } from 'url';

const FEUILLE = 'src/index.css';
const RACINE = 'src';
const IGNORE_DOSSIER = new Set(['node_modules', 'dist', '__snapshots__']);
const IGNORE_FICHIER = /\.test\.|\.spec\./;

export function jetonsDe(css) {
  const texte = String(css);
  const debut = texte.indexOf(':root {');
  const base = debut < 0 ? '' : texte.slice(debut, texte.indexOf('\n}', debut));

  const table = new Map();
  for (const m of base.matchAll(/(--fl-[\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    const hex = m[2].toLowerCase();
    if (!table.has(hex)) table.set(hex, m[1]);
  }
  return table;
}

const EN_POSITION_CSS =
  /(background|backgroundColor|color|border[A-Za-z]*|outline[A-Za-z]*|fill|stroke|boxShadow|textShadow|caretColor|accentColor)\s*:|gradient\(|color-mix\(|\.style\.[A-Za-z]+\s*=/;

export function copiesDe(source, jetons, etiquette = 'source') {
  const trouves = [];
  const lignes = String(source).split('\n');
  lignes.forEach((ligne, i) => {
    if (!EN_POSITION_CSS.test(ligne)) return;
    for (const m of ligne.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
      const hex = m[0].toLowerCase();
      const jeton = jetons.get(hex);
      if (jeton) trouves.push({ fichier: etiquette, ligne: i + 1, hex, jeton });
    }
  });
  return trouves;
}

function fichiers(dir, acc = []) {
  for (const entree of readdirSync(dir)) {
    if (IGNORE_DOSSIER.has(entree)) continue;
    const chemin = join(dir, entree);
    if (statSync(chemin).isDirectory()) fichiers(chemin, acc);
    else if (extname(chemin) === '.jsx' && !IGNORE_FICHIER.test(chemin)) acc.push(chemin);
  }
  return acc;
}

function selftest() {
  const jetons = jetonsDe(
    ':root {\n  --fl-card: #131722;\n  --fl-bg: #0A0C11;\n}\n'
    + 'body.theme-light {\n  --fl-panel: #ffffff;\n}\n');
  const vus = [...jetons.entries()].map(([h, j]) => `${h}=${j}`).join(' ');

  const copie = copiesDe("const s = { background: '#131722' };", jetons, 'x');
  const casse = copiesDe("const s = { background: '#0a0c11' };", jetons, 'x');
  const sain = copiesDe("const s = { background: 'var(--fl-card)' };", jetons, 'x');
  const etranger = copiesDe("const s = { background: '#abcdef' };", jetons, 'x');

  const clair = copiesDe("const s = { background: '#ffffff' };", jetons, 'x');
  const etat = copiesDe("const [c, setC] = useState('#131722');", jetons, 'x');
  const degrade = copiesDe("const s = { background: `linear-gradient(90deg, #131722, red)` };", jetons, 'x');
  const pointe = copiesDe("e.currentTarget.style.background = '#131722';", jetons, 'x');

  const ok = jetons.size === 2 && clair.length === 0
    && etat.length === 0 && degrade.length === 1 && pointe.length === 1
    && copie.length === 1 && copie[0].jeton === '--fl-card'
    && casse.length === 1 && casse[0].jeton === '--fl-bg'
    && sain.length === 0
    && etranger.length === 0;

  console.log(ok
    ? `selftest : ${vus} — copie vue, casse ignoree, jeton et theme clair laisses, valeur d etat epargnee, degrade et affectation pointee vus`
    : `selftest ECHEC — copie=${copie.length} casse=${casse.length} sain=${sain.length} etranger=${etranger.length} clair=${clair.length}`);
  return ok ? 0 : 1;
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();

  const jetons = jetonsDe(readFileSync(FEUILLE, 'utf8'));
  const tous = [];
  for (const chemin of fichiers(RACINE)) {
    tous.push(...copiesDe(readFileSync(chemin, 'utf8'), jetons, relative('.', chemin)));
  }

  if (tous.length === 0) {
    console.log(`palette check passed : aucune couleur du DOM ne recopie un jeton (${jetons.size} jetons)`);
    return 0;
  }
  for (const c of tous) console.error(`${c.fichier}:${c.ligne} — ${c.hex} recopie ${c.jeton}`);
  console.error(`\n${tous.length} couleur(s) figee(s) sur le theme sombre : elles ne suivront pas le theme clair.`);
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exit(main());
