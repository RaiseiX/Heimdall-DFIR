#!/usr/bin/env node
/**
 * Génère les polices auto-hébergées depuis l'API CSS de Google Fonts.
 * Reproductible : `node scripts/generate-fonts.mjs` régénère public/fonts
 * et src/fonts.css à l'identique. Aucune requête réseau au runtime.
 *
 * Tout se construit dans un répertoire et un fichier temporaires, siblings
 * de la sortie réelle. Le remplacement de `public/fonts/` et l'écriture de
 * `src/fonts.css` n'ont lieu qu'une fois tous les téléchargements réussis et
 * le contenu CSS entièrement assemblé. Si quoi que ce soit échoue en cours de
 * route — limite de débit, coupure réseau, réponse de Google qui change de
 * forme — `public/fonts/` et `src/fonts.css` existants restent intacts et le
 * script sort en erreur. `public/fonts/` n'est pas suivi par git : il n'y a
 * pas de `git checkout` pour se rattraper d'une exécution interrompue.
 */
import fs from 'node:fs';
import path from 'node:path';

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
// GENERATE_FONTS_ROOT permet de rejouer ce script contre un répertoire de
// test (voir la preuve de la Task 3) sans jamais toucher au vrai
// `public/fonts/`. Absent, le comportement est inchangé.
const ROOT = process.env.GENERATE_FONTS_ROOT
  ? path.resolve(process.env.GENERATE_FONTS_ROOT)
  : path.resolve(import.meta.dirname, '..');
const OUT_DIR = path.join(ROOT, 'public', 'fonts');
const OUT_CSS = path.join(ROOT, 'src', 'fonts.css');
const TMP_DIR = `${OUT_DIR}.tmp`;
const TMP_CSS = `${OUT_CSS}.tmp`;

const FAMILLES = [
  { nom: 'IBM Plex Sans',           spec: 'IBM+Plex+Sans:wght@400;500;600;700' },
  { nom: 'IBM Plex Sans Condensed', spec: 'IBM+Plex+Sans+Condensed:wght@400;600;700' },
  { nom: 'IBM Plex Mono',           spec: 'IBM+Plex+Mono:wght@400;500;600' },
];
const SOUS_ENSEMBLES = new Set(['latin', 'latin-ext']);

const recuperer = async (url, avecUa) => {
  const r = await fetch(url, avecUa ? { headers: { 'User-Agent': UA } } : undefined);
  if (!r.ok) throw new Error(`${r.status} sur ${url}`);
  return avecUa ? r.text() : Buffer.from(await r.arrayBuffer());
};

const nettoyerTemp = () => {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
  fs.rmSync(TMP_CSS, { force: true });
};

// Résidu d'une exécution précédente interrompue avant le nettoyage final.
nettoyerTemp();
fs.mkdirSync(TMP_DIR, { recursive: true });

try {
  const blocs = [
    '/* Polices auto-hébergées — aucune dépendance réseau externe.',
    '   GÉNÉRÉ PAR scripts/generate-fonts.mjs — ne pas éditer à la main.',
    '   Un poste d\'analyse isolé doit rendre la typographie à l\'identique. */',
  ];

  for (const { nom, spec } of FAMILLES) {
    const css = await recuperer(`https://fonts.googleapis.com/css2?family=${spec}&display=swap`, true);
    for (const [, sousEnsemble, corps] of css.matchAll(/\/\*\s*([\w-]+)\s*\*\/\s*@font-face\s*\{([^}]*)\}/g)) {
      if (!SOUS_ENSEMBLES.has(sousEnsemble)) continue;
      const poids = corps.match(/font-weight:\s*(\d+)/)?.[1];
      const url = corps.match(/url\((https:\/\/[^)]+\.woff2)\)/)?.[1];
      const plage = corps.match(/unicode-range:\s*([^;]+);/)?.[1]?.trim();
      if (!(poids && url && plage)) continue;

      const fichier = `${nom.replace(/\s+/g, '')}-${poids}-${sousEnsemble}.woff2`;
      fs.writeFileSync(path.join(TMP_DIR, fichier), await recuperer(url, false));
      blocs.push(
        '@font-face {',
        `  font-family: '${nom}';`,
        '  font-style: normal;',
        `  font-weight: ${poids};`,
        '  font-display: swap;',
        `  src: url('/fonts/${fichier}') format('woff2');`,
        `  unicode-range: ${plage};`,
        '}',
      );
      console.log(`  ${fichier}`);
    }
  }

  fs.writeFileSync(TMP_CSS, blocs.join('\n') + '\n');

  // Tout a réussi — bascule atomique. C'est la seule fenêtre où l'ancienne
  // sortie est touchée, et elle n'est atteinte qu'après succès complet.
  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.renameSync(TMP_DIR, OUT_DIR);
  fs.renameSync(TMP_CSS, OUT_CSS);

  console.log(`\n${fs.readdirSync(OUT_DIR).length} fichiers · ${OUT_CSS} réécrit`);
} catch (err) {
  nettoyerTemp();
  console.error(
    `\nÉchec de la génération des polices — public/fonts/ et src/fonts.css ` +
    `existants n'ont pas été modifiés.\n${err.message}`,
  );
  process.exit(1);
}
