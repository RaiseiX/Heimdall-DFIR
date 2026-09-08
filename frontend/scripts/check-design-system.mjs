#!/usr/bin/env node
/**
 * Garde-fou du langage de design — 2026-08-04.
 *
 * Contexte. Trois substrats de design ont été écrits pour ce frontend.
 * `src/utils/designTokens.js` contenait une échelle d'espacement et une palette
 * complètes : il n'a jamais été importé une seule fois, et il a fini par être
 * supprimé. La couche CSS `.fl-*` est appelée 159 fois contre 4 892 `style={{`.
 * `components/ui/Alert` n'est utilisé nulle part, alors que 21 fichiers gèrent un
 * état d'erreur à la main.
 *
 * La qualité du substrat n'a jamais été le problème : l'adoption l'est. Ce script
 * est le mécanisme d'adoption. Les CEILINGS sont des maxima décroissants — chaque
 * lot de migration en abaisse au moins un, aucun lot ne peut les remonter.
 * Baisser un plafond fait partie du lot ; le remonter est un échec du lot.
 *
 * Il vit dans `scripts/` et non dans un `*.test.js` parce que `.gitignore` exclut
 * tous les tests du dépôt : un garde-fou dans un test ne survivrait pas à un clone.
 * Deux points d'entrée, un seul calcul — `npm run design:check` et `npm test` via
 * `src/designSystem.test.js`.
 *
 */
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const srcDir = path.join(root, 'src');

/**
 * Maxima mesurés le 2026-08-04 sur `frontend/src`. À BAISSER, jamais à monter.
 * 2026-08-13, lot « login photo nue » : les styles inline et les tailles littérales de la
 * carte de connexion sont passés en classes CSS. Mesures réelles 4759 -> 4734 et 1965 -> 1960.
 * Les plafonds sont abaissés du même montant, la marge existante est conservée telle quelle.
 */
export const CEILINGS = {
  inlineStyle: 4857,
  halfPixel: 203,
  literalFontSize: 2009,
  pictogramCode: 165,
};

/**
 * Ces motifs comptent des occurrences de substrings, pas des attributs JSX
 * analysés : `inlineStyle` matche `style={{` littéralement, y compris dans
 * un commentaire JSDoc (ex. `utils/theme.jsx:7`). C'est auto-cohérent pour un
 * cliquet — la même règle s'applique avant et après un lot de migration —
 * mais le compte n'est pas littéralement « N attributs style inline ».
 *
 */
export const PATTERNS = {
  inlineStyle: /style=\{\{/g,
  halfPixel: /fontSize:\s*'?\d+\.5\b/g,
  literalFontSize: /fontSize:\s*'?\d/g,
  pictogramCode: /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}]/gu,
};

/**
 * Contrôles positif et négatif. Ils vivent ici, hors de `src/`, donc le scan ne
 * les rencontre jamais — le problème d'auto-comptage d'un test qui contient les
 * motifs qu'il cherche disparaît par construction.
 */
export const FIXTURES = {
  violating: 'const a = <div ' + 'style={{ fontSize: 10.5 }}>' + String.fromCodePoint(0x1f6a8) + '</div>;',
  clean: 'const a = <div className="fl-card">texte</div>;',
};

const EXCLUDED = ['src_backup', 'node_modules', `${path.sep}i18n${path.sep}`];

/**
 * Échelles pliées depuis l'usage réel le 2026-08-04 : 25 tailles de police et
 * 20 valeurs d'espacement littérales mesurées dans `src/`. `checkScales()`
 * verrouille ce pliage et interdit qu'un pas en demi-pixel réapparaisse dans
 * l'échelle elle-même (Task 2).
 */
export const ECHELLE_FS = {
  '--fs-micro': '8px', '--fs-xs': '9px', '--fs-sm': '10px', '--fs-base': '11px',
  '--fs-md': '12px', '--fs-lg': '13px', '--fs-title': '15px',
  '--fs-display': '20px', '--fs-hero': '26px',
};
export const ECHELLE_SP = {
  '--sp-hair': '1px', '--sp-1': '2px', '--sp-2': '4px', '--sp-3': '6px',
  '--sp-4': '8px', '--sp-5': '12px', '--sp-6': '16px', '--sp-7': '24px',
  '--sp-8': '32px', '--sp-9': '48px',
};
export const ECHELLE_FW = { '--fw-body': '400', '--fw-label': '600', '--fw-strong': '700' };

/**
 * Isole le bloc `:root { ... }` de la feuille. `body.theme-light` redéclare
 * des tokens de couleur (thème clair) mais ne redéclare jamais les échelles
 * `--fs-*` / `--fw-*` : scanner la feuille entière les compterait deux fois
 * si jamais ils y apparaissaient un jour. La portée est donc volontairement
 * limitée à `:root` — un seul bloc de ce nom existe dans `index.css`, sans
 * accolade imbriquée, donc l'arrêt non-gourmand au premier `\n}` est fiable.
 */
export function rootBlock(css) {
  const match = css.match(/:root\s*\{([\s\S]*?)\n\}/);
  if (!match) {
    throw new Error('Bloc :root introuvable dans src/index.css.');
  }
  return match[1];
}

/**
 * Déclarations `--<prefix><nom>: <valeur>;` trouvées dans un bloc CSS déjà
 * isolé (voir `rootBlock`). Point de calcul unique partagé par
 * `checkScales()` et `src/designSystem.test.js` — cf. l'en-tête de ce
 * fichier : « Deux points d'entrée, un seul calcul ».
 */
export function scaleDeclarations(block, prefix) {
  const found = [];
  const pattern = new RegExp(`(${prefix}[\\w-]+)\\s*:\\s*([^;]+);`, 'g');
  let match;
  while ((match = pattern.exec(block))) {
    found.push([match[1], match[2].trim()]);
  }
  return found;
}

/**
 * Vrai si une valeur de token porte un pas en demi-pixel (`10.5px`) ou plus
 * généralement une valeur en px non entière. Repris identiquement dans
 * `checkScales()` et `src/designSystem.test.js`.
 */
export function isHalfPixelValue(valeur) {
  const numeric = parseFloat(valeur);
  return valeur.includes('.5') || (Number.isFinite(numeric) && !Number.isInteger(numeric));
}

/**
 * Point d'extension du lot (Task 2). Lit `src/index.css` et vérifie que
 * chaque token de chaque échelle y est déclaré avec la valeur pliée, qu'aucun
 * pas de l'échelle typographique n'est en demi-pixel, que l'échelle
 * typographique compte exactement 9 pas, et que la graisse 500 est absente.
 * Les trois derniers contrôles lisent les déclarations réelles de `:root`
 * dans `index.css` (pas les objets `ECHELLE_*` ci-dessus) : ces objets ne
 * sont qu'un pliage de référence pour le contrôle « token présent avec la
 * bonne valeur » ; ils ne peuvent pas, par construction, détecter une dérive
 * de la feuille elle-même. Retourne des messages de `failures`, ne lève
 * jamais (sauf `rootBlock`, qui lève si `:root` est introuvable — un défaut
 * de structure du fichier, pas une dérive de contenu).
 */
export function checkScales() {
  const failures = [];
  const cssPath = path.join(srcDir, 'index.css');
  const css = fs.readFileSync(cssPath, 'utf8');
  const root = rootBlock(css);

  for (const [token, valeur] of Object.entries({ ...ECHELLE_FS, ...ECHELLE_SP, ...ECHELLE_FW })) {
    if (!new RegExp(`${token}\\s*:\\s*${valeur}\\s*;`).test(css)) {
      failures.push(
        `Scale token missing or wrong value — ${token} should be ${valeur} in src/index.css.`,
      );
    }
  }

  const fsFromCss = scaleDeclarations(root, '--fs-');
  for (const [token, valeur] of fsFromCss) {
    if (isHalfPixelValue(valeur)) {
      failures.push(
        `Half-pixel step found in the typographic scale — ${token}: ${valeur} in src/index.css. ` +
        'Half-pixel sizes carry no intent and must not reappear.',
      );
    }
  }

  if (fsFromCss.length !== 9) {
    failures.push(
      `Typographic scale must have exactly 9 steps, found ${fsFromCss.length} ` +
      `(--fs-* declared in :root, src/index.css).`,
    );
  }

  const fwFromCss = scaleDeclarations(root, '--fw-');
  for (const [token, valeur] of fwFromCss) {
    if (valeur === '500') {
      failures.push(
        `Font-weight 500 must be absent from the scale — ${token}: ${valeur} in src/index.css. ` +
        'It is invisible between 400 and 600.',
      );
    }
  }

  return failures;
}

/** Seuls ces sous-ensembles Google Fonts sont permis (cf. generate-fonts.mjs). */
export const SOUS_ENSEMBLES_PERMIS = new Set(['latin', 'latin-ext']);

/** Hôtes de CDN de polices dont toute référence réelle doit rester absente. */
const HOTES_CDN = 'fonts\\.googleapis\\.com|fonts\\.gstatic\\.com|use\\.typekit';

/**
 * Motifs de *référence réelle* à un hôte de CDN de polices : un attribut
 * `href=`/`src=` HTML, un `@import`, ou un `url(...)` CSS qui nomme l'hôte —
 * jamais un simple passage du nom de domaine dans du texte ou un commentaire.
 * Revue de Task 3 : un scan de sous-chaîne sur le texte entier faisait échouer
 * la vérification sur son propre commentaire de documentation dans
 * `index.html` ; un futur commentaire nommant le domaine ne doit plus jamais
 * casser le build.
 */
const MOTIFS_REFERENCE_CDN = [
  new RegExp(`(?:href|src)\\s*=\\s*["'][^"']*(?:${HOTES_CDN})[^"']*["']`, 'i'),
  new RegExp(`@import\\s+(?:url\\()?['"]?[^'");]*(?:${HOTES_CDN})[^'");]*`, 'i'),
  new RegExp(`url\\(\\s*['"]?[^'")]*(?:${HOTES_CDN})[^'")]*['"]?\\s*\\)`, 'i'),
];

/**
 * Vrai si `source` contient une référence *réelle* (chargement de ressource) à
 * un CDN de polices, pas une simple occurrence du nom de domaine. Point de
 * calcul unique partagé par `checkFonts()` et `src/designSystem.test.js`.
 */
export function referenceCdnPolices(source) {
  return MOTIFS_REFERENCE_CDN.some(motif => motif.test(source));
}

/**
 * Point d'extension du lot (Task 3). Un poste d'analyse DFIR est fréquemment
 * isolé du réseau : toute police servie depuis un CDN y retombe en fallback
 * système et change toute la typographie du produit. Ce contrôle verrouille
 * l'auto-hébergement en lisant les fichiers réels — `src/fonts.css`,
 * `src/index.css`, `index.html` et le contenu effectif de `public/fonts/` —
 * jamais une constante recopiée qui s'auto-validerait indéfiniment (la leçon
 * des Tâches 1 et 2 : deux garde-fous de ce lot ont été trouvés en train
 * d'affirmer des constantes contre elles-mêmes). Retourne des messages de
 * `failures`, ne lève jamais.
 */
export function checkFonts() {
  const failures = [];
  const fontsCssPath = path.join(srcDir, 'fonts.css');
  const indexCssPath = path.join(srcDir, 'index.css');
  const indexHtmlPath = path.join(root, 'index.html');
  const fontsDir = path.join(root, 'public', 'fonts');

  const fontsCss = fs.readFileSync(fontsCssPath, 'utf8');
  const indexCss = fs.readFileSync(indexCssPath, 'utf8');
  const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');

  const sources = { 'src/fonts.css': fontsCss, 'src/index.css': indexCss, 'index.html': indexHtml };
  for (const [label, source] of Object.entries(sources)) {
    if (referenceCdnPolices(source)) {
      failures.push(
        `Font CDN reference found in ${label} — fonts must stay self-hosted for ` +
        'network-isolated DFIR workstations.',
      );
    }
  }

  const urls = [...fontsCss.matchAll(/url\(['"]?(\/fonts\/[^'")]+)['"]?\)/g)].map(m => m[1]);
  if (urls.length === 0) {
    failures.push('No @font-face url(...) found in src/fonts.css.');
  }
  const manquants = urls.filter(u => !fs.existsSync(path.join(root, 'public', u)));
  if (manquants.length) {
    failures.push(
      `@font-face url(...) in src/fonts.css points to a file missing on disk: ${manquants.join(', ')}.`,
    );
  }

  for (const famille of ['IBM Plex Sans', 'IBM Plex Sans Condensed', 'IBM Plex Mono']) {
    if (!fontsCss.includes(`font-family: '${famille}'`)) {
      failures.push(`Font family declaration missing from src/fonts.css — font-family: '${famille}'.`);
    }
  }

  // Task 3 review — rien n'empêchait un fichier ajouté à la main pour un
  // sous-ensemble hors périmètre (cyrillic, greek…) de passer inaperçu.
  // Deux angles, non redondants : les fichiers réellement présents sur
  // disque dans public/fonts/, et les valeurs unicode-range réellement
  // déclarées par les @font-face de src/fonts.css.
  const fichiersPolices = fs.existsSync(fontsDir)
    ? fs.readdirSync(fontsDir).filter(f => f.endsWith('.woff2'))
    : [];
  const horsPermis = fichiersPolices.filter(
    f => ![...SOUS_ENSEMBLES_PERMIS].some(sousEnsemble => f.endsWith(`-${sousEnsemble}.woff2`)),
  );
  if (horsPermis.length) {
    failures.push(
      `Font file(s) in public/fonts/ use a subset outside ${[...SOUS_ENSEMBLES_PERMIS].join('/')}: ` +
      `${horsPermis.join(', ')}.`,
    );
  }

  const plagesUniques = new Set(
    [...fontsCss.matchAll(/unicode-range:\s*([^;]+);/g)].map(m => m[1].trim()),
  );
  if (plagesUniques.size > SOUS_ENSEMBLES_PERMIS.size) {
    failures.push(
      `${plagesUniques.size} distinct unicode-range values found in src/fonts.css — only ` +
      `${SOUS_ENSEMBLES_PERMIS.size} are expected (${[...SOUS_ENSEMBLES_PERMIS].join(', ')}). ` +
      'A @font-face outside the permitted subsets was likely added.',
    );
  }

  const tokenChecks = [
    ['--f-display', /--f-display:\s*"IBM Plex Sans"/],
    ['--f-ui', /--f-ui:\s*"IBM Plex Sans"/],
    ['--f-mono', /--f-mono:\s*"IBM Plex Mono"/],
    ['--f-cond', /--f-cond:\s*"IBM Plex Sans Condensed"/],
  ];
  for (const [token, pattern] of tokenChecks) {
    if (!pattern.test(indexCss)) {
      failures.push(`Font token ${token} does not point to the expected Plex family in src/index.css.`);
    }
  }

  const referencees = [...indexCss.matchAll(/--f-\w+:\s*"([^"]+)"/g)].map(m => m[1]);
  for (const famille of referencees) {
    if (!fontsCss.includes(`font-family: '${famille}'`)) {
      failures.push(
        `Font family "${famille}" referenced by a --f-* token in src/index.css is absent from src/fonts.css.`,
      );
    }
  }

  return failures;
}

/**
 * Sélecteurs qui doivent porter l'anneau de focus généralisé (Task 4). Repris
 * tel quel par `src/designSystem.test.js` — un `it()` par sélecteur — cf.
 * l'en-tête de ce fichier : « Deux points d'entrée, un seul calcul ».
 */
export const SELECTEURS_FOCUS = ['button', 'a', '[role="button"]', 'summary'];

/**
 * Isole le bloc qui suit le commentaire GLOBAL FOCUS dans la feuille — même
 * logique de portée non gourmande que `rootBlock()` : un seul bloc de ce nom est attendu,
 * sans accolade imbriquée avant sa fermeture, donc l'arrêt au premier `}` est
 * fiable. Retourne `null` si le bloc est absent (contrairement à `rootBlock`,
 * qui lève : l'absence du bloc GLOBAL FOCUS est une dérive de contenu à
 * signaler dans `failures`, pas un défaut de structure du fichier).
 */
export function globalFocusBlock(css) {
  const match = css.match(/\/\* GLOBAL FOCUS \*\/([\s\S]*?)\}/);
  return match ? match[1] : null;
}

/**
 * Occurrences de suppression de l'anneau `outline` dans toute la feuille, avec
 * leur position et leur numéro de ligne. Couvre `outline` et `outline-width`,
 * valeur `none` ou zéro avec unité quelconque (`0`, `0px`, `0em`, …), les deux
 * combinés dans n'importe quel ordre (`0 none` / `none 0`), un `!important`
 * optionnel, et `;` ou `}` comme terminateur (une déclaration finale sans
 * point-virgule reste valide en CSS). Un ancien motif ne couvrant que
 * `outline: (none|0);` laissait passer `outline: none !important;`,
 * `outline: 0px;`, `outline: 0 none;`, `outline: none }` (sans point-virgule)
 * et `outline-width: 0` sans jamais consulter `OUTLINE_NONE_ALLOWLIST`. Point
 * de calcul unique partagé par `checkFocusRing()` et `src/designSystem.test.js`.
 */
export function outlineSuppressions(css) {
  const re = /\boutline(?:-width)?\s*:\s*(?:(?:0(?:\.0+)?[a-zA-Z%]*|none)\s*){1,2}(?:!important\s*)?(?=[;}])/g;
  return [...css.matchAll(re)].map(m => ({
    index: m.index,
    line: css.slice(0, m.index).split('\n').length,
  }));
}

/**
 * Sélecteur de la règle CSS qui contient la position `index` de `css` :
 * l'accolade ouvrante de la règle courante est trouvée en scannant vers
 * l'arrière avec suivi de profondeur (depth tracking) — seul le premier `{`
 * rencontré quand depth=0 clôt la règle courante. L'accolade fermante la plus
 * proche avant celui-ci marque la fin de la règle précédente. Le texte entre
 * les deux — commentaires retirés, espaces réduits, prélude `@media`/`@supports`
 * strippés — est le sélecteur, normalisé pour une comparaison exacte avec
 * `OUTLINE_NONE_ALLOWLIST`. Point de calcul unique partagé par
 * `checkFocusRing()` et `src/designSystem.test.js`.
 */
export function ruleSelectorAt(css, index) {
  const before = css.slice(0, index);

  // Scan backwards with depth tracking to find the opening brace of the rule
  let braceDepth = 0;
  let openBrace = -1;
  for (let i = before.length - 1; i >= 0; i--) {
    const char = before[i];
    if (char === '}') {
      braceDepth++;
    } else if (char === '{') {
      if (braceDepth === 0) {
        openBrace = i;
        break;
      }
      braceDepth--;
    }
  }

  if (openBrace === -1) return '';

  const closeBrace = css.slice(0, openBrace).lastIndexOf('}');
  let selector = css
    .slice(closeBrace + 1, openBrace)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, ' ')
    .trim();

  // Strip any leading @media/@supports/etc prelude from the selector
  selector = selector.replace(/^@[^{]*\{\s*/, '').trim();

  return selector;
}

/**
 * Allowlist explicite des suppressions `outline: none`/`0`. Remplace une
 * heuristique de proximité de caractères (chercher `focus-visible` dans une
 * fenêtre fixe autour du match) qui donnait la bonne réponse pour la
 * mauvaise raison : elle acceptait `input:focus, select:focus,
 * textarea:focus` (l. 225) seulement parce que le bloc GLOBAL FOCUS se
 * trouve quelques lignes plus bas par accident de mise en page, et refusait
 * `.fl-select` (l. 470) — pourtant couvert par le même anneau `box-shadow`
 * que `.fl-input` — simplement parce que la distance en caractères (245
 * lignes) dépassait la fenêtre. La proximité ne peut pas exprimer « cet
 * élément a un indicateur de focus fourni ailleurs dans la feuille ».
 *
 * Chaque entrée nomme le sélecteur exact (normalisé par `ruleSelectorAt`) et
 * justifie, en une phrase vérifiée, quelle règle fournit le remplacement.
 * Toute suppression trouvée dans `index.css` et absente d'ici fait échouer
 * `checkFocusRing()` : ajouter un nouveau `outline: none` exige de le
 * documenter ici, pas de l'ajouter en silence.
 *
 * Les trois entrées ci-dessous ont été vérifiées le 2026-08-05 :
 * - `input:focus, select:focus, textarea:focus` (l. 225) pose elle-même
 *   `box-shadow: 0 0 0 2px …var(--fl-accent)…` et `border-color:
 *   var(--fl-accent)` dans la même règle : l'anneau outline est remplacé par
 *   un anneau box-shadow, pas supprimé sans remplacement.
 * - `.fl-input` (l. 457) n'est jamais posé sur autre chose qu'un <input>,
 *   <textarea> ou <select> (vérifié par grep sur les fichiers .jsx de src/ :
 *   toutes les occurrences sont sur ces trois balises) ; au focus clavier, la règle
 *   `input:focus, select:focus, textarea:focus` ci-dessus prend le relais.
 * - `.fl-select` (l. 470) n'est jamais posé sur autre chose qu'un <select>
 *   (même vérification par grep) ; au focus clavier, la même règle
 *   `select:focus` fournit l'anneau box-shadow de remplacement.
 */
export const OUTLINE_NONE_ALLOWLIST = [
  {
    selector: 'input:focus, select:focus, textarea:focus',
    replacement:
      'Same rule sets box-shadow: 0 0 0 2px …var(--fl-accent)… and border-color: ' +
      'var(--fl-accent) — the outline ring is replaced by a box-shadow ring, not removed.',
  },
  {
    selector: '.fl-input',
    replacement:
      '.fl-input is only ever applied to <input>/<textarea>/<select> elements (verified ' +
      'by grep across src/**/*.jsx) — on keyboard focus the "input:focus, select:focus, ' +
      'textarea:focus" rule above supplies the box-shadow ring.',
  },
  {
    selector: '.fl-select',
    replacement:
      '.fl-select is only ever applied to <select> elements (verified by grep across ' +
      'src/**/*.jsx) — on keyboard focus the same "select:focus" rule supplies the ' +
      'box-shadow ring.',
  },
];

/**
 * Point d'extension du lot (Task 4). Audit du 2026-07-29 : aucun style de
 * focus visible sur `button` ni sur `a` dans tout le produit — seul un champ
 * de la page de login (`.login-input:focus-visible`, l. ~1109) faisait le
 * bon geste : `:focus-visible`, pas `:focus`, pour n'apparaître qu'au clavier.
 * Ce contrôle verrouille la généralisation de ce geste à `button`, `a`,
 * `[role="button"]`, `summary` (et `[tabindex]` côté CSS — non redemandé ici
 * séparément, il partage le même bloc) : présence du bloc, sélecteurs
 * couverts, usage de `--fl-accent` sans le redéfinir, et — sur la feuille
 * entière — qu'aucune suppression `outline: none`/`0` n'existe hors de
 * `OUTLINE_NONE_ALLOWLIST` (voir sa documentation pour la revue qui a motivé
 * ce remplacement de l'heuristique de proximité). Retourne des messages de
 * `failures`, ne lève jamais.
 */
export function checkFocusRing() {
  const failures = [];
  const cssPath = path.join(srcDir, 'index.css');
  const css = fs.readFileSync(cssPath, 'utf8');

  const bloc = globalFocusBlock(css);
  if (bloc === null) {
    failures.push(
      'Global focus ring block missing from src/index.css — expected a `/* GLOBAL FOCUS */` ' +
      'comment followed by a rule covering button, a, [role="button"], summary, [tabindex].',
    );
  } else {
    for (const selecteur of SELECTEURS_FOCUS) {
      if (!bloc.includes(`${selecteur}:focus-visible`)) {
        failures.push(
          `Global focus ring is missing ${selecteur}:focus-visible in the GLOBAL FOCUS block ` +
          'of src/index.css.',
        );
      }
    }
    if (!/outline:\s*2px solid var\(--fl-accent\)/.test(bloc)) {
      failures.push(
        'Global focus ring must use outline: 2px solid var(--fl-accent) in the GLOBAL FOCUS ' +
        'block of src/index.css.',
      );
    }
    if (!/outline-offset:\s*2px/.test(bloc)) {
      failures.push(
        'Global focus ring must use outline-offset: 2px in the GLOBAL FOCUS block of ' +
        'src/index.css.',
      );
    }
  }

  for (const { index, line } of outlineSuppressions(css)) {
    const selecteur = ruleSelectorAt(css, index);
    const entree = OUTLINE_NONE_ALLOWLIST.find(e => e.selector === selecteur);
    if (!entree) {
      failures.push(
        `outline:none/0 suppression not in OUTLINE_NONE_ALLOWLIST — src/index.css:${line} ` +
        `(selector: ${selecteur || '<unresolved>'}). Add it to OUTLINE_NONE_ALLOWLIST in ` +
        'scripts/check-design-system.mjs with a verified replacement, or restore a visible ' +
        'focus indicator.',
      );
    }
  }

  return failures;
}

/**
 * Isole le bloc qui suit le commentaire GLOBAL REDUCED MOTION dans la feuille
 * — même logique que `globalFocusBlock()`. Le commentaire précède la liste de
 * sélecteurs (`*, *::before, *::after {`), donc le texte capturé contient à la
 * fois le sélecteur et les déclarations : les deux sont vérifiables depuis ce
 * seul bloc. Retourne `null` si le bloc est absent. Point de calcul unique
 * partagé par `checkReducedMotion()` et `src/designSystem.test.js`.
 */
export function reducedMotionBlock(css) {
  const match = css.match(/\/\* GLOBAL REDUCED MOTION \*\/([\s\S]*?)\n\}/);
  return match ? match[1] : null;
}

/**
 * Étendues `[début, fin]` de chaque bloc `@media (prefers-reduced-motion:
 * reduce) { ... }` de la feuille — les trois blocs déjà présents dans la
 * section login (Task 5 leur laisse la place, cf. constraints) et le nouveau
 * bloc GLOBAL REDUCED MOTION. `début` pointe sur le premier caractère de
 * `@media`, `fin` sur l'accolade fermante qui referme ce même bloc, trouvée
 * par suivi de profondeur (depth tracking) — même technique que
 * `ruleSelectorAt()`, mais en avant plutôt qu'en arrière puisqu'ici la borne
 * de départ (le marqueur `@media`) est connue et c'est la fin qui doit être
 * localisée. Point de calcul unique partagé par
 * `importantMotionOverridesOutsideReducedMotion()` et
 * `src/designSystem.test.js`.
 */
export function reducedMotionMediaSpans(css) {
  const marker = '@media (prefers-reduced-motion: reduce)';
  const spans = [];
  let searchFrom = 0;
  for (;;) {
    const markerIndex = css.indexOf(marker, searchFrom);
    if (markerIndex === -1) break;
    const braceStart = css.indexOf('{', markerIndex);
    if (braceStart === -1) break;

    let depth = 0;
    let end = -1;
    for (let i = braceStart; i < css.length; i++) {
      if (css[i] === '{') {
        depth++;
      } else if (css[i] === '}') {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end === -1) break;

    spans.push([markerIndex, end]);
    searchFrom = end + 1;
  }
  return spans;
}

/**
 * Déclarations `animation`/`transition` (raccourci ou sous-propriété) posées
 * avec `!important` en dehors de tout bloc `@media (prefers-reduced-motion:
 * reduce)` de la feuille. C'est le contrôle qui donne un sens réel à « la
 * neutralisation est atteignable » : dans la cascade CSS, deux déclarations
 * `!important` se départagent par spécificité, pas par la simple présence de
 * `!important` — `*` a une spécificité nulle. Une règle future du type
 * `.fl-loading-pulse { animation: fl-pulse 2s !important; }` hors media query
 * gagnerait donc contre le bloc global dès que `prefers-reduced-motion:
 * reduce` s'active, et l'animation applicative continuerait de tourner sans
 * qu'aucune des trois assertions du brief ne le détecte (le bloc global
 * existerait toujours, intact). Les trois `animation: none !important;` déjà
 * présents dans la section login sont, eux, posés à l'intérieur de leur
 * propre `@media (prefers-reduced-motion: reduce)` (cf. `reducedMotionMediaSpans`)
 * : ils ne sont donc jamais remontés ici, et ils poussent de toute façon dans
 * le même sens (moins de mouvement), pas en sens contraire. Point de calcul
 * unique partagé par `checkReducedMotion()` et `src/designSystem.test.js`.
 */
export function importantMotionOverridesOutsideReducedMotion(css) {
  const pattern = /\b(animation(?:-duration|-name|-iteration-count)?|transition(?:-duration|-property)?)\s*:[^;]*!important/gi;
  const spans = reducedMotionMediaSpans(css);
  const insideAny = (index) => spans.some(([start, end]) => index >= start && index <= end);

  const found = [];
  for (const match of css.matchAll(pattern)) {
    if (insideAny(match.index)) continue;
    found.push({
      index: match.index,
      line: css.slice(0, match.index).split('\n').length,
      declaration: match[0].trim(),
    });
  }
  return found;
}

/**
 * Point d'extension du lot (Task 5). Audit du 2026-07-29 : les trois blocs
 * `prefers-reduced-motion` du produit sont tous dans la section login ; les 13
 * animations applicatives déclarées l. 223-260 (avant ce lot) ne sont jamais
 * désactivables. Ce contrôle verrouille : présence et contenu du bloc GLOBAL
 * REDUCED MOTION (durées neutralisées à `0.01ms`, pas supprimées — un
 * `animation: none` empêcherait `animationend` de se déclencher, ce dont
 * plusieurs composants dépendent pour enchaîner un état), son imbrication
 * sous `@media (prefers-reduced-motion: reduce)`, la présence d'au moins un bloc
 * `prefers-reduced-motion`, et — au-delà de la simple
 * présence du bloc — que rien ailleurs dans la feuille ne peut le
 * court-circuiter dans la cascade (voir
 * `importantMotionOverridesOutsideReducedMotion`). Retourne des messages de
 * `failures`, ne lève jamais.
 */
export function checkReducedMotion() {
  const failures = [];
  const cssPath = path.join(srcDir, 'index.css');
  const css = fs.readFileSync(cssPath, 'utf8');

  const bloc = reducedMotionBlock(css);
  if (bloc === null) {
    failures.push(
      'Global reduced-motion block missing from src/index.css — expected a ' +
      '`/* GLOBAL REDUCED MOTION */` comment followed by a `*, *::before, *::after` rule ' +
      'neutralising animation and transition durations.',
    );
  } else {
    if (!/animation-duration:\s*0\.01ms\s*!important/.test(bloc)) {
      failures.push(
        'Global reduced-motion block must set animation-duration: 0.01ms !important in ' +
        'src/index.css (0.01ms, not animation: none, so animationend still fires).',
      );
    }
    if (!/transition-duration:\s*0\.01ms\s*!important/.test(bloc)) {
      failures.push(
        'Global reduced-motion block must set transition-duration: 0.01ms !important in ' +
        'src/index.css.',
      );
    }
    if (!/scroll-behavior:\s*auto\s*!important/.test(bloc)) {
      failures.push(
        'Global reduced-motion block must set scroll-behavior: auto !important in ' +
        'src/index.css.',
      );
    }
    if (!/\*::before/.test(bloc) || !/\*::after/.test(bloc)) {
      failures.push(
        'Global reduced-motion block must cover *, *::before and *::after in src/index.css — ' +
        'a narrower selector would leave pseudo-element-driven animation untouched.',
      );
    }
  }

  if (!/@media \(prefers-reduced-motion: reduce\)\s*\{\s*\/\* GLOBAL REDUCED MOTION \*\//.test(css)) {
    failures.push(
      'Global reduced-motion block is not nested directly under ' +
      '@media (prefers-reduced-motion: reduce) in src/index.css.',
    );
  }

  // 2026-08-13 — Trois assertions ont été retirées ici : un seuil de 4 blocs
  // @media (prefers-reduced-motion) et deux `css.includes()` exigeant la survie de
  // `.login-blob` et `.login-aurora`. Elles dataient de l'audit du 2026-07-29 et étaient
  // rédigées « must remain untouched by this task » — une contrainte de portée temporaire,
  // gelée par erreur en garde permanente. Le lot « login photo nue » supprime ces calques
  // décoratifs, décision du propriétaire du projet : une animation qui n'existe plus ne peut
  // pas mal gérer le mouvement réduit, donc ces assertions protégeaient des noms de classe,
  // plus une propriété. Les deux protections réelles restent en place et suffisent : la
  // vérification complète du bloc global ci-dessus, et l'interdiction des `!important` de
  // mouvement hors bloc `prefers-reduced-motion` ci-dessous.
  //
  // NE PAS réintroduire d'assertion citant une classe CSS nommée. Si le besoin réapparaît,
  // écrire un invariant général — par exemple : toute règle `animation: … infinite` doit être
  // couverte par le bloc global de mouvement réduit.
  const blocsPrefersReducedMotion = css.match(/@media \(prefers-reduced-motion: reduce\)/g) ?? [];
  if (blocsPrefersReducedMotion.length < 1) {
    failures.push(
      `Expected at least 1 @media (prefers-reduced-motion: reduce) block (the global one), ` +
      `found ${blocsPrefersReducedMotion.length} in src/index.css.`,
    );
  }

  for (const { line, declaration } of importantMotionOverridesOutsideReducedMotion(css)) {
    failures.push(
      `animation/transition !important declaration outside any ` +
      `@media (prefers-reduced-motion: reduce) block — src/index.css:${line} ("${declaration}"). ` +
      'A same-tier !important with higher selector specificity than the universal `*` can win ' +
      'the cascade once reduced motion is active, silently defeating the global neutralisation ' +
      'for that element.',
    );
  }

  return failures;
}

export function sourceFiles(dir = srcDir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (EXCLUDED.some(part => full.includes(part))) continue;
    if (entry.isDirectory()) sourceFiles(full, acc);
    else if (/\.(jsx|tsx|js|ts)$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

export function countDrift() {
  // Dérivé de PATTERNS plutôt qu'écrit en dur : une clé ajoutée à PATTERNS
  // sans être ajoutée ici finirait en `undefined`, et `undefined + n` -> NaN
  // ne dépasserait jamais un plafond (voir le garde dans runChecks).
  const total = Object.fromEntries(Object.keys(PATTERNS).map(key => [key, 0]));
  for (const file of sourceFiles()) {
    const source = fs.readFileSync(file, 'utf8');
    for (const [key, pattern] of Object.entries(PATTERNS)) {
      total[key] += (source.match(pattern) ?? []).length;
    }
  }
  return total;
}

/**
 * Point d'extension du lot. Les Tâches 2 à 5 ajoutent leur contrôle ici, en
 * poussant dans `failures` et en renseignant `counts`.
 */
export function runChecks() {
  // Garde-fou du garde-fou : PATTERNS et CEILINGS doivent couvrir exactement
  // les mêmes clés, sinon une nouvelle clé ajoutée d'un seul côté ne serait
  // jamais contrôlée (silencieusement, via le NaN décrit dans countDrift).
  const patternKeys = new Set(Object.keys(PATTERNS));
  const ceilingKeys = new Set(Object.keys(CEILINGS));
  const sameKeys = patternKeys.size === ceilingKeys.size
    && [...patternKeys].every(key => ceilingKeys.has(key));
  if (!sameKeys) {
    throw new Error(
      `PATTERNS et CEILINGS doivent déclarer les mêmes clés. ` +
      `PATTERNS: ${[...patternKeys].sort().join(', ')} — ` +
      `CEILINGS: ${[...ceilingKeys].sort().join(', ')}.`,
    );
  }

  const failures = [];
  const counts = countDrift();

  for (const [key, ceiling] of Object.entries(CEILINGS)) {
    if (counts[key] > ceiling) {
      failures.push(
        `Drift ceiling exceeded — ${key}: ${counts[key]} > ${ceiling}.\n` +
        `Ceilings only go down. Migrate, do not raise the ceiling.`,
      );
    }
  }

  failures.push(...checkScales());
  failures.push(...checkFonts());
  failures.push(...checkFocusRing());
  failures.push(...checkReducedMotion());

  return { failures, counts };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { failures, counts } = runChecks();
  if (failures.length) {
    console.error(failures.join('\n\n'));
    process.exit(1);
  }
  console.log(
    'design-system check passed: ' +
    Object.entries(counts).map(([k, v]) => `${k}=${v}/${CEILINGS[k]}`).join(' · '),
  );
}
