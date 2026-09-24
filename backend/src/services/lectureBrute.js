const fs = require('fs');

const ECHANTILLON = 4096;
const BLOC = 1024 * 1024;
const TRANCHE_DEFAUT = 256 * 1024;
const TRANCHE_MAX = 1024 * 1024;
const HEXA_DEFAUT = 4096;
const LIGNES_COMPTEES_MAX = 256 * 1024 * 1024;
const RECHERCHE_OCTETS_MAX = 512 * 1024 * 1024;
const RECHERCHE_MAX = 500;
const LIGNE_MAX = 1024 * 1024;
const EXTRAIT_MAX = 400;
const ENCODAGES = ['auto', 'utf-8', 'utf-16le', 'utf-16be', 'windows-1252', 'hexa'];

const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const windows1252 = new TextDecoder('windows-1252');

function erreur(code) {
  return Object.assign(new Error(code), { code });
}

function finUtf8Incomplete(b) {
  for (let k = 1; k <= Math.min(3, b.length); k++) {
    const c = b[b.length - k];
    if ((c & 0xc0) === 0x80) continue;
    const attendu = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ? 2 : 1;
    return attendu > k ? k : 0;
  }
  return 0;
}

function detecterEncodage(octets) {
  if (!octets.length) return { encodage: 'vide', deduit: false, bom: 0 };
  if (octets[0] === 0xef && octets[1] === 0xbb && octets[2] === 0xbf) return { encodage: 'utf-8', deduit: false, bom: 3 };
  if (octets[0] === 0xff && octets[1] === 0xfe) return { encodage: 'utf-16le', deduit: false, bom: 2 };
  if (octets[0] === 0xfe && octets[1] === 0xff) return { encodage: 'utf-16be', deduit: false, bom: 2 };

  const e = octets.subarray(0, ECHANTILLON);
  let nulsPairs = 0;
  let nulsImpairs = 0;
  let controles = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === 0) { if (i % 2) nulsImpairs++; else nulsPairs++; } else if ((c < 0x20 && c !== 9 && c !== 10 && c !== 12 && c !== 13) || c === 0x7f) controles++;
  }
  const paires = Math.max(1, Math.floor(e.length / 2));
  if (nulsImpairs / paires > 0.3 && nulsPairs / paires < 0.05) return { encodage: 'utf-16le', deduit: true, bom: 0 };
  if (nulsPairs / paires > 0.3 && nulsImpairs / paires < 0.05) return { encodage: 'utf-16be', deduit: true, bom: 0 };
  if (nulsPairs + nulsImpairs > 0 || controles / e.length > 0.1) return { encodage: 'binaire', deduit: true, bom: 0 };
  try {
    utf8Strict.decode(e.subarray(0, e.length - finUtf8Incomplete(e)));
    return { encodage: 'utf-8', deduit: true, bom: 0 };
  } catch {
    return { encodage: 'windows-1252', deduit: true, bom: 0 };
  }
}

function decoder(octets, encodage) {
  if (encodage === 'utf-16le') return octets.toString('utf16le');
  if (encodage === 'utf-16be') {
    const inverse = Buffer.from(octets.subarray(0, octets.length - (octets.length % 2)));
    inverse.swap16();
    return inverse.toString('utf16le');
  }
  if (encodage === 'windows-1252') return windows1252.decode(octets);
  return octets.toString('utf8');
}

function borner(valeur, defaut, max) {
  const n = Math.floor(Number(valeur));
  if (!Number.isFinite(n) || n < 1) return defaut;
  return Math.min(n, max);
}

function estSaut(b, i, encodage) {
  if (encodage === 'utf-16le') return b[i] === 0x0a && b[i + 1] === 0x00;
  if (encodage === 'utf-16be') return b[i] === 0x00 && b[i + 1] === 0x0a;
  return b[i] === 0x0a;
}

async function compterSauts(fh, de, a, encodage) {
  const unite = encodage.startsWith('utf-16') ? 2 : 1;
  const tampon = Buffer.alloc(BLOC);
  let sauts = 0;
  for (let position = de; position < a;) {
    const { bytesRead } = await fh.read(tampon, 0, Math.min(BLOC, a - position), position);
    if (!bytesRead) break;
    for (let i = 0; i + unite <= bytesRead; i += unite) if (estSaut(tampon, i, encodage)) sauts++;
    position += bytesRead;
  }
  return sauts;
}

async function ouvrir(chemin) {
  const fh = await fs.promises.open(chemin, 'r');
  const { size } = await fh.stat();
  const tete = Buffer.alloc(Math.min(ECHANTILLON, size));
  if (tete.length) await fh.read(tete, 0, tete.length, 0);
  return { fh, taille: size, detection: detecterEncodage(tete) };
}

async function lireTranche(chemin, { offset = 0, longueur, encodage = 'auto' } = {}) {
  if (!ENCODAGES.includes(encodage)) throw erreur('encodage');
  const { fh, taille, detection } = await ouvrir(chemin);
  try {
    const base = { taille, encodage_detecte: detection.encodage, deduit: detection.deduit };
    if (taille === 0) return { ...base, encodage: 'vide', offset: 0, longueur: 0, suivant: null, premiere_ligne: 1, texte: '' };

    const mode = encodage === 'auto' ? (detection.encodage === 'binaire' ? 'hexa' : detection.encodage) : encodage;
    let debut = Math.max(0, Math.floor(Number(offset) || 0));

    if (mode === 'hexa') {
      const n = debut >= taille ? 0 : Math.min(borner(longueur, HEXA_DEFAUT, TRANCHE_MAX), taille - debut);
      const tampon = Buffer.alloc(n);
      if (n) await fh.read(tampon, 0, n, debut);
      return { ...base, encodage: 'hexa', offset: debut, longueur: n, suivant: debut + n < taille ? debut + n : null, hexa: tampon.toString('hex') };
    }

    const bom = mode === detection.encodage ? detection.bom : 0;
    const unite = mode.startsWith('utf-16') ? 2 : 1;
    debut = Math.max(debut, bom);
    if (unite === 2) debut -= debut % 2;
    if (debut >= taille) return { ...base, encodage: mode, offset: debut, longueur: 0, suivant: null, premiere_ligne: null, texte: '' };

    let n = Math.min(borner(longueur, TRANCHE_DEFAUT, TRANCHE_MAX), taille - debut);
    if (unite === 2 && n > 1) n -= n % 2;
    let tampon = Buffer.alloc(n);
    await fh.read(tampon, 0, n, debut);

    if (mode === 'utf-8' && debut > bom) {
      let k = 0;
      while (k < 3 && k < tampon.length && (tampon[k] & 0xc0) === 0x80) k++;
      debut += k;
      tampon = tampon.subarray(k);
    }
    if (debut + tampon.length < taille) {
      if (mode === 'utf-8') tampon = tampon.subarray(0, tampon.length - finUtf8Incomplete(tampon));
      else if (unite === 2 && tampon.length >= 2) {
        const dernier = mode === 'utf-16le' ? tampon.readUInt16LE(tampon.length - 2) : tampon.readUInt16BE(tampon.length - 2);
        if (dernier >= 0xd800 && dernier <= 0xdbff) tampon = tampon.subarray(0, tampon.length - 2);
      }
    }

    const fin = debut + tampon.length;
    const premiereLigne = debut === bom ? 1 : debut > LIGNES_COMPTEES_MAX ? null : 1 + await compterSauts(fh, bom, debut, mode);
    return {
      ...base, encodage: mode, offset: debut, longueur: tampon.length,
      suivant: fin < taille ? fin : null, premiere_ligne: premiereLigne, texte: decoder(tampon, mode),
    };
  } finally {
    await fh.close();
  }
}

function extrait(texte, index) {
  if (texte.length <= EXTRAIT_MAX) return texte;
  const debut = Math.max(0, index - 150);
  return texte.slice(debut, debut + EXTRAIT_MAX);
}

async function chercher(chemin, { q, encodage = 'auto', max = RECHERCHE_MAX, octetsMax = RECHERCHE_OCTETS_MAX } = {}) {
  if (typeof q !== 'string' || !q.trim() || q.length > 200) throw erreur('recherche');
  if (!ENCODAGES.includes(encodage)) throw erreur('encodage');
  const { fh, taille, detection } = await ouvrir(chemin);
  try {
    const mode = encodage === 'auto' ? detection.encodage : encodage;
    if (mode === 'binaire' || mode === 'hexa') throw erreur('binaire');
    if (mode === 'vide') return { resultats: [], tronque: false };

    const aiguille = q.toLowerCase();
    const unite = mode.startsWith('utf-16') ? 2 : 1;
    const bom = mode === detection.encodage ? detection.bom : 0;
    const limite = Math.min(taille, octetsMax);
    const resultats = [];
    let tronque = taille > octetsMax;
    let ligne = 1;

    const examiner = (octets, offset) => {
      const texte = decoder(octets, mode).replace(/\r$/, '');
      const i = texte.toLowerCase().indexOf(aiguille);
      if (i < 0) return true;
      resultats.push({ ligne, offset, extrait: extrait(texte, i) });
      if (resultats.length >= max) { tronque = true; return false; }
      return true;
    };

    let reste = Buffer.alloc(0);
    let resteDebut = bom;
    const tampon = Buffer.alloc(BLOC);
    let continuer = true;
    for (let position = bom; continuer && position < limite;) {
      const { bytesRead } = await fh.read(tampon, 0, Math.min(BLOC, limite - position), position);
      if (!bytesRead) break;
      position += bytesRead;
      const donnees = Buffer.concat([reste, tampon.subarray(0, bytesRead)]);
      let debutLigne = 0;
      for (let i = 0; continuer && i + unite <= donnees.length; i += unite) {
        if (!estSaut(donnees, i, mode)) continue;
        continuer = examiner(donnees.subarray(debutLigne, i), resteDebut + debutLigne);
        ligne++;
        debutLigne = i + unite;
      }
      reste = donnees.subarray(debutLigne);
      resteDebut += debutLigne;
      if (continuer && reste.length > LIGNE_MAX) {
        continuer = examiner(reste, resteDebut);
        resteDebut += reste.length;
        reste = Buffer.alloc(0);
      }
    }
    if (continuer && reste.length) examiner(reste, resteDebut);
    return { resultats, tronque };
  } finally {
    await fh.close();
  }
}

module.exports = { detecterEncodage, lireTranche, chercher, ENCODAGES, TRANCHE_MAX };
