const fs = require('fs');
const path = require('path');

const fsp = fs.promises;

const LIMITES = Object.freeze({
  entrees: 2000,
  sonde: 8192,
  apercuTexteDefaut: 256 * 1024,
  apercuTexteMax: 1024 * 1024,
  apercuHex: 4096,
  rechercheTermeMin: 2,
  rechercheTermeMax: 200,
  rechercheFichiers: 5000,
  rechercheOctetsParFichier: 2 * 1024 * 1024,
  rechercheOctetsTotal: 256 * 1024 * 1024,
  rechercheResultats: 200,
  rechercheLignesParFichier: 10,
  rechercheLigne: 300,
  rechercheDureeMs: 15000,
});

function refus(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

function dedans(racine, cible) {
  return cible === racine || cible.startsWith(racine + path.sep);
}

function relatifDe(racine, absolu) {
  return path.relative(racine, absolu).split(path.sep).join('/');
}

async function cibleConfinee(racineReelle, relatif) {
  const brut = relatif === undefined || relatif === null ? '' : String(relatif);
  if (brut.includes('\0') || path.isAbsolute(brut)) throw refus(400, 'CHEMIN_INVALIDE', 'Chemin invalide');
  const cible = path.resolve(racineReelle, brut || '.');
  if (!dedans(racineReelle, cible)) throw refus(400, 'CHEMIN_INVALIDE', 'Chemin invalide');
  let reelle;
  try {
    reelle = await fsp.realpath(cible);
  } catch {
    throw refus(404, 'INTROUVABLE', 'Fichier introuvable');
  }
  if (!dedans(racineReelle, reelle)) throw refus(403, 'HORS_COLLECTE', 'Chemin hors de la collecte');
  return reelle;
}

async function fichierConfine(racineReelle, relatif) {
  const cible = await cibleConfinee(racineReelle, relatif);
  const st = await fsp.stat(cible);
  if (!st.isFile()) throw refus(400, 'PAS_UN_FICHIER', "Ce chemin n'est pas un fichier");
  return { chemin: cible, taille: st.size };
}

function typeDe(entree) {
  if (entree.isSymbolicLink()) return 'lien';
  if (entree.isDirectory()) return 'dir';
  if (entree.isFile()) return 'file';
  return 'autre';
}

function comparerEntrees(a, b) {
  if (a.type === 'dir' && b.type !== 'dir') return -1;
  if (b.type === 'dir' && a.type !== 'dir') return 1;
  return a.nom.localeCompare(b.nom, undefined, { sensitivity: 'base' });
}

async function listerRepertoire(racineReelle, relatif, { max = LIMITES.entrees } = {}) {
  const repertoire = await cibleConfinee(racineReelle, relatif);
  const st = await fsp.stat(repertoire);
  if (!st.isDirectory()) throw refus(400, 'PAS_UN_REPERTOIRE', "Ce chemin n'est pas un répertoire");
  const brutes = await fsp.readdir(repertoire, { withFileTypes: true });
  const triees = brutes
    .map((d) => ({ nom: d.name, type: typeDe(d) }))
    .filter((e) => e.type !== 'autre')
    .sort(comparerEntrees);
  const entrees = [];
  for (const e of triees.slice(0, max)) {
    const absolu = path.join(repertoire, e.nom);
    let taille = null;
    let modifie = null;
    try {
      const info = await fsp.lstat(absolu);
      taille = e.type === 'file' ? info.size : null;
      modifie = info.mtime ? info.mtime.toISOString() : null;
    } catch {
      taille = null;
    }
    entrees.push({ nom: e.nom, chemin: relatifDe(racineReelle, absolu), type: e.type, taille, modifie });
  }
  return {
    chemin: relatifDe(racineReelle, repertoire),
    parent: repertoire === racineReelle ? null : relatifDe(racineReelle, path.dirname(repertoire)),
    total: triees.length,
    tronque: triees.length > max,
    entrees,
  };
}

function estBinaire(tampon) {
  const echantillon = tampon.subarray(0, LIMITES.sonde);
  if (echantillon.length === 0) return false;
  if (echantillon.includes(0)) return true;
  let controles = 0;
  for (const octet of echantillon) {
    if (octet < 0x09 || (octet > 0x0d && octet < 0x20) || octet === 0x7f) controles += 1;
  }
  return controles / echantillon.length > 0.3;
}

async function lireFenetre(poignee, position, longueur) {
  const tampon = Buffer.alloc(longueur);
  const { bytesRead } = await poignee.read(tampon, 0, longueur, position);
  return tampon.subarray(0, bytesRead);
}

function entier(valeur, defaut) {
  const n = Number.parseInt(valeur, 10);
  return Number.isFinite(n) ? n : defaut;
}

async function lireExtrait(racineReelle, relatif, { offset, limite } = {}) {
  const { chemin, taille } = await fichierConfine(racineReelle, relatif);
  const debut = Math.min(Math.max(0, entier(offset, 0)), taille);
  const poignee = await fsp.open(chemin, 'r');
  try {
    const sonde = await lireFenetre(poignee, 0, Math.min(taille, LIMITES.sonde));
    const binaire = estBinaire(sonde);
    const base = { nom: path.basename(chemin), chemin: relatifDe(racineReelle, chemin), taille, offset: debut, binaire };
    if (binaire) {
      const fenetre = await lireFenetre(poignee, debut, Math.min(LIMITES.apercuHex, taille - debut));
      return {
        ...base,
        longueur: fenetre.length,
        tronque: debut + fenetre.length < taille,
        hex: fenetre.toString('hex'),
        ascii: fenetre.toString('latin1').replace(/[^\x20-\x7e]/g, '.'),
      };
    }
    const voulu = Math.min(LIMITES.apercuTexteMax, Math.max(1, entier(limite, LIMITES.apercuTexteDefaut)));
    const fenetre = await lireFenetre(poignee, debut, Math.min(voulu, taille - debut));
    return {
      ...base,
      longueur: fenetre.length,
      tronque: debut + fenetre.length < taille,
      texte: fenetre.toString('utf8'),
    };
  } finally {
    await poignee.close();
  }
}

function nomDeTelechargement(nom) {
  const ascii = String(nom).replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(String(nom))}`;
}

function termeDeRecherche(brut) {
  const terme = typeof brut === 'string' ? brut.trim() : '';
  if (terme.length < LIMITES.rechercheTermeMin || terme.length > LIMITES.rechercheTermeMax) {
    throw refus(400, 'TERME_INVALIDE', `Le terme doit contenir entre ${LIMITES.rechercheTermeMin} et ${LIMITES.rechercheTermeMax} caractères`);
  }
  return terme;
}

async function rechercher(racineReelle, relatif, brut, { limites = LIMITES, maintenant = Date.now } = {}) {
  const terme = termeDeRecherche(brut);
  const aiguille = terme.toLowerCase();
  const depart = await cibleConfinee(racineReelle, relatif);
  const st = await fsp.stat(depart);
  if (!st.isDirectory()) throw refus(400, 'PAS_UN_REPERTOIRE', "Ce chemin n'est pas un répertoire");

  const debut = maintenant();
  const resultats = [];
  const file = [depart];
  let fichiersParcourus = 0;
  let octetsLus = 0;
  let ignores = 0;
  let raison = null;

  while (file.length > 0 && raison === null) {
    const courant = file.shift();
    let entrees;
    try {
      entrees = await fsp.readdir(courant, { withFileTypes: true });
    } catch {
      continue;
    }
    entrees.sort((a, b) => a.name.localeCompare(b.name));
    for (const d of entrees) {
      if (maintenant() - debut > limites.rechercheDureeMs) { raison = 'duree'; break; }
      if (resultats.length >= limites.rechercheResultats) { raison = 'resultats'; break; }
      if (fichiersParcourus >= limites.rechercheFichiers) { raison = 'fichiers'; break; }
      if (octetsLus >= limites.rechercheOctetsTotal) { raison = 'octets'; break; }
      const absolu = path.join(courant, d.name);
      if (d.isDirectory()) { file.push(absolu); continue; }
      if (!d.isFile()) continue;
      fichiersParcourus += 1;
      let info;
      try { info = await fsp.stat(absolu); } catch { continue; }
      if (info.size > limites.rechercheOctetsParFichier) { ignores += 1; continue; }
      let contenu;
      try { contenu = await fsp.readFile(absolu); } catch { continue; }
      octetsLus += contenu.length;
      if (estBinaire(contenu)) continue;
      const lignes = contenu.toString('utf8').split(/\r?\n/);
      const trouvees = [];
      for (let i = 0; i < lignes.length && trouvees.length < limites.rechercheLignesParFichier; i += 1) {
        if (lignes[i].toLowerCase().includes(aiguille)) {
          trouvees.push({ numero: i + 1, texte: lignes[i].slice(0, limites.rechercheLigne) });
        }
      }
      if (trouvees.length > 0) {
        resultats.push({ chemin: relatifDe(racineReelle, absolu), nom: d.name, taille: info.size, lignes: trouvees });
      }
    }
  }

  return { terme, fichiersParcourus, octetsLus, fichiersTropGros: ignores, tronque: raison !== null, raison, resultats };
}

module.exports = {
  LIMITES,
  cibleConfinee,
  fichierConfine,
  listerRepertoire,
  lireExtrait,
  rechercher,
  estBinaire,
  nomDeTelechargement,
};
