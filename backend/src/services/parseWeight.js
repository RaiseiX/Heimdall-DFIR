function entierPositif(n) {
  return Number.isInteger(n) && n >= 0;
}

function tailleLisible(tailleDe, chemin) {
  let n;
  try {
    n = tailleDe(chemin);
  } catch (_e) {
    return null;
  }
  return entierPositif(n) ? n : null;
}

function poidsDesTypes(detectes, tailleDe) {
  const poids = {};
  if (!detectes || typeof detectes !== 'object' || Array.isArray(detectes)) return poids;
  if (typeof tailleDe !== 'function') return poids;

  for (const [type, info] of Object.entries(detectes)) {
    const fichiers = info && Array.isArray(info.files) ? info.files : [];
    let somme = 0;
    let mesures = 0;
    for (const chemin of fichiers) {
      const n = tailleLisible(tailleDe, chemin);
      if (n === null) continue;
      somme += n;
      mesures += 1;
    }
    if (mesures > 0) poids[type] = somme;
  }
  return poids;
}

function octetsDistincts(detectes, tailleDe) {
  if (!detectes || typeof detectes !== 'object' || Array.isArray(detectes)) return null;
  if (typeof tailleDe !== 'function') return null;

  const vus = new Set();
  let somme = 0;
  let mesures = 0;
  for (const info of Object.values(detectes)) {
    for (const chemin of info && Array.isArray(info.files) ? info.files : []) {
      if (vus.has(chemin)) continue;
      vus.add(chemin);
      const n = tailleLisible(tailleDe, chemin);
      if (n === null) continue;
      somme += n;
      mesures += 1;
    }
  }
  return mesures > 0 ? somme : null;
}

function memoriser(tailleDe) {
  const lues = new Map();
  return (chemin) => {
    if (!lues.has(chemin)) lues.set(chemin, typeof tailleDe === 'function' ? tailleLisible(tailleDe, chemin) : null);
    return lues.get(chemin);
  };
}

function mesurerLecture(detectes, tailleDe) {
  const lire = memoriser(tailleDe);
  return { poids: poidsDesTypes(detectes, lire), distincts: octetsDistincts(detectes, lire) };
}

function parseursInitiaux(types, poids, nomDe) {
  const etats = {};
  const connus = poids && typeof poids === 'object' ? poids : {};
  for (const type of Array.isArray(types) ? types : []) {
    const entree = { status: 'queued', records: 0, name: typeof nomDe === 'function' ? nomDe(type) : type };
    if (entierPositif(connus[type])) entree.octets = connus[type];
    etats[type] = entree;
  }
  return etats;
}

module.exports = { poidsDesTypes, parseursInitiaux, octetsDistincts, mesurerLecture };
