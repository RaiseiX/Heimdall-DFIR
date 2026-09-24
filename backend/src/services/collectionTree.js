function vide() {
  return { nom: '', n: 0, types: [], enfants: [] };
}

function figer(noeud) {
  return {
    nom: noeud.nom,
    n: noeud.n,
    types: [...noeud.types].sort(),
    enfants: noeud.enfants
      .map(figer)
      .sort((a, b) => b.n - a.n || a.nom.localeCompare(b.nom)),
  };
}

function arbreDeCollecte(detectes, racine) {
  if (!detectes || typeof detectes !== 'object' || Array.isArray(detectes)) return vide();

  const prefixe = typeof racine === 'string' && racine ? `${racine.replace(/\/+$/, '')}/` : null;
  const typesParDossier = new Map();
  const fichiersParDossier = new Map();

  for (const [type, info] of Object.entries(detectes)) {
    const fichiers = info && Array.isArray(info.files) ? info.files : [];
    for (const chemin of fichiers) {
      if (typeof chemin !== 'string' || !chemin) continue;

      let relatif = chemin;
      if (prefixe) {
        if (!chemin.startsWith(prefixe)) continue;
        relatif = chemin.slice(prefixe.length);
      }

      const coupe = relatif.lastIndexOf('/');
      const dossier = coupe > 0 ? relatif.slice(0, coupe) : '';
      const fichier = relatif.slice(coupe + 1);

      if (!typesParDossier.has(dossier)) typesParDossier.set(dossier, new Set());
      if (!fichiersParDossier.has(dossier)) fichiersParDossier.set(dossier, new Set());
      typesParDossier.get(dossier).add(type);
      fichiersParDossier.get(dossier).add(fichier);
    }
  }

  const racineArbre = { nom: '', n: 0, types: new Set(), enfants: [] };

  for (const [dossier, types] of typesParDossier) {
    const n = fichiersParDossier.get(dossier).size;
    let courant = racineArbre;
    courant.n += n;
    for (const t of types) courant.types.add(t);

    for (const segment of dossier ? dossier.split('/') : []) {
      let enfant = courant.enfants.find((e) => e.nom === segment);
      if (!enfant) {
        enfant = { nom: segment, n: 0, types: new Set(), enfants: [] };
        courant.enfants.push(enfant);
      }
      enfant.n += n;
      for (const t of types) enfant.types.add(t);
      courant = enfant;
    }
  }

  return figer(racineArbre);
}

module.exports = { arbreDeCollecte };
