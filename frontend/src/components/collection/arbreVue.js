export function typesSous(noeud) {
  if (!noeud || typeof noeud !== 'object') return [];
  const vus = new Set(Array.isArray(noeud.types) ? noeud.types : []);
  for (const enfant of noeud.enfants || []) {
    for (const t of typesSous(enfant)) vus.add(t);
  }
  return [...vus];
}

export function replier(noeud) {
  if (!noeud || typeof noeud !== 'object') return null;

  let nom = noeud.nom;
  let courant = noeud;
  while ((courant.enfants || []).length === 1) {
    const seul = courant.enfants[0];
    if (!seul || !seul.nom) break;
    nom = nom ? `${nom}/${seul.nom}` : seul.nom;
    courant = seul;
  }

  return {
    nom,
    n: noeud.n,
    types: typesSous(noeud),
    enfants: courant.enfants || [],
  };
}

export function vueDeDepart(arbre) {
  if (!arbre || typeof arbre !== 'object') return [];
  let nom = arbre.nom || '';
  let courant = arbre;
  while ((courant.enfants || []).length === 1) {
    const seul = courant.enfants[0];
    if (!seul || !seul.nom || !(seul.enfants || []).length) break;
    nom = nom ? `${nom}/${seul.nom}` : seul.nom;
    courant = seul;
  }
  return [{ nom, n: arbre.n, types: typesSous(arbre), enfants: courant.enfants || [] }];
}

export function enfantsAffiches(noeud) {
  if (!noeud || !Array.isArray(noeud.enfants)) return [];
  return noeud.enfants
    .map(replier)
    .filter(Boolean)
    .sort((a, b) => b.n - a.n || String(a.nom).localeCompare(String(b.nom)));
}

export function etatCase(noeud, retenus) {
  if (!noeud || !(retenus instanceof Set)) return 'vide';
  const types = typesSous(noeud);
  if (types.length === 0) return 'vide';
  const pris = types.filter((t) => retenus.has(t)).length;
  if (pris === 0) return 'vide';
  return pris === types.length ? 'plein' : 'partiel';
}
