export const TYPES_LINUX = ['catscale_auth', 'catscale_logon', 'catscale_failed_login'];

export function aretesVisibles(graphe, { echecsSeulement = false } = {}) {
  const aretes = graphe?.aretes || [];
  return echecsSeulement ? aretes.filter((a) => a.echec > 0) : aretes;
}

export function elementsCytoscape(graphe, options = {}) {
  const aretes = aretesVisibles(graphe, options);
  const utiles = new Set();
  for (const a of aretes) { utiles.add(a.source); utiles.add(a.cible); }
  const noeuds = (graphe?.noeuds || [])
    .filter((n) => utiles.has(n.id))
    .map((n) => ({ data: { id: n.id, label: n.libelle, type: n.type, total: n.total, echec: n.echec } }));
  const liens = aretes.map((a) => ({
    data: { id: a.id, source: a.source, target: a.cible, total: a.total, echec: a.echec, poids: Math.log2(a.total + 1) },
  }));
  return [...noeuds, ...liens];
}

export function nomCourt(utilisateur) {
  const s = String(utilisateur || '');
  return s.includes('\\') ? s.split('\\').pop() : s;
}

export function filtresDePivot(arete) {
  const linux = (arete.artifactTypes || []).some((t) => TYPES_LINUX.includes(t));
  const ids = Object.keys(arete.eventIds || {});
  return {
    userFilter: nomCourt(arete.utilisateur),
    ...(ids.length ? { eventIdFilter: ids.join(',') } : {}),
    artifactTypes: (arete.artifactTypes || []).join(','),
    ...(linux ? { hostFilter: arete.machine } : {}),
  };
}

export function repartition(objet) {
  return Object.entries(objet || {})
    .sort((a, b) => b[1] - a[1])
    .map(([cle, n]) => `${cle} (${n})`)
    .join(', ');
}
