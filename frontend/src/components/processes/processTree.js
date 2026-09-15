const MAX_PROFONDEUR = 128;

function indexer(procs) {
  const parPid = new Map();
  for (const p of procs) parPid.set(p.pid, p);
  return parPid;
}

export function markKernel(procs) {
  const liste = Array.isArray(procs) ? procs : [];
  const parPid = indexer(liste);
  return liste.map(p => {
    let cur = p;
    let garde = 0;
    while (cur && garde++ < MAX_PROFONDEUR) {
      if (cur.pid === 2) return { ...p, noyau: true };
      if (!cur.ppid) return { ...p, noyau: false };
      cur = parPid.get(cur.ppid);
    }
    return { ...p, noyau: false };
  });
}

function correspond(p, q) {
  if (!q) return true;
  const t = q.toLowerCase();
  return String(p.nom || '').toLowerCase().includes(t)
    || String(p.pid).includes(t)
    || String(p.commande || '').toLowerCase().includes(t);
}

export function buildTreeRows(procs, options = {}) {
  const liste = Array.isArray(procs) ? procs : [];
  if (liste.length === 0) return [];

  const { replies = new Set(), recherche = '', sansNoyau = false } = options;
  const parPid = indexer(liste);
  const retenus = sansNoyau ? liste.filter(p => !p.noyau) : liste;
  const dispo = new Set(retenus.map(p => p.pid));

  const enfants = new Map();
  const racines = [];
  for (const p of retenus) {
    if (p.ppid && dispo.has(p.ppid) && p.ppid !== p.pid) {
      if (!enfants.has(p.ppid)) enfants.set(p.ppid, []);
      enfants.get(p.ppid).push(p);
    } else {
      racines.push(p);
    }
  }
  for (const l of enfants.values()) l.sort((a, b) => a.pid - b.pid);
  racines.sort((a, b) => a.pid - b.pid);

  const visibles = new Map();
  const visible = (p, vus) => {
    if (visibles.has(p.pid)) return visibles.get(p.pid);
    if (vus.has(p.pid)) return false;
    vus.add(p.pid);
    const ok = correspond(p, recherche)
      || (enfants.get(p.pid) || []).some(c => visible(c, vus));
    visibles.set(p.pid, ok);
    return ok;
  };

  const lignes = [];
  const descendre = (p, profondeur, vus) => {
    if (profondeur > MAX_PROFONDEUR || vus.has(p.pid)) return;
    if (!visible(p, new Set())) return;
    vus.add(p.pid);
    const kids = (enfants.get(p.pid) || []).filter(c => visible(c, new Set()));
    lignes.push({
      pid: p.pid,
      nom: p.nom,
      profondeur,
      aDesEnfants: kids.length > 0,
      proc: p,
    });
    if (replies.has(p.pid)) return;
    for (const c of kids) descendre(c, profondeur + 1, vus);
  };

  const vus = new Set();
  for (const r of racines) descendre(r, 0, vus);
  return lignes;
}

export function collapsibleIds(procs) {
  const liste = Array.isArray(procs) ? procs : [];
  const avecEnfants = new Set();
  for (const p of liste) if (p.ppid) avecEnfants.add(p.ppid);
  return avecEnfants;
}
