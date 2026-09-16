const MAX_PROFONDEUR = 128;

export function cleDe(p) {
  return p && p.id != null ? p.id : p?.pid;
}

export function cleParentDe(p) {
  if (!p) return undefined;
  if (p.id != null) return p.parent_id == null ? 0 : p.parent_id;
  return p.ppid;
}

function indexer(procs) {
  const parCle = new Map();
  for (const p of procs) parCle.set(cleDe(p), p);
  return parCle;
}

export function markKernel(procs) {
  const liste = Array.isArray(procs) ? procs : [];
  const parCle = indexer(liste);
  return liste.map(p => {
    let cur = p;
    let garde = 0;
    while (cur && garde++ < MAX_PROFONDEUR) {
      if (cur.pid === 2) return { ...p, noyau: true };
      const pc = cleParentDe(cur);
      if (!pc) return { ...p, noyau: false };
      cur = parCle.get(pc);
    }
    return { ...p, noyau: false };
  });
}

function correspond(p, q) {
  if (!q) return true;
  const t = q.toLowerCase();
  return String(p.name || '').toLowerCase().includes(t)
    || String(p.pid).includes(t)
    || String(p.command_line || '').toLowerCase().includes(t);
}

export function buildTreeRows(procs, options = {}) {
  const liste = Array.isArray(procs) ? procs : [];
  if (liste.length === 0) return [];

  const { replies = new Set(), recherche = '', sansNoyau = false } = options;
  const retenus = sansNoyau ? liste.filter(p => !p.noyau) : liste;
  const dispo = new Set(retenus.map(cleDe));

  const enfants = new Map();
  const racines = [];
  for (const p of retenus) {
    const cle = cleDe(p);
    const pc = cleParentDe(p);
    if (pc && dispo.has(pc) && pc !== cle) {
      if (!enfants.has(pc)) enfants.set(pc, []);
      enfants.get(pc).push(p);
    } else {
      racines.push(p);
    }
  }
  const ordre = (a, b) => (a.pid - b.pid) || (cleDe(a) - cleDe(b));
  for (const l of enfants.values()) l.sort(ordre);
  racines.sort(ordre);

  const visibles = new Map();
  const visible = (p, vus) => {
    const cle = cleDe(p);
    if (visibles.has(cle)) return visibles.get(cle);
    if (vus.has(cle)) return false;
    vus.add(cle);
    const ok = correspond(p, recherche)
      || (enfants.get(cle) || []).some(c => visible(c, vus));
    visibles.set(cle, ok);
    return ok;
  };

  const lignes = [];
  const descendre = (p, profondeur, vus) => {
    const cle = cleDe(p);
    if (profondeur > MAX_PROFONDEUR || vus.has(cle)) return;
    if (!visible(p, new Set())) return;
    vus.add(cle);
    const kids = (enfants.get(cle) || []).filter(c => visible(c, new Set()));
    lignes.push({
      cle,
      pid: p.pid,
      name: p.name,
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
  for (const p of liste) {
    const pc = cleParentDe(p);
    if (pc) avecEnfants.add(pc);
  }
  return avecEnfants;
}
