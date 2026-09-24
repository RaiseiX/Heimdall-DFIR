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

const MARQUEUR_SESSION = 'smss.exe';

export function cheminBinaire(p) {
  const exe = String((p && p.exe) || '').trim();
  if (exe) return exe;
  return String((p && p.image) || '').trim();
}

export function ecartLisible(ms) {
  if (!Number.isFinite(ms) || ms < 0) return null;
  const s = ms / 1000;
  if (s < 60) return { n: Math.round(s), unite: 's' };
  const min = s / 60;
  if (min < 60) return { n: Math.round(min), unite: 'min' };
  const h = min / 60;
  if (h < 24) return { n: Math.round(h * 10) / 10, unite: 'h' };
  return { n: Math.round((h / 24) * 10) / 10, unite: 'j' };
}

function nomDe(p) {
  if (p && p.name) return String(p.name);
  return String((p && p.image) || '').split(/[\\/]/).pop();
}

function instantDe(p) {
  const t = Date.parse(p && p.timestamp);
  return Number.isFinite(t) ? t : 0;
}

export function sessionsDe(procs) {
  const liste = Array.isArray(procs) ? procs : [];
  if (!liste.length) return [];

  const parCle = indexer(liste);
  const estRacine = (p) => {
    const pc = cleParentDe(p);
    if (pc === undefined || pc === null || pc === 0) return true;
    if (pc === cleDe(p)) return true;
    return !parCle.has(pc);
  };

  const ordonne = [...liste].sort((a, b) => instantDe(a) - instantDe(b));
  const sessions = [];
  let attente = [];

  for (const p of ordonne) {
    const racine = estRacine(p);
    if (racine && nomDe(p).toLowerCase() === MARQUEUR_SESSION) {
      sessions.push({ depart: p.timestamp, evenements: [...attente, p], ecartMs: null });
      attente = [];
    } else if (racine) {
      attente.push(p);
    } else if (sessions.length) {
      sessions[sessions.length - 1].evenements.push(p);
    } else {
      attente.push(p);
    }
  }

  if (!sessions.length) return [];
  if (attente.length) sessions[sessions.length - 1].evenements.push(...attente);

  for (let i = 1; i < sessions.length; i++) {
    const ecart = Date.parse(sessions[i].depart) - Date.parse(sessions[i - 1].depart);
    sessions[i].ecartMs = Number.isFinite(ecart) ? ecart : null;
  }
  return sessions;
}

export function racinesDe(procs) {
  const liste = Array.isArray(procs) ? procs : [];
  const parCle = indexer(liste);
  return liste.filter(p => {
    const pc = cleParentDe(p);
    if (pc === undefined || pc === null || pc === 0) return true;
    if (pc === cleDe(p)) return true;
    return !parCle.has(pc);
  });
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

export function filtrerProcessus(procs, options = {}) {
  const liste = Array.isArray(procs) ? procs : [];
  const { seulSupprime = false, seulExpose = false, seulExterne = false } = options;

  const alarmesReseau = [];
  if (seulExpose)  alarmesReseau.push(p => Number(p.net_listen_exposed) > 0);
  if (seulExterne) alarmesReseau.push(p => Number(p.net_estab_external) > 0);

  return liste.filter(p => {
    if (seulSupprime && !p.exe_deleted) return false;
    if (alarmesReseau.length && !alarmesReseau.some(f => f(p))) return false;
    return true;
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
    if (replies.has(cle)) return;
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
