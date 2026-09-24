const FINIS = new Set(['done', 'skipped', 'error']);
const RANGS = { parsing: 0, error: 1, done: 2, skipped: 3 };
const RANG_FILE = 4;

function valeursDe(etats) {
  return etats && typeof etats === 'object' ? Object.values(etats) : [];
}

function poidsConnu(v) {
  return Boolean(v) && Number.isInteger(v.octets) && v.octets >= 0;
}

export function pourcentage(fait, total, fini) {
  if (!Number.isFinite(fait) || !Number.isFinite(total) || total <= 0) return null;
  if (fini) return 100;
  return Math.min(99, Math.round((fait / total) * 100));
}

export function avancement(etats) {
  const valeurs = valeursDe(etats);
  const total = valeurs.length;
  const termines = valeurs.filter((v) => FINIS.has(v && v.status)).length;
  const fini = total > 0 && termines === total;

  if (total > 0 && valeurs.every(poidsConnu)) {
    const octetsTotal = valeurs.reduce((s, v) => s + v.octets, 0);
    if (octetsTotal > 0) {
      const octetsLus = valeurs.filter((v) => FINIS.has(v.status)).reduce((s, v) => s + v.octets, 0);
      return { termines, total, pct: pourcentage(octetsLus, octetsTotal, fini), mesure: 'octets', octetsLus, octetsTotal };
    }
  }

  return { termines, total, pct: pourcentage(termines, total, fini) ?? 0, mesure: 'parseurs', octetsLus: null, octetsTotal: null };
}

export function parseurPrincipal(etats) {
  const pas = avancement(etats);
  if (pas.mesure !== 'octets') return null;
  const actifs = Object.entries(etats)
    .filter(([, v]) => v && v.status === 'parsing')
    .sort(([ca, a], [cb, b]) => b.octets - a.octets || ca.localeCompare(cb));
  if (actifs.length === 0) return null;
  const [cle, v] = actifs[0];
  return { cle, octets: v.octets, part: Math.round((v.octets / pas.octetsTotal) * 100), autres: actifs.length - 1 };
}

export function lignesIndexees(etats) {
  let somme = 0;
  for (const v of valeursDe(etats)) {
    const n = Number(v && v.records);
    if (Number.isFinite(n)) somme += n;
  }
  return somme;
}

export function parseursOrdonnes(parseurs, etats) {
  const liste = Array.isArray(parseurs) ? parseurs : [];
  const connus = etats && typeof etats === 'object' ? etats : {};
  const rang = (p) => {
    const statut = connus[p && p.key] && connus[p.key].status;
    return statut in RANGS ? RANGS[statut] : RANG_FILE;
  };
  const volume = (p) => {
    const n = Number(connus[p && p.key] && connus[p.key].records);
    return Number.isFinite(n) ? n : 0;
  };
  return [...liste].sort((a, b) => {
    const ra = rang(a);
    const rb = rang(b);
    if (ra !== rb) return ra - rb;
    const va = volume(a);
    const vb = volume(b);
    if (va !== vb) return vb - va;
    return String(a && a.key).localeCompare(String(b && b.key));
  });
}

const entierOuNul = v => (Number.isInteger(v) && v >= 0 ? v : null);

export function lignesDuDepliant(parseurs, etats, fichiers) {
  const connus = etats && typeof etats === 'object' ? etats : {};
  const comptes = fichiers && typeof fichiers === 'object' ? fichiers : {};
  return parseursOrdonnes(parseurs, connus).map(p => {
    const e = connus[p.key] || {};
    return {
      cle: p.key,
      nom: p.name || p.key,
      statut: e.status || 'queued',
      fichiers: entierOuNul(comptes[p.key]),
      octets: entierOuNul(e.octets),
      lignes: e.status === 'parsing' || e.status === 'queued' || !e.status ? null : entierOuNul(e.records),
    };
  });
}

export function compteDesStatuts(etats) {
  const compte = {};
  for (const e of valeursDe(etats)) {
    const statut = (e && e.status) || 'queued';
    compte[statut] = (compte[statut] || 0) + 1;
  }
  return compte;
}

export function masquesParPlateforme(masques) {
  const liste = Array.isArray(masques) ? masques : [];
  const compte = new Map();
  for (const entree of liste) {
    const p = (entree && typeof entree === 'object' && entree.plateforme) || null;
    compte.set(p, (compte.get(p) || 0) + 1);
  }
  return [...compte.entries()]
    .map(([plateforme, n]) => ({ plateforme, n }))
    .sort((a, b) => b.n - a.n || String(a.plateforme).localeCompare(String(b.plateforme)));
}

export function dureeLisible(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '';
  const secondes = Math.floor(n / 1000);
  if (secondes < 60) return `${secondes} s`;
  const minutes = Math.floor(secondes / 60);
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, '0')}`;
}
