export const JOURNAL_MAX = 5000;

const NIVEAU_CLIENT = { erreur: 'error', ignore: 'warn' };
const INTERDITS = /[\\/:*?"<>|\u0000-\u001f]+/g;
const ARCHIVE = /\.(zip|7z|tgz|tar\.gz|tar|gz)$/i;

export function cleDeLigne(ligne) {
  return ligne.cle || `${ligne.demarrage}:${ligne.seq}`;
}

export function ligneNavigateur(message, niveau, maintenant, n) {
  return {
    cle: `nav:${n}`,
    ts: maintenant.toISOString(),
    niveau: NIVEAU_CLIENT[niveau] || 'info',
    source: 'navigateur',
    message,
    preuve: null,
  };
}

export function fusionner(existantes, nouvelles, max = JOURNAL_MAX) {
  const parCle = new Map();
  for (const l of [...existantes, ...nouvelles]) parCle.set(cleDeLigne(l), l);
  const rangees = [...parCle.values()]
    .map((l, i) => [l, i])
    .sort(([a, ia], [b, ib]) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : (a.seq ?? 0) - (b.seq ?? 0) || ia - ib))
    .map(([l]) => l);
  return rangees.length > max ? rangees.slice(rangees.length - max) : rangees;
}

export function pourLesPreuves(lignes, preuves) {
  if (!preuves) return lignes;
  return lignes.filter(l => l.preuve == null || preuves.includes(l.preuve));
}

export function filtrer(lignes, requete) {
  const q = String(requete || '').trim().toLowerCase();
  if (!q) return lignes;
  return lignes.filter(l => `${l.source} ${l.message}`.toLowerCase().includes(q));
}

export function heure(ts, locale, timeZone) {
  return new Date(ts).toLocaleTimeString(locale, { hour12: false, timeZone });
}

export function ligneTexte(l) {
  return `${l.ts} ${l.niveau} ${l.source ? `[${l.source}] ` : ''}${l.message}`;
}

export function texteExport(lignes, { provenance, maintenant }) {
  const tete = ['# Heimdall-DFIR - journal du parsing'];
  for (const p of provenance) {
    tete.push(`# preuve    ${p.nom}`);
    tete.push(`# sha256    ${p.sha256 || 'inconnue'}`);
  }
  tete.push(`# exporte   ${maintenant.toISOString()}`);
  tete.push(`# lignes    ${lignes.length}`);
  tete.push('# format    horodatage_utc niveau [source] message');
  tete.push('');
  return `${tete.concat(lignes.map(ligneTexte)).join('\n')}\n`;
}

export function nomExport(nomPreuve, maintenant) {
  const instant = maintenant.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const base = nomPreuve ? String(nomPreuve).replace(ARCHIVE, '').replace(INTERDITS, '_') : '';
  return base ? `parsing_${base}_${instant}.log` : `parsing_${instant}.log`;
}
