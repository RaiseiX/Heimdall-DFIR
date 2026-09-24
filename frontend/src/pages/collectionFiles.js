const UNITES = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatOctets(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return '—';
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < UNITES.length - 1) { v /= 1024; i += 1; }
  return `${i === 0 ? v : v.toFixed(1)} ${UNITES[i]}`;
}

export function segmentsDeChemin(chemin) {
  const morceaux = String(chemin || '').split('/').filter(Boolean);
  return morceaux.map((nom, i) => ({ nom, chemin: morceaux.slice(0, i + 1).join('/') }));
}

export function lignesHex(hex, ascii, offset = 0, largeur = 16) {
  const octets = String(hex || '').match(/.{1,2}/g) || [];
  const texte = String(ascii || '');
  const lignes = [];
  for (let i = 0; i < octets.length; i += largeur) {
    lignes.push({
      adresse: (offset + i).toString(16).padStart(8, '0'),
      hex: octets.slice(i, i + largeur).join(' '),
      ascii: texte.slice(i, i + largeur),
    });
  }
  return lignes;
}

const RUCHES = new Set(['ntuser.dat', 'usrclass.dat', 'system', 'software', 'sam', 'security', 'default', 'amcache.hve', 'syscache.hve']);

export function estUneRuche(nom) {
  const bas = String(nom || '').toLowerCase();
  return RUCHES.has(bas) || bas.endsWith('.hve');
}

export function segmentsDeCle(chemin) {
  const morceaux = String(chemin || '').split('\\').filter(Boolean);
  return morceaux.map((nom, i) => ({ nom, chemin: morceaux.slice(0, i + 1).join('\\') }));
}

export function hexGroupe(hex, largeur = 2) {
  return (String(hex || '').match(new RegExp(`.{1,${largeur}}`, 'g')) || []).join(' ');
}
