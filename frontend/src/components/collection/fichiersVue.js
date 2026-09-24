const OUVERT_JUSQUA = 20;

const NOMS_ENCODAGE = {
  'utf-8': 'UTF-8',
  'utf-16le': 'UTF-16LE',
  'utf-16be': 'UTF-16BE',
  'windows-1252': 'Windows-1252',
  hexa: 'Hexa',
};

export function compter(fichiers) {
  return { tous: fichiers.length, nonLus: fichiers.filter(f => !f.lu).length };
}

export function grouperParDossier(fichiers, { seulementNonLus, filtre }) {
  const aiguille = (filtre || '').toLowerCase();
  const groupes = new Map();
  for (const f of fichiers) {
    if (seulementNonLus && f.lu) continue;
    if (aiguille && !f.chemin.toLowerCase().includes(aiguille)) continue;
    const coupe = f.chemin.lastIndexOf('/');
    const dossier = coupe > 0 ? f.chemin.slice(0, coupe) : '';
    if (!groupes.has(dossier)) groupes.set(dossier, []);
    groupes.get(dossier).push({ ...f, nom: f.chemin.slice(coupe + 1) });
  }
  return [...groupes.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([dossier, liste]) => ({ dossier, fichiers: liste }));
}

export function ouvertParDefaut(groupe, filtre) {
  return Boolean(filtre) || groupe.fichiers.length <= OUVERT_JUSQUA;
}

export function designation(fichier) {
  return fichier.octets ? { octets: fichier.octets } : { chemin: fichier.chemin };
}

export function lignesTexte(texte, premiere) {
  if (!texte) return [];
  const lignes = texte.split('\n');
  if (lignes[lignes.length - 1] === '') lignes.pop();
  return lignes.map((l, i) => ({
    no: premiere == null ? null : premiere + i,
    texte: l.endsWith('\r') ? l.slice(0, -1) : l,
  }));
}

export function morceaux(ligne, terme) {
  if (!terme) return [{ texte: ligne, marque: false }];
  const bas = ligne.toLowerCase();
  const aiguille = terme.toLowerCase();
  const resultat = [];
  let debut = 0;
  for (let i = bas.indexOf(aiguille); i >= 0; i = bas.indexOf(aiguille, i + aiguille.length)) {
    if (i > debut) resultat.push({ texte: ligne.slice(debut, i), marque: false });
    resultat.push({ texte: ligne.slice(i, i + aiguille.length), marque: true });
    debut = i + aiguille.length;
  }
  if (debut < ligne.length) resultat.push({ texte: ligne.slice(debut), marque: false });
  return resultat.length ? resultat : [{ texte: ligne, marque: false }];
}

export function lignesHexa(hexa, offset) {
  const octets = (hexa.match(/../g) || []).map(x => parseInt(x, 16));
  const lignes = [];
  for (let i = 0; i < octets.length; i += 16) {
    const ligne = octets.slice(i, i + 16);
    lignes.push({
      offset: (offset + i).toString(16).padStart(8, '0'),
      hexa: ligne.map(o => o.toString(16).padStart(2, '0')).join(' '),
      ascii: ligne.map(o => (o >= 0x20 && o < 0x7f ? String.fromCharCode(o) : '.')).join(''),
    });
  }
  return lignes;
}

export function nomEncodage(code) {
  return NOMS_ENCODAGE[code] || code;
}

export function octetsDuNom(hexa) {
  const octets = (hexa || '').toLowerCase().match(/../g) || [];
  return octets.slice(octets.lastIndexOf('2f') + 1).join(' ');
}
