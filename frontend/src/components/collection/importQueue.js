export const ARCHIVES = new Set(['.zip', '.tar', '.gz', '.tgz', '.7z', '.bz2', '.xz']);

const ARTEFACTS = new Set([
  '.evtx', '.pf', '.lnk', '.dat', '.hve', '.db', '.sqlite', '.mdb',
  '.automaticdestinations-ms', '.customdestinations-ms', '.pcap', '.pcapng', '.cap',
]);

function extension(nom) {
  const texte = String(nom || '');
  const i = texte.lastIndexOf('.');
  return i > 0 ? texte.slice(i).toLowerCase() : '';
}

export function classerDepot(fichiers) {
  const liste = Array.isArray(fichiers) ? fichiers : [];
  const entrees = [];
  const refuses = [];
  const paquet = [];

  for (const fichier of liste) {
    const nom = fichier && fichier.name ? String(fichier.name) : '';
    const taille = Number(fichier && fichier.size) || 0;
    const ext = extension(nom);

    if (!nom) {
      refuses.push({ nom: '', motif: 'format' });
    } else if (taille <= 0) {
      refuses.push({ nom, motif: 'vide' });
    } else if (ARCHIVES.has(ext)) {
      entrees.push({ nom, taille, mode: 'archive', fichiers: [fichier] });
    } else if (ARTEFACTS.has(ext)) {
      paquet.push(fichier);
    } else {
      refuses.push({ nom, motif: 'format' });
    }
  }

  if (paquet.length > 0) {
    entrees.push({
      nom: 'artifacts.zip',
      taille: paquet.reduce((n, f) => n + (Number(f.size) || 0), 0),
      mode: 'paquet',
      fichiers: paquet,
    });
  }

  return { entrees, refuses };
}
