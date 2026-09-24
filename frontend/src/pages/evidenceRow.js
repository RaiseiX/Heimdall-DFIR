import { ecartDeclare, entier } from './evidenceCounts';

const SCANS_ECRITS = { quarantined: 'quarantaine' };

export function faitsDePiece({ type, octets, octetsArchive, verseLe, scanStatus, declare, indexe } = {}) {
  const segments = [];

  if (type) segments.push({ cle: 'type', valeur: type });
  const archive = entier(octetsArchive);
  const extrait = entier(octets);
  if (archive !== null && extrait !== null && archive !== extrait) {
    segments.push({ cle: 'archive', valeur: archive });
    segments.push({ cle: 'extrait', valeur: extrait });
  } else if (extrait !== null) {
    segments.push({ cle: 'taille', valeur: extrait });
  } else if (archive !== null) {
    segments.push({ cle: 'archive', valeur: archive });
  }
  if (verseLe) segments.push({ cle: 'verse', valeur: verseLe });

  const marque = SCANS_ECRITS[scanStatus];
  if (marque) segments.push({ cle: marque, ton: 'alerte' });

  const declares = entier(declare) ?? 0;
  const indexes = entier(indexe) ?? 0;
  const ecart = ecartDeclare(declares, indexes);

  if (ecart) {
    segments.push({ cle: 'parse', valeur: ecart.declare });
    segments.push({ cle: 'indexe', valeur: ecart.stocke });
    segments.push({ cle: 'ecart', valeur: ecart.manquant, ton: 'ecart' });
  } else if (indexes > 0) {
    segments.push({ cle: 'indexe', valeur: indexes });
  } else {
    segments.push({ cle: 'non-parse' });
  }

  return segments;
}

export function actionsDePiece({ declare, indexe } = {}) {
  const declares = entier(declare) ?? 0;
  const indexes = entier(indexe) ?? 0;
  return {
    parsing: declares > 0 || indexes > 0 ? 'reparse' : 'parse',
    timeline: indexes > 0,
  };
}

export function octetsArchiveDe(metadata) {
  let objet = metadata;
  if (typeof objet === 'string') {
    try { objet = JSON.parse(objet); } catch { return null; }
  }
  if (!objet || typeof objet !== 'object') return null;
  return entier(objet.archive_size);
}
