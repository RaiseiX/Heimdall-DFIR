import { pourcentage } from './parsingView';

export const ETAPES = ['upload', 'extract', 'detect', 'parse', 'timeline'];

function nombre(valeur) {
  if (valeur === null || valeur === undefined || valeur === '' || typeof valeur === 'boolean') return null;
  const n = Number(valeur);
  return Number.isFinite(n) ? n : null;
}

export function mesureDEtape(etape, etat = {}) {
  switch (etape) {
    case 'upload': {
      const recus = nombre(etat.octetsRecus) ?? 0;
      const total = nombre(etat.octetsTotal) ?? 0;
      return {
        pct: total > 0 ? Math.round((recus / total) * 100) : null,
        valeurs: { recus, total },
        indetermine: false,
      };
    }
    case 'extract': {
      const fichiers = nombre(etat.fichiers);
      if (fichiers === null) return { pct: null, valeurs: {}, indetermine: true };
      return { pct: 100, valeurs: { fichiers }, indetermine: false };
    }
    case 'detect': {
      const types = nombre(etat.types) ?? 0;
      return { pct: types > 0 ? 100 : null, valeurs: { types }, indetermine: false };
    }
    case 'parse': {
      const finis = nombre(etat.parseursFinis) ?? 0;
      const total = nombre(etat.parseursTotal) ?? 0;
      const lignes = nombre(etat.lignes) ?? 0;
      const fini = total > 0 && finis >= total;
      const octetsLus = nombre(etat.octetsLus);
      const octetsTotal = nombre(etat.octetsTotal);
      if (octetsLus !== null && octetsTotal !== null && octetsTotal > 0) {
        return {
          pct: pourcentage(octetsLus, octetsTotal, fini),
          valeurs: { octetsLus, octetsTotal, lignes },
          mesure: 'octets',
          indetermine: false,
        };
      }
      return {
        pct: pourcentage(finis, total, fini),
        valeurs: { finis, total, lignes },
        mesure: 'parseurs',
        indetermine: false,
      };
    }
    case 'hayabusa': {
      if (etat.statut === 'fait') {
        return { pct: 100, valeurs: { detections: nombre(etat.detections) ?? 0 }, indetermine: false };
      }
      return { pct: null, valeurs: {}, indetermine: etat.statut === 'cours' };
    }
    case 'timeline': {
      const lignes = nombre(etat.lignes) ?? 0;
      return { pct: lignes > 0 ? 100 : null, valeurs: { lignes }, indetermine: false };
    }
    default:
      return { pct: null, valeurs: {}, indetermine: false };
  }
}

export function artefactsTries(detectes) {
  if (!detectes || typeof detectes !== 'object' || Array.isArray(detectes)) return [];
  return Object.entries(detectes)
    .map(([cle, info]) => ({ cle, fichiers: (info ? nombre(info.count) ?? nombre(info.n) : null) ?? 0 }))
    .sort((a, b) => b.fichiers - a.fichiers || a.cle.localeCompare(b.cle));
}

export function typesAbsents(detectes, catalogue, plateforme) {
  if (!plateforme) return [];
  if (!catalogue || typeof catalogue !== 'object') return [];
  const vus = new Set(detectes && typeof detectes === 'object' ? Object.keys(detectes) : []);
  return Object.entries(catalogue)
    .filter(([cle, p]) => p === plateforme && !vus.has(cle))
    .map(([cle]) => cle)
    .sort();
}

const STATUT_FIN = { success: 'done', skipped: 'skipped' };

export function etatsApresEvenement(etats, evenement, cle) {
  const base = etats && typeof etats === 'object' ? etats : {};
  if (!evenement || typeof evenement !== 'object') return base;

  if (evenement.type === 'start') {
    if (!Array.isArray(evenement.artifacts)) return base;
    const poids = evenement.poids && typeof evenement.poids === 'object' ? evenement.poids : {};
    const suivant = {};
    for (const k of evenement.artifacts) {
      const entree = { status: 'queued' };
      if (Number.isInteger(poids[k]) && poids[k] >= 0) entree.octets = poids[k];
      suivant[k] = entree;
    }
    return suivant;
  }

  if (!cle) return base;
  const avant = base[cle] || {};

  if (evenement.type === 'artifact_start') {
    return { ...base, [cle]: { ...avant, status: 'parsing' } };
  }
  if (evenement.type === 'artifact_done') {
    return {
      ...base,
      [cle]: { ...avant, status: STATUT_FIN[evenement.status] || 'error', records: evenement.records ?? avant.records },
    };
  }
  return base;
}

export function etapesDeChaine({ avecHayabusa } = {}) {
  return avecHayabusa ? [...ETAPES, 'hayabusa'] : [...ETAPES];
}

const ETAPE_DU_PANNEAU = {
  uploading: 'upload', extracting: 'extract', detecting: 'detect', detected: 'detect',
  parsing: 'parse', hayabusa: 'hayabusa',
};

export function indexDEtape(step, etapes) {
  const liste = Array.isArray(etapes) ? etapes : [];
  if (step === 'done') return liste.length;
  const cle = ETAPE_DU_PANNEAU[step];
  return cle ? liste.indexOf(cle) : -1;
}

export function etatsDeChaine({ etapes, index, echec = null } = {}) {
  const liste = Array.isArray(etapes) ? etapes : [];
  return liste.map((cle, i) => {
    if (echec !== null && echec !== undefined && i === echec) return { cle, etat: 'erreur' };
    if (i < index) return { cle, etat: 'fait' };
    if (i === index && (echec === null || echec === undefined)) return { cle, etat: 'cours' };
    return { cle, etat: 'attente' };
  });
}

const STATUT_DE_MOTEUR = { running: 'cours', done: 'fait', error: 'erreur' };

export function hayabusaDepuisChasse(chasse, debutParsing) {
  const attente = { statut: 'attente', detections: null, erreur: null };
  if (!chasse || !chasse.started_at || !debutParsing) return attente;
  const depart = Date.parse(chasse.started_at);
  const debut = Date.parse(debutParsing);
  if (!Number.isFinite(depart) || !Number.isFinite(debut) || depart < debut) return attente;
  const etape = (Array.isArray(chasse.steps) ? chasse.steps : []).find(x => x && x.key === 'hayabusa');
  const statut = etape && STATUT_DE_MOTEUR[etape.status];
  if (!statut) return attente;
  return {
    statut,
    detections: statut === 'fait' ? (nombre(etape.count) ?? 0) : null,
    erreur: statut === 'erreur' ? (etape.error || null) : null,
  };
}
