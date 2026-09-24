import { etatsApresEvenement, etapesDeChaine, etatsDeChaine, indexDEtape, hayabusaDepuisChasse, mesureDEtape } from './importView';
import { avancement } from './parsingView';
import { vueDeDepart } from './arbreVue';

export const DELAI_REVUE = 10000;

const HAYABUSA_VIDE = { statut: 'attente', detections: null, erreur: null };

const ETAPE_DU_STATUT = {
  envoi: 'uploading', extraction: 'extracting', detecte: 'detected', revue: 'detected',
  parsing: 'parsing', hayabusa: 'hayabusa', fini: 'done',
};

const ETAPE_EN_ECHEC = {
  attente: 'uploading', envoi: 'uploading', extraction: 'extracting', detecte: 'detecting', revue: 'detecting',
  parsing: 'parsing', hayabusa: 'hayabusa',
};

export function entreesInitiales(entrees) {
  return (Array.isArray(entrees) ? entrees : []).map((e, id) => ({
    id,
    nom: e.nom,
    taille: e.taille,
    mode: e.mode,
    fichiers: e.fichiers,
    etat: 'attente',
    octets: { recus: 0, total: Number(e.taille) || 0 },
    collDir: null,
    detected: null,
    types: [],
    retenus: [],
    arbre: null,
    pile: [],
    echeance: null,
    catscale: false,
    avecHayabusa: false,
    parserStates: {},
    actif: false,
    lance: false,
    debutParsing: null,
    hayabusa: HAYABUSA_VIDE,
    erreur: null,
    echec: null,
  }));
}

function modifier(file, trouve, maj) {
  const i = file.findIndex(trouve);
  if (i < 0) return file;
  const suivant = [...file];
  suivant[i] = { ...file[i], ...maj(file[i]) };
  return suivant;
}

const parId = (id) => (e) => e.id === id;
const parDossier = (dossier) => (e) => Boolean(dossier) && e.collDir === dossier;

function typesDetectes(detected) {
  const det = detected && typeof detected === 'object' ? detected : {};
  return Object.keys(det).filter((k) => (Number(det[k] && (det[k].count ?? det[k].n)) || 0) > 0);
}

export function fileApres(file, ev) {
  if (!Array.isArray(file) || !ev) return file;
  switch (ev.type) {
    case 'envoi':
      return modifier(file, parId(ev.id), () => ({
        etat: 'envoi', octets: { recus: Number(ev.recus) || 0, total: Number(ev.total) || 0 },
      }));
    case 'envoye':
      return modifier(file, parId(ev.id), (e) => {
        const total = e.octets.total || e.octets.recus;
        return { etat: 'extraction', collDir: ev.collDir || null, octets: { recus: total, total } };
      });
    case 'extrait':
      return modifier(file, parDossier(ev.collDir), () => {
        const types = typesDetectes(ev.detected);
        const catscale = types.includes('catscale');
        const t0 = Number.isFinite(ev.maintenant) ? ev.maintenant : 0;
        return {
          etat: 'detecte',
          detected: ev.detected || {},
          types,
          retenus: [...types],
          catscale,
          avecHayabusa: !catscale && types.includes('evtx'),
          arbre: ev.arbre || null,
          pile: ev.arbre ? vueDeDepart(ev.arbre) : [],
          echeance: catscale ? t0 : t0 + DELAI_REVUE,
        };
      });
    case 'revoir':
      return modifier(file, parId(ev.id), (e) => (e.etat === 'detecte' && !e.lance ? { etat: 'revue' } : {}));
    case 'selection':
      return modifier(file, parId(ev.id), (e) => {
        const garde = new Set(e.retenus);
        for (const t of Array.isArray(ev.types) ? ev.types : []) {
          if (ev.activer) garde.add(t); else garde.delete(t);
        }
        return { retenus: e.types.filter((t) => garde.has(t)) };
      });
    case 'tout':
      return modifier(file, parId(ev.id), (e) => ({ retenus: e.retenus.length === e.types.length ? [] : [...e.types] }));
    case 'lancer':
      return modifier(file, parId(ev.id), (e) => (e.etat === 'revue' || e.etat === 'detecte' ? { etat: 'detecte', echeance: 0 } : {}));
    case 'descendre':
      return modifier(file, parId(ev.id), (e) => (ev.noeud ? { pile: [...e.pile, ev.noeud] } : {}));
    case 'remonter':
      return modifier(file, parId(ev.id), (e) => ({ pile: e.pile.length > 1 ? e.pile.slice(0, -1) : e.pile }));
    case 'lance':
      return modifier(file, parDossier(ev.collDir), () => ({ etat: 'parsing', lance: true }));
    case 'progression': {
      const d = ev.data || {};
      if (d.type === 'start') {
        const i = file.findIndex(parDossier(d.collection_dir));
        if (i < 0) return file;
        return file.map((e, j) => {
          if (j === i) return { ...e, actif: true, parserStates: etatsApresEvenement(e.parserStates, d, null) };
          return e.actif ? { ...e, actif: false } : e;
        });
      }
      if (d.type === 'artifact_start' || d.type === 'artifact_done') {
        return modifier(file, (e) => e.actif, (e) => ({ parserStates: etatsApresEvenement(e.parserStates, d, d.artifact || null) }));
      }
      return file;
    }
    case 'parse_fini':
      return modifier(file, parDossier(ev.collDir), (e) => ({
        actif: false, debutParsing: ev.started_at || null, etat: e.avecHayabusa ? 'hayabusa' : 'fini',
      }));
    case 'chasse': {
      if (!file.some((e) => e.etat === 'hayabusa')) return file;
      return file.map((e) => {
        if (e.etat !== 'hayabusa') return e;
        const h = hayabusaDepuisChasse(ev.chasse, e.debutParsing);
        return h.statut === 'fait' || h.statut === 'erreur' ? { ...e, hayabusa: h, etat: 'fini' } : { ...e, hayabusa: h };
      });
    }
    case 'erreur': {
      const trouve = ev.id !== undefined && ev.id !== null ? parId(ev.id) : parDossier(ev.collDir);
      return modifier(file, trouve, (e) => ({
        etat: 'erreur', erreur: ev.message || null, echec: ETAPE_EN_ECHEC[e.etat] || 'uploading', actif: false,
      }));
    }
    default:
      return file;
  }
}

export function aLancer(file, maintenant = Date.now()) {
  return (Array.isArray(file) ? file : []).filter((e) =>
    e.etat === 'detecte' && !e.lance && e.retenus.length > 0 && (e.echeance ?? 0) <= maintenant);
}

export function resteAvantLancement(e, maintenant) {
  const reste = (((e && e.echeance) || 0) - maintenant) / 1000;
  return reste > 0 ? Math.ceil(reste) : 0;
}

export function ligneDeChaine(e) {
  const etapes = etapesDeChaine({ avecHayabusa: e.avecHayabusa });
  if (e.etat === 'erreur') {
    const idx = indexDEtape(e.echec, etapes);
    return { etapes, maillons: etatsDeChaine({ etapes, index: idx, echec: idx }), cle: etapes[idx] || null, pct: null, reussi: false };
  }
  const index = e.etat === 'attente' ? -1 : indexDEtape(ETAPE_DU_STATUT[e.etat], etapes);
  const idxHayabusa = etapes.indexOf('hayabusa');
  const echec = e.etat === 'fini' && e.hayabusa && e.hayabusa.statut === 'erreur' && idxHayabusa >= 0 ? idxHayabusa : null;
  const maillons = etatsDeChaine({ etapes, index, echec });
  const cle = index >= 0 && index < etapes.length ? etapes[index] : null;
  let pct = null;
  if (cle === 'upload') pct = mesureDEtape('upload', { octetsRecus: e.octets.recus, octetsTotal: e.octets.total }).pct;
  if (cle === 'parse') {
    const pas = avancement(e.parserStates);
    pct = pas.total ? pas.pct : null;
  }
  return { etapes, maillons, cle, pct, reussi: e.etat === 'fini' && echec === null };
}
