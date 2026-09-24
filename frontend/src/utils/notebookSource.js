import { QUERY_KEY_SET } from '../components/supertimeline/utils/timelineFilterKeys';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const UUID_RE = new RegExp(`^${UUID}$`, 'i');

export const VUES = ['timeline', 'processes', 'files', 'auth', 'artifacts'];

const CLES_PAR_VUE = {
  timeline: QUERY_KEY_SET,
  files: new Set(['path', 'file']),
  processes: new Set(),
  auth: new Set(),
  artifacts: new Set(),
};

const CHEMIN_RE = new RegExp(`^/cases/(${UUID})/collections/(${UUID})/(${VUES.join('|')})(?:\\?([A-Za-z0-9_\\-.~%=&]*))?$`, 'i');

export const LIEN_MARKDOWN_RE = /\[([^\]\n]{1,300})\]\((\/cases\/[^)\s"'<>`]{1,2000})\)/g;

export function estUuid(valeur) {
  return typeof valeur === 'string' && UUID_RE.test(valeur);
}

export function cheminSource({ caseId, evidenceId, vue = 'timeline', filtres = {} } = {}) {
  if (!estUuid(caseId) || !estUuid(evidenceId) || !VUES.includes(vue)) return null;
  const autorisees = CLES_PAR_VUE[vue];
  const sp = new URLSearchParams();
  for (const [cle, valeur] of Object.entries(filtres || {})) {
    if (!autorisees.has(cle) || valeur == null || valeur === '') continue;
    sp.set(cle, String(valeur));
  }
  const requete = sp.toString().replace(/\+/g, '%20');
  return `/cases/${caseId.toLowerCase()}/collections/${evidenceId.toLowerCase()}/${vue}${requete ? `?${requete}` : ''}`;
}

export function analyserSource(chemin) {
  const m = CHEMIN_RE.exec(String(chemin || ''));
  if (!m) return null;
  const [, caseId, evidenceId, vue, requete] = m;
  const autorisees = CLES_PAR_VUE[vue.toLowerCase()];
  const filtres = {};
  for (const [cle, valeur] of new URLSearchParams(requete || '')) {
    if (autorisees.has(cle)) filtres[cle] = valeur;
  }
  return { caseId: caseId.toLowerCase(), evidenceId: evidenceId.toLowerCase(), vue: vue.toLowerCase(), filtres };
}

function libelleSur(texte) {
  return String(texte || '').replace(/[[\]()\n\r`]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
}

export function lienSource({ libelle, ...cible }) {
  const chemin = cheminSource(cible);
  if (!chemin) return null;
  return `[${libelleSur(`source : ${libelle}`)}](${chemin})`;
}

export function horodatageUtc(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

export function fenetre(debut, fin = debut, margeMs = 1000) {
  const a = debut ? new Date(debut) : null;
  const b = fin ? new Date(fin) : null;
  if (!a || Number.isNaN(a.getTime()) || !b || Number.isNaN(b.getTime())) return {};
  return {
    startTime: new Date(a.getTime() - margeMs).toISOString(),
    endTime: new Date(b.getTime() + margeMs).toISOString(),
  };
}

export function extraireSources(markdown) {
  const trouvees = [];
  for (const m of String(markdown || '').matchAll(LIEN_MARKDOWN_RE)) {
    const analyse = analyserSource(m[2]);
    if (analyse) trouvees.push({ texte: m[0], libelle: m[1], chemin: m[2], ...analyse });
  }
  return trouvees;
}
