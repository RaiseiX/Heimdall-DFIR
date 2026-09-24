const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const VUES = ['timeline', 'processes', 'files', 'auth', 'artifacts'];
const CHEMIN_RE = new RegExp(`^/cases/(${UUID})/collections/(${UUID})/(${VUES.join('|')})(?:\\?([A-Za-z0-9_\\-.~%=&]*))?$`, 'i');
const LIEN_RE = /\[([^\]\n]{1,300})\]\((\/cases\/[^)\s"'<>`]{1,2000})\)/g;
const UUID_RE = new RegExp(`^${UUID}$`, 'i');

function analyserSource(chemin) {
  const m = CHEMIN_RE.exec(String(chemin || ''));
  if (!m) return null;
  const filtres = {};
  for (const [cle, valeur] of new URLSearchParams(m[4] || '')) filtres[cle] = valeur;
  return { caseId: m[1].toLowerCase(), evidenceId: m[2].toLowerCase(), vue: m[3].toLowerCase(), filtres };
}

function cleCanonique(source) {
  const filtres = Object.keys(source.filtres).sort().map((k) => `${k}=${source.filtres[k]}`).join('&');
  return `${source.caseId}/${source.evidenceId}/${source.vue}?${filtres}`;
}

function numeroterTexte(texte, etat) {
  if (typeof texte !== 'string' || !texte) return texte;
  return texte.replace(LIEN_RE, (brut, libelle, chemin) => {
    const source = analyserSource(chemin);
    if (!source) return brut;
    const cle = cleCanonique(source);
    let n = etat.index.get(cle);
    if (!n) {
      n = etat.sources.length + 1;
      etat.index.set(cle, n);
      etat.sources.push({ n, libelle: libelle.trim(), ...source });
    }
    return `${libelle.trim()} [${n}]`;
  });
}

function numeroterSources({ narratif = null, notes = null } = {}) {
  const etat = { index: new Map(), sources: [] };
  let narratifNumerote = narratif;
  if (narratif && typeof narratif === 'object') {
    narratifNumerote = {};
    for (const [cle, texte] of Object.entries(narratif)) narratifNumerote[cle] = numeroterTexte(texte, etat);
  }
  let notesNumerotees = notes;
  if (typeof notes === 'string') notesNumerotees = numeroterTexte(notes, etat);
  else if (Array.isArray(notes)) {
    notesNumerotees = notes.map((n) => {
      if (typeof n === 'string') return numeroterTexte(n, etat);
      if (n && typeof n === 'object') {
        const copie = { ...n };
        if (typeof copie.text === 'string') copie.text = numeroterTexte(copie.text, etat);
        if (typeof copie.note === 'string') copie.note = numeroterTexte(copie.note, etat);
        return copie;
      }
      return n;
    });
  }
  return { narratif: narratifNumerote, notes: notesNumerotees, sources: etat.sources };
}

function horodatage(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

function decrire(source) {
  const f = source.filtres;
  const parties = [];
  if (source.vue === 'timeline') {
    if (f.artifactTypes) parties.push(`artefact ${f.artifactTypes}`);
    const debut = f.startTime && horodatage(f.startTime);
    const fin = f.endTime && horodatage(f.endTime);
    if (debut && fin) parties.push(`fenêtre ${debut} → ${fin}`);
    if (f.hostFilter) parties.push(`hôte ${f.hostFilter}`);
    if (f.userFilter) parties.push(`utilisateur ${f.userFilter}`);
    if (f.eventIdFilter) parties.push(`Event ID ${f.eventIdFilter}`);
    if (!parties.length) parties.push('SuperTimeline');
  } else if (source.vue === 'files') {
    parties.push(`fichier ${f.file || f.path || '(racine de la collecte)'}`);
  } else if (source.vue === 'processes') {
    parties.push('arbre des processus de la collecte');
  } else if (source.vue === 'auth') {
    parties.push("graphe d'authentification de la collecte");
  } else {
    parties.push('résumé des artefacts de la collecte');
  }
  return parties.join(' · ');
}

async function resoudreSources(pool, caseId, sources) {
  if (!sources.length) return [];
  const dossier = String(caseId).toLowerCase();
  const ids = [...new Set(sources.filter((s) => s.caseId === dossier).map((s) => s.evidenceId))].filter((id) => UUID_RE.test(id));
  const preuves = new Map();
  const supprimees = new Set();
  if (ids.length) {
    const { rows } = await pool.query(
      'SELECT id, name, original_filename, hash_sha256 FROM evidence WHERE case_id = $1 AND id = ANY($2::uuid[])',
      [caseId, ids],
    );
    for (const r of rows) preuves.set(String(r.id).toLowerCase(), r);
    const manquantes = ids.filter((id) => !preuves.has(id));
    if (manquantes.length) {
      const journal = await pool.query(
        `SELECT DISTINCT lower(target_id) AS id FROM case_deletion_operations
          WHERE case_id = $1 AND operation_type = 'delete_evidence' AND status = 'completed' AND lower(target_id) = ANY($2::text[])`,
        [caseId, manquantes],
      );
      for (const r of journal.rows) supprimees.add(r.id);
    }
  }
  return sources.map((s) => {
    const base = { n: s.n, libelle: s.libelle, element: decrire(s) };
    if (s.caseId !== dossier) return { ...base, statut: 'hors_dossier', preuve: null, sha256: null, element: null };
    const p = preuves.get(s.evidenceId);
    if (p) return { ...base, statut: 'resolue', preuve: p.original_filename || p.name, sha256: p.hash_sha256 || null };
    return { ...base, statut: supprimees.has(s.evidenceId) ? 'supprimee' : 'introuvable', preuve: null, sha256: null };
  });
}

module.exports = { analyserSource, numeroterSources, resoudreSources, decrire, cleCanonique };
