const fs = require('fs');
const path = require('path');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function refus(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

function reel(chemin, fsImpl = fs) {
  if (typeof chemin !== 'string' || !chemin) return null;
  try {
    return fsImpl.realpathSync(path.resolve(chemin));
  } catch {
    return null;
  }
}

function dedans(racine, cible) {
  return cible === racine || cible.startsWith(racine + path.sep);
}

async function cheminsConnus(db, caseId) {
  const { rows } = await db.query(
    `SELECT 'import' AS origine, evidence_id, COALESCE(NULLIF(output_data->>'collection_dir', ''), input_file) AS chemin, created_at AS date
       FROM parser_results
      WHERE case_id = $1 AND parser_name = 'MagnetRESPONSE_Import'
        AND COALESCE(NULLIF(output_data->>'collection_dir', ''), input_file) IS NOT NULL
     UNION ALL
     SELECT 'preuve' AS origine, id AS evidence_id, file_path AS chemin, created_at AS date
       FROM evidence
      WHERE case_id = $1 AND file_path IS NOT NULL AND file_path <> ''
      ORDER BY date DESC NULLS LAST`,
    [caseId]
  );
  return rows;
}

async function resoudreRacineDeCollecte(db, caseId, demande = {}, options = {}) {
  const fsImpl = options.fsImpl || fs;
  const racines = (options.racines || []).map((r) => reel(r, fsImpl)).filter(Boolean);
  const { evidenceId, collectionDir } = demande;

  let preuve = null;
  if (evidenceId !== undefined && evidenceId !== null && evidenceId !== '') {
    if (typeof evidenceId !== 'string' || !UUID_RE.test(evidenceId)) {
      throw refus(400, 'EVIDENCE_INVALIDE', 'evidence_id invalide');
    }
    const ev = await db.query('SELECT id, file_path FROM evidence WHERE id = $1 AND case_id = $2', [evidenceId, caseId]);
    if (ev.rows.length === 0) throw refus(403, 'HORS_DOSSIER', 'Collecte introuvable ou accès refusé');
    preuve = ev.rows[0];
  }

  const connus = await cheminsConnus(db, caseId);
  const parReel = new Map();
  for (const ligne of connus) {
    const r = reel(ligne.chemin, fsImpl);
    if (r && !parReel.has(r)) parReel.set(r, ligne);
  }

  let retenu = null;
  const demandeReelle = typeof collectionDir === 'string' && collectionDir ? reel(collectionDir, fsImpl) : null;
  if (demandeReelle) {
    const connu = parReel.get(demandeReelle);
    if (!connu) throw refus(403, 'HORS_DOSSIER', 'Collecte introuvable ou accès refusé');
    const reelPreuve = preuve ? reel(preuve.file_path, fsImpl) : null;
    if (reelPreuve && reelPreuve !== demandeReelle) {
      throw refus(400, 'COLLECTE_DIVERGENTE', 'collection_dir et evidence_id désignent deux collectes différentes');
    }
    retenu = { chemin: connu.chemin, reel: demandeReelle, evidenceId: preuve ? preuve.id : null };
  } else if (preuve) {
    const r = reel(preuve.file_path, fsImpl);
    if (r) retenu = { chemin: preuve.file_path, reel: r, evidenceId: preuve.id };
  } else {
    for (const ligne of connus) {
      if (ligne.origine !== 'import') continue;
      const r = reel(ligne.chemin, fsImpl);
      if (r) { retenu = { chemin: ligne.chemin, reel: r, evidenceId: null }; break; }
    }
  }

  if (!retenu) throw refus(404, 'INTROUVABLE', 'Répertoire de collecte introuvable');
  if (!racines.some((r) => dedans(r, retenu.reel))) {
    throw refus(403, 'HORS_STOCKAGE', 'Collecte hors du stockage autorisé');
  }
  if (options.repertoireRequis === true) {
    let st = null;
    try { st = fsImpl.statSync(retenu.reel); } catch { st = null; }
    if (!st || !st.isDirectory()) throw refus(404, 'INTROUVABLE', 'Répertoire de collecte introuvable');
  }
  return retenu;
}

module.exports = { resoudreRacineDeCollecte, cheminsConnus, UUID_RE };
