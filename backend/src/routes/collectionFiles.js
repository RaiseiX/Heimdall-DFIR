const express = require('express');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { canAccessCase } = require('../middleware/caseAccess');
const { resoudreRacineDeCollecte } = require('../services/collectionRoot');
const fichiers = require('../services/collectionFiles');
const logger = require('../config/logger').default;

const RACINES_PAR_DEFAUT = [...new Set(['/app/collections', process.env.COLLECTIONS_DIR || '/app/collections'])];
const SCRIPT_RUCHE = path.resolve(__dirname, '..', '..', 'parsers', 'parse_hive_browse.py');
const RUCHE_DELAI_MS = 60000;
const RUCHE_SIMULTANES = 2;
const STATUT_RUCHE = { CLE_INTROUVABLE: 404, TERME_INVALIDE: 400, RUCHE_ILLISIBLE: 422, DEPENDANCE: 503 };

function executerPython(args, options) {
  return new Promise((resolve) => {
    execFile('python3', args, options, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout: String(stdout || ''), stderr: String(stderr || ''), tue: Boolean(err && err.killed) });
    });
  });
}

function repondreErreur(res, err, contexte) {
  if (err && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ error: err.message, code: err.code });
  }
  logger.error(`[collection-files] ${contexte}: ${err && err.message}`);
  return res.status(500).json({ error: 'Erreur de lecture de la collecte' });
}

function creerRouteur({
  db = pool, racines = RACINES_PAR_DEFAUT, audit = auditLog, authentifier = authenticate,
  executer = executerPython, scriptRuche = SCRIPT_RUCHE,
} = {}) {
  const router = express.Router();
  let ruchesEnCours = 0;

  const verifierAcces = (req, res, next) => {
    canAccessCase(req.user, req.params.caseId, db)
      .then((ok) => (ok ? next() : res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' })))
      .catch(() => res.status(500).json({ error: "Erreur de contrôle d'accès." }));
  };

  const racineDe = async (req) => {
    const evidenceId = req.query.evidence_id;
    if (typeof evidenceId !== 'string' || !evidenceId) {
      throw Object.assign(new Error('evidence_id requis'), { status: 400, code: 'EVIDENCE_REQUISE' });
    }
    const r = await resoudreRacineDeCollecte(db, req.params.caseId, { evidenceId }, { racines, repertoireRequis: true });
    return r;
  };

  router.get('/:caseId/files', authentifier, verifierAcces, async (req, res) => {
    try {
      const racine = await racineDe(req);
      res.json(await fichiers.listerRepertoire(racine.reel, req.query.path));
    } catch (err) {
      repondreErreur(res, err, 'liste');
    }
  });

  router.get('/:caseId/file/content', authentifier, verifierAcces, async (req, res) => {
    try {
      const racine = await racineDe(req);
      res.json(await fichiers.lireExtrait(racine.reel, req.query.path, { offset: req.query.offset, limite: req.query.limit }));
    } catch (err) {
      repondreErreur(res, err, 'contenu');
    }
  });

  router.get('/:caseId/file/download', authentifier, verifierAcces, async (req, res) => {
    let cible;
    let racine;
    try {
      racine = await racineDe(req);
      cible = await fichiers.fichierConfine(racine.reel, req.query.path);
    } catch (err) {
      return repondreErreur(res, err, 'telechargement');
    }
    const relatif = String(req.query.path || '');
    await audit(req.user.id, 'download_collection_file', 'evidence', racine.evidenceId,
      { case_id: req.params.caseId, path: relatif, size: cible.taille }, req.ip);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(cible.taille));
    res.setHeader('Content-Disposition', fichiers.nomDeTelechargement(relatif.split('/').pop() || 'fichier'));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const flux = fs.createReadStream(cible.chemin);
    flux.on('error', (err) => {
      logger.error(`[collection-files] flux: ${err.message}`);
      res.destroy(err);
    });
    flux.pipe(res);
  });

  router.get('/:caseId/files/search', authentifier, verifierAcces, async (req, res) => {
    try {
      const racine = await racineDe(req);
      res.json(await fichiers.rechercher(racine.reel, req.query.path, req.query.q));
    } catch (err) {
      repondreErreur(res, err, 'recherche');
    }
  });

  router.get('/:caseId/file/hive', authentifier, verifierAcces, async (req, res) => {
    let cible;
    try {
      const racine = await racineDe(req);
      cible = await fichiers.fichierConfine(racine.reel, req.query.path);
    } catch (err) {
      return repondreErreur(res, err, 'ruche');
    }
    const cle = typeof req.query.key === 'string' ? req.query.key.slice(0, 2048) : '';
    const terme = typeof req.query.search === 'string' ? req.query.search.trim() : '';
    if (terme && (terme.length < 2 || terme.length > 200)) {
      return res.status(400).json({ error: 'Le terme doit contenir entre 2 et 200 caractères', code: 'TERME_INVALIDE' });
    }
    if (ruchesEnCours >= RUCHE_SIMULTANES) {
      return res.status(429).json({ error: 'Trop de lectures de ruche en cours, réessayez', code: 'OCCUPE' });
    }
    ruchesEnCours += 1;
    try {
      const args = [scriptRuche, '-f', cible.chemin, '--limit', '500', ...(terme ? ['-s', terme] : cle ? ['-p', cle] : [])];
      const r = await executer(args, { timeout: RUCHE_DELAI_MS, maxBuffer: 32 * 1024 * 1024, encoding: 'utf8' });
      if (r.tue) return res.status(504).json({ error: 'Lecture de la ruche trop longue', code: 'DELAI' });
      let donnees = null;
      try { donnees = JSON.parse(r.stdout.trim().split('\n').pop() || 'null'); } catch { donnees = null; }
      if (!donnees) {
        logger.warn(`[collection-files] ruche: sortie illisible (code ${r.code}) ${r.stderr.slice(0, 300)}`);
        return res.status(500).json({ error: 'Lecture de la ruche impossible' });
      }
      if (donnees.error) {
        return res.status(STATUT_RUCHE[donnees.code] || 500).json({ error: donnees.error, code: donnees.code });
      }
      return res.json(donnees);
    } finally {
      ruchesEnCours -= 1;
    }
  });

  return router;
}

module.exports = creerRouteur();
module.exports.creerRouteur = creerRouteur;
