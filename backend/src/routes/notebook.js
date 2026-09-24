'use strict';
const express = require('express');
const logger = require('../config/logger').default;
const { NotebookError } = require('../services/notebookDocRegistry');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATUT = { VIDE: 400, TROP_LONG: 413, VERSION_PERIMEE: 409 };

function diffuser(io, caseId, update) {
  if (!io || !update || !update.length) return;
  io.to(`case:${caseId}`).emit('notebook:update', { caseId, update: Buffer.from(update).toString('base64') });
}

function creerRouteur({ db, registre, audit, authentifier, controleAcces }) {
  const router = express.Router();
  router.use(authentifier);
  router.param('id', (req, res, next, valeur) => {
    if (!UUID.test(valeur)) return res.status(400).json({ error: 'Identifiant invalide' });
    return controleAcces(req, res, next, valeur);
  });

  const echec = (res, err, etape) => {
    if (err instanceof NotebookError) return res.status(STATUT[err.code] || 400).json({ error: err.message, code: err.code });
    logger.error(`[notebook] ${etape} error: ${err.message}`);
    return res.status(500).json({ error: 'Erreur serveur' });
  };
  const tracer = (req, action, chars) =>
    Promise.resolve(audit(req.user.id, action, 'case', req.params.id, { chars }, req.ip)).catch(() => {});

  router.get('/:id', async (req, res) => {
    try {
      res.json(await registre.lire(db, req.params.id));
    } catch (err) { echec(res, err, 'get'); }
  });

  router.put('/:id', async (req, res) => {
    try {
      const contenu = String(req.body?.content ?? '');
      const update = await registre.remplacer(db, req.params.id, contenu, req.body?.base_updated_at ?? null, req.user.id);
      diffuser(req.app.locals.io, req.params.id, update);
      const { updated_at } = await registre.lire(db, req.params.id);
      tracer(req, 'save_notebook', contenu.length);
      res.json({ saved: true, updated_at });
    } catch (err) { echec(res, err, 'put'); }
  });

  router.post('/:id/append', async (req, res) => {
    try {
      const bloc = String(req.body?.content ?? '');
      const update = await registre.ajouter(db, req.params.id, bloc, req.user.id);
      diffuser(req.app.locals.io, req.params.id, update);
      const { updated_at } = await registre.lire(db, req.params.id);
      tracer(req, 'append_notebook', bloc.trim().length);
      res.json({ appended: true, updated_at });
    } catch (err) { echec(res, err, 'append'); }
  });

  return router;
}

function routeurParDefaut() {
  const { pool } = require('../config/database');
  const { authenticate, auditLog } = require('../middleware/auth');
  const { caseAccessParam } = require('../middleware/caseAccess');
  const notebookDocs = require('../services/notebookDocs');
  return creerRouteur({ db: pool, registre: notebookDocs, audit: auditLog, authentifier: authenticate, controleAcces: caseAccessParam });
}

module.exports = routeurParDefaut();
module.exports.creerRouteur = creerRouteur;
