'use strict';

const logger = require('../config/logger').default;
const { revoquerSessionActive } = require('./sessionGuard');
const { deconnecterUtilisateur, reevaluerSocketsUtilisateur, ejecterDossier } = require('../socket/sessionEviction');

async function proteger(operation, contexte) {
  try {
    await operation();
  } catch (err) {
    logger.warn(`[sessionRevocation] ${contexte} en echec`, { error: err.message });
  }
}

async function couperSessionsUtilisateur(io, userId, { revoquerJeton = true } = {}) {
  if (revoquerJeton) await proteger(() => revoquerSessionActive(userId), 'Revocation du jeton');
  if (io) await proteger(() => deconnecterUtilisateur(io, userId), 'Deconnexion des sockets');
}

async function reevaluerAcces(io, userId) {
  if (!io || !userId) return;
  await proteger(() => reevaluerSocketsUtilisateur(io, userId), 'Reevaluation des acces');
}

async function retirerDossierDesSockets(io, caseId) {
  if (!io) return;
  await proteger(() => ejecterDossier(io, caseId), 'Ejection du dossier');
}

module.exports = { couperSessionsUtilisateur, reevaluerAcces, retirerDossierDesSockets };
