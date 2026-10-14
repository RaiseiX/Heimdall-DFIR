'use strict';

const { canAccessCase } = require('../middleware/caseAccess');
const { lireUtilisateur, causeRevocation, CAUSE_REMPLACE, normaliserId, avecDelai } = require('../services/sessionGuard');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVT_INTERNE = 'session:eviction:interne';
const INTERVALLE_FILET_MS = 60000;
const DELAI_TICK_MS = 30000;

const contextes = new WeakMap();
const crochets = new WeakMap();

function normaliserCaseId(caseId) {
  return typeof caseId === 'string' ? caseId.toLowerCase() : caseId;
}

function sallesDuDossier(caseId) {
  const id = normaliserCaseId(caseId);
  return [id, `case:${id}`, `netmap:${id}`];
}

function caseIdDeSalle(room) {
  if (typeof room !== 'string') return null;
  const brut = room.startsWith('case:') ? room.slice(5) : room.startsWith('netmap:') ? room.slice(7) : room;
  return UUID_RE.test(brut) ? brut.toLowerCase() : null;
}

function enregistrerSocket(socket, api) {
  crochets.set(socket, api);
}

function socketsLocales(io) {
  const table = io && io.sockets && io.sockets.sockets;
  return table ? Array.from(table.values()) : [];
}

function journal(io) {
  return contextes.get(io)?.logger || null;
}

function memeUtilisateur(socket, userId) {
  return normaliserId(socket.user?.id) === normaliserId(userId);
}

function deconnecterSocket(socket, evenement = 'session:revoked') {
  try {
    socket.emit(evenement, {});
    socket.disconnect(true);
  } catch (_err) {}
}

async function retirerSocketDuDossier(socket, caseId) {
  const api = crochets.get(socket);
  if (api) {
    await api.retirerDossier(caseId);
    return;
  }
  for (const salle of sallesDuDossier(caseId)) socket.leave(salle);
  socket.emit('case:access:revoked', { case_id: normaliserCaseId(caseId) });
}

function dossiersDeSocket(socket) {
  const ids = new Set();
  for (const salle of socket.rooms || []) {
    const id = caseIdDeSalle(salle);
    if (id) ids.add(id);
  }
  return ids;
}

async function ejecterDossierLocal(io, caseId) {
  const id = normaliserCaseId(caseId);
  const salles = sallesDuDossier(id);
  for (const socket of socketsLocales(io)) {
    if (!salles.some((s) => socket.rooms && socket.rooms.has(s))) continue;
    await retirerSocketDuDossier(socket, id);
  }
}

function deconnecterUtilisateurLocal(io, userId) {
  for (const socket of socketsLocales(io)) {
    if (memeUtilisateur(socket, userId)) deconnecterSocket(socket);
  }
}

async function reevaluerSocket(io, socket, ligne) {
  const pool = contextes.get(io)?.pool;
  const log = journal(io);
  if (!ligne || ligne.is_active === false) {
    deconnecterSocket(socket);
    return;
  }
  Object.assign(socket.user, {
    username: ligne.username,
    full_name: ligne.full_name,
    role: ligne.role,
  });
  for (const caseId of dossiersDeSocket(socket)) {
    let ok;
    try {
      ok = await canAccessCase(socket.user, caseId, pool);
    } catch (err) {
      if (log) log.warn('[sessionEviction] Controle d acces impossible, socket conservee', { error: err.message });
      continue;
    }
    if (!ok) await retirerSocketDuDossier(socket, caseId);
  }
}

async function reevaluerUtilisateurLocal(io, userId) {
  const pool = contextes.get(io)?.pool;
  const concernees = socketsLocales(io).filter((s) => memeUtilisateur(s, userId));
  if (!concernees.length || !pool) return;
  let ligne;
  try {
    ligne = await lireUtilisateur(userId, pool);
  } catch (err) {
    const log = journal(io);
    if (log) log.warn('[sessionEviction] Lecture utilisateur impossible', { error: err.message });
    return;
  }
  for (const socket of concernees) await reevaluerSocket(io, socket, ligne);
}

function diffuser(io, message) {
  if (!io || typeof io.serverSideEmit !== 'function') return;
  try {
    io.serverSideEmit(EVT_INTERNE, message);
  } catch (err) {
    const log = journal(io);
    if (log) log.warn('[sessionEviction] Diffusion inter-instances impossible', { error: err.message });
  }
}

function enregistrer(io, { pool, logger }) {
  contextes.set(io, { pool, logger });
  if (io && typeof io.on === 'function') {
    io.on(EVT_INTERNE, (message) => {
      traiterMessage(io, message).catch((err) => {
        if (logger) logger.warn('[sessionEviction] Message interne en echec', { error: err.message });
      });
    });
  }
}

async function traiterMessage(io, message) {
  if (!message || typeof message !== 'object') return;
  if (message.type === 'dossier') await ejecterDossierLocal(io, message.caseId);
  else if (message.type === 'utilisateur') await reevaluerUtilisateurLocal(io, message.userId);
  else if (message.type === 'deconnexion') deconnecterUtilisateurLocal(io, message.userId);
}

async function ejecterDossier(io, caseId) {
  const id = normaliserCaseId(caseId);
  await ejecterDossierLocal(io, id);
  diffuser(io, { type: 'dossier', caseId: id });
}

async function reevaluerSocketsUtilisateur(io, rawUserId) {
  const userId = normaliserId(rawUserId);
  await reevaluerUtilisateurLocal(io, userId);
  diffuser(io, { type: 'utilisateur', userId });
}

async function deconnecterUtilisateur(io, rawUserId) {
  const userId = normaliserId(rawUserId);
  deconnecterUtilisateurLocal(io, userId);
  diffuser(io, { type: 'deconnexion', userId });
}

async function reevaluerToutes(io) {
  const ctx = contextes.get(io);
  if (!ctx) return;
  const sockets = socketsLocales(io);
  const parUtilisateur = new Map();
  for (const socket of sockets) {
    const id = socket.user?.id;
    if (!id) continue;
    if (!parUtilisateur.has(id)) parUtilisateur.set(id, []);
    parUtilisateur.get(id).push(socket);
  }
  for (const [userId, liste] of parUtilisateur) {
    let ligne;
    try {
      ligne = await lireUtilisateur(userId, ctx.pool);
    } catch (err) {
      if (ctx.logger) ctx.logger.warn('[sessionEviction] Filet : lecture utilisateur impossible', { error: err.message });
      continue;
    }
    for (const socket of liste) {
      if (socket.disconnected) continue;
      const exp = socket.data?.exp ?? socket.user?.exp;
      if (typeof exp === 'number' && exp * 1000 <= Date.now()) {
        deconnecterSocket(socket, 'session:expired');
        continue;
      }
      const cause = socket.user?.jti ? await causeRevocation(socket.user.jti) : null;
      if (cause) {
        deconnecterSocket(socket, cause === CAUSE_REMPLACE ? 'session:replaced' : 'session:revoked');
        continue;
      }
      await reevaluerSocket(io, socket, ligne);
    }
  }
}

function demarrerFilet(io, { intervalleMs = INTERVALLE_FILET_MS, delaiTickMs = DELAI_TICK_MS } = {}) {
  let enCours = false;
  const minuterie = setInterval(async () => {
    if (enCours) return;
    enCours = true;
    try {
      await avecDelai(reevaluerToutes(io), delaiTickMs);
    } catch (err) {
      const log = journal(io);
      if (log) log.warn('[sessionEviction] Filet en echec', { error: err.message });
    } finally {
      enCours = false;
    }
  }, intervalleMs);
  if (typeof minuterie.unref === 'function') minuterie.unref();
  return { arreter: () => clearInterval(minuterie) };
}

module.exports = {
  EVT_INTERNE,
  normaliserCaseId,
  sallesDuDossier,
  caseIdDeSalle,
  enregistrer,
  enregistrerSocket,
  ejecterDossier,
  reevaluerSocketsUtilisateur,
  deconnecterUtilisateur,
  reevaluerToutes,
  demarrerFilet,
  traiterMessage,
};
