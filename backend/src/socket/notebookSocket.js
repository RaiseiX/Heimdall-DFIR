'use strict';

const TAILLE_MAX = 1_000_000;

const normaliser = (id) => (typeof id === 'string' ? id.toLowerCase() : id);

function brancherCarnet({ socket, pool, registre, guard, user, logger = null, retirer = null }) {
  const abonnements = new Set();

  socket.on('notebook:join', async (payload) => {
    const caseId = normaliser((payload || {}).caseId);
    if (!(await guard(caseId))) { socket.emit('notebook:denied', { caseId }); return; }
    socket.join(`case:${caseId}`);
    if (!(await guard(caseId))) {
      if (retirer) await retirer(caseId);
      else socket.leave(`case:${caseId}`);
      return;
    }
    let doc;
    try {
      if (abonnements.has(caseId)) {
        doc = await registre.getDoc(pool, caseId);
      } else {
        abonnements.add(caseId);
        doc = await registre.acquireDoc(pool, caseId);
      }
    } catch (err) {
      abonnements.delete(caseId);
      if (logger) logger.warn('[notebook] join failed', { caseId, err: err?.message });
      socket.emit('notebook:error', { caseId });
      return;
    }
    socket.emit('notebook:state', { caseId, update: registre.encodeState(doc).toString('base64') });
  });

  socket.on('notebook:update', async (payload) => {
    const { update } = payload || {};
    const caseId = normaliser((payload || {}).caseId);
    if (!caseId || typeof update !== 'string' || update.length > TAILLE_MAX) return;
    if (!abonnements.has(caseId)) return;
    if (!(await guard(caseId))) return;
    try {
      registre.applyRemoteUpdate(pool, caseId, new Uint8Array(Buffer.from(update, 'base64')), user?.id ?? null);
    } catch (err) {
      if (logger) logger.warn('[notebook] rejected update', { caseId, err: err?.message });
      return;
    }
    socket.to(`case:${caseId}`).emit('notebook:update', { caseId, update });
  });

  return {
    quitter(caseId) {
      if (abonnements.delete(caseId)) registre.releaseDoc(pool, caseId).catch(() => {});
    },
    fermer() {
      for (const caseId of abonnements) registre.releaseDoc(pool, caseId).catch(() => {});
      abonnements.clear();
    },
  };
}

module.exports = { brancherCarnet, TAILLE_MAX };
