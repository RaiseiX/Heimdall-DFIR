import * as Y from 'yjs';

function toB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function fromB64(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

export function createCollabProvider(socket, caseId, doc, canal, { onState } = {}) {
  const onLocalUpdate = (update, origin) => {
    if (origin === 'remote') return;
    socket.emit(`${canal}:update`, { caseId, update: toB64(update) });
  };
  const onStateMsg = (msg) => {
    if (msg?.caseId !== caseId) return;
    Y.applyUpdate(doc, fromB64(msg.update), 'remote');
    if (onState) onState();
  };
  const onRemoteUpdate = (msg) => {
    if (msg?.caseId !== caseId) return;
    Y.applyUpdate(doc, fromB64(msg.update), 'remote');
  };

  const onConnect = () => socket.emit(`${canal}:join`, { caseId });
  let detached = false;
  const detach = () => {
    if (detached) return;
    detached = true;
    doc.off('update', onLocalUpdate);
    socket.off(`${canal}:state`, onStateMsg);
    socket.off(`${canal}:update`, onRemoteUpdate);
    socket.off('connect', onConnect);
    socket.off('case:access:revoked', onAccessRevoked);
  };
  const onAccessRevoked = (msg) => {
    if (String(msg?.case_id || '').toLowerCase() !== String(caseId).toLowerCase()) return;
    detach();
  };

  doc.on('update', onLocalUpdate);
  socket.on(`${canal}:state`, onStateMsg);
  socket.on(`${canal}:update`, onRemoteUpdate);
  socket.emit(`${canal}:join`, { caseId });
  socket.on('connect', onConnect);
  socket.on('case:access:revoked', onAccessRevoked);

  return { destroy: detach };
}

export function createReportCollabProvider(socket, caseId, doc, options = {}) {
  return createCollabProvider(socket, caseId, doc, 'report', options);
}
