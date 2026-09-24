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

  doc.on('update', onLocalUpdate);
  socket.on(`${canal}:state`, onStateMsg);
  socket.on(`${canal}:update`, onRemoteUpdate);
  socket.emit(`${canal}:join`, { caseId });
  const onConnect = () => socket.emit(`${canal}:join`, { caseId });
  socket.on('connect', onConnect);

  return {
    destroy() {
      doc.off('update', onLocalUpdate);
      socket.off(`${canal}:state`, onStateMsg);
      socket.off(`${canal}:update`, onRemoteUpdate);
      socket.off('connect', onConnect);
    },
  };
}

export function createReportCollabProvider(socket, caseId, doc) {
  return createCollabProvider(socket, caseId, doc, 'report');
}
