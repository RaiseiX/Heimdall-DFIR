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

// Sync a Y.Doc over an existing socket.io connection using the case room relay.
// origin 'remote' on applied updates prevents an echo loop.
export function createReportCollabProvider(socket, caseId, doc) {
  const onLocalUpdate = (update, origin) => {
    if (origin === 'remote') return;
    socket.emit('report:update', { caseId, update: toB64(update) });
  };
  const onState = (msg) => {
    if (msg?.caseId !== caseId) return;
    Y.applyUpdate(doc, fromB64(msg.update), 'remote');
  };
  const onRemoteUpdate = (msg) => {
    if (msg?.caseId !== caseId) return;
    Y.applyUpdate(doc, fromB64(msg.update), 'remote');
  };

  doc.on('update', onLocalUpdate);
  socket.on('report:state', onState);
  socket.on('report:update', onRemoteUpdate);
  socket.emit('report:join', { caseId });
  // re-join on reconnect so state re-syncs
  const onConnect = () => socket.emit('report:join', { caseId });
  socket.on('connect', onConnect);

  return {
    destroy() {
      doc.off('update', onLocalUpdate);
      socket.off('report:state', onState);
      socket.off('report:update', onRemoteUpdate);
      socket.off('connect', onConnect);
    },
  };
}
