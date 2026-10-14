export const SESSION_INVALID_MESSAGE = 'Session invalide';
export const SESSION_INVALID_CODE = 'session_invalide';
export const SESSION_EXPIRED_CODE = 'session_expiree';
export const SESSION_REPLACED_CODE = 'session_remplacee';
export const SESSION_UNAVAILABLE_CODE = 'session_indisponible';

export function classifySocketError(err) {
  const code = err?.data?.code;
  if (code === SESSION_INVALID_CODE) return 'invalid';
  if (code === SESSION_EXPIRED_CODE) return 'expired';
  if (code === SESSION_UNAVAILABLE_CODE) return 'unavailable';
  if (code === SESSION_REPLACED_CODE) return 'replaced';
  if (!code && err?.message === SESSION_INVALID_MESSAGE) return 'invalid';
  return 'other';
}

export function isSessionRejection(err) {
  return classifySocketError(err) === 'invalid';
}

const RETRY_BASE_MS = 1000;
const RETRY_MAX_MS = 10000;

function isExplicitRefusal(err) {
  const status = err?.response?.status;
  return status === 401 || status === 403 || err?.message === 'no_refresh_token';
}

const storedToken = () => localStorage.getItem('heimdall_token');

export function guardSocketSession(socket, exit, options = {}) {
  const { onOtherError, refresh, getUsedToken } = options;
  const getToken = options.getToken || storedToken;
  let stopped = false;
  let refreshAttempted = false;
  let reconnectOnDisconnect = false;
  let retryDelay = RETRY_BASE_MS;
  let retryTimer = null;

  const stop = () => {
    if (stopped) return;
    stopped = true;
    socket.io.reconnection(false);
    socket.disconnect();
    exit.end('revoked');
  };

  const giveUp = () => {
    if (stopped) return;
    stopped = true;
    socket.io.reconnection(false);
    socket.disconnect();
    exit.end('expired');
  };

  const onExpired = () => {
    if (stopped) return;
    if (!refresh || refreshAttempted) {
      giveUp();
      return;
    }
    refreshAttempted = true;
    refresh().then(
      () => {
        if (stopped) return;
        if (socket.connected) reconnectOnDisconnect = true;
        else socket.connect();
      },
      (err) => {
        if (stopped) return;
        if (isExplicitRefusal(err)) {
          giveUp();
          return;
        }
        refreshAttempted = false;
        const delay = retryDelay;
        retryDelay = Math.min(retryDelay * 2, RETRY_MAX_MS);
        retryTimer = setTimeout(() => {
          retryTimer = null;
          if (!stopped) socket.connect();
        }, delay);
      },
    );
  };

  const reconnectNow = () => {
    if (socket.connected) reconnectOnDisconnect = true;
    else socket.connect();
  };

  const onReplaced = () => {
    if (stopped) return;
    const current = getToken();
    const used = getUsedToken ? getUsedToken() : null;
    if (current && used && current !== used) {
      reconnectNow();
      return;
    }
    onExpired();
  };

  const onConnectError = (err) => {
    const kind = classifySocketError(err);
    if (kind === 'invalid') stop();
    else if (kind === 'expired') onExpired();
    else if (kind === 'replaced') onReplaced();
    else if (onOtherError) onOtherError(err);
  };
  const onConnect = () => { refreshAttempted = false; retryDelay = RETRY_BASE_MS; };
  const onDisconnect = () => {
    if (!reconnectOnDisconnect) return;
    reconnectOnDisconnect = false;
    if (!stopped) socket.connect();
  };

  socket.on('connect_error', onConnectError);
  socket.on('session:revoked', stop);
  socket.on('session:expired', onExpired);
  socket.on('session:replaced', onReplaced);
  socket.on('connect', onConnect);
  socket.on('disconnect', onDisconnect);
  return () => {
    if (retryTimer) clearTimeout(retryTimer);
    socket.off('connect_error', onConnectError);
    socket.off('session:revoked', stop);
    socket.off('session:expired', onExpired);
    socket.off('session:replaced', onReplaced);
    socket.off('connect', onConnect);
    socket.off('disconnect', onDisconnect);
  };
}
