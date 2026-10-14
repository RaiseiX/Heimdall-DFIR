export const SESSION_NOTICE_KEY = 'heimdall_session_notice';

export const CHAT_DRAFT_PREFIX = 'heimdall_chat_draft:';
export const ACCESS_NOTICE_KEY = 'heimdall_case_access_notice';

const NOTICE_TEXT_KEYS = {
  revoked: 'login.session_closed',
  expired: 'login.session_expired',
};

export function sessionNoticeTextKey(reason) {
  return NOTICE_TEXT_KEYS[reason] ?? null;
}

const SESSION_KEYS = ['heimdall_token', 'heimdall_refresh_token', 'heimdall_user'];

function sessionKeys(session) {
  if (typeof session.key === 'function') {
    return Array.from({ length: session.length }, (_, i) => session.key(i));
  }
  return Object.keys(session);
}

function purgeCaseData(session) {
  sessionKeys(session).forEach((k) => {
    if (k && (k.startsWith(CHAT_DRAFT_PREFIX) || k === ACCESS_NOTICE_KEY)) session.removeItem(k);
  });
}

export function createSessionExit({ local, session, goToLogin }) {
  let ended = false;
  return {
    end(reason) {
      if (ended) return false;
      ended = true;
      SESSION_KEYS.forEach((k) => local.removeItem(k));
      purgeCaseData(session);
      if (reason) session.setItem(SESSION_NOTICE_KEY, reason);
      if (goToLogin() === false) ended = false;
      return true;
    },
  };
}

export function peekSessionNotice(session = sessionStorage) {
  try {
    return session.getItem(SESSION_NOTICE_KEY);
  } catch {
    return null;
  }
}

export function takeSessionNotice(session = sessionStorage) {
  try {
    const reason = session.getItem(SESSION_NOTICE_KEY);
    session.removeItem(SESSION_NOTICE_KEY);
    return reason;
  } catch {
    return null;
  }
}

export const sessionExit = createSessionExit({
  local: localStorage,
  session: sessionStorage,
  goToLogin: () => {
    if (window.location.pathname.startsWith('/login')) return false;
    window.location.href = '/login';
    return true;
  },
});
