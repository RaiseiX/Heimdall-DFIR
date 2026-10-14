import { ACCESS_NOTICE_KEY, CHAT_DRAFT_PREFIX } from './sessionExit';
import { currentUser } from './auth';

const DUPLICATE_WINDOW_MS = 5000;

const drafts = new Map();
const handled = new Map();

export function resetCaseAccessState() {
  drafts.clear();
  handled.clear();
  caseNames.clear();
}

const norm = (id) => (typeof id === 'string' ? id.toLowerCase() : '');

export function registerUnsentDraft(caseId, read) {
  const key = norm(caseId);
  drafts.set(key, read);
  return () => {
    if (drafts.get(key) === read) drafts.delete(key);
  };
}

export function readUnsentDraft(caseId) {
  const read = drafts.get(norm(caseId));
  if (!read) return '';
  const text = read();
  return typeof text === 'string' ? text : '';
}

const caseNames = new Map();

export function rememberCaseNames(list) {
  if (!Array.isArray(list)) return;
  list.forEach((c) => {
    if (c?.id && c.case_number) caseNames.set(norm(c.id), String(c.case_number));
  });
}

export function caseNameOf(caseId) {
  return caseNames.get(norm(caseId)) ?? null;
}

const draftKey = (userId, caseId) => `${CHAT_DRAFT_PREFIX}${userId}:${norm(caseId)}`;

export function saveChatDraft(userId, caseId, text) {
  try { sessionStorage.setItem(draftKey(userId, caseId), text); } catch { return; }
}

export function takeChatDraft(userId, caseId) {
  try {
    const key = draftKey(userId, caseId);
    const text = sessionStorage.getItem(key);
    sessionStorage.removeItem(key);
    return text || '';
  } catch {
    return '';
  }
}

export function setAccessNotice(key) {
  try { sessionStorage.setItem(ACCESS_NOTICE_KEY, key); } catch { return; }
}

export function peekAccessNotice() {
  try { return sessionStorage.getItem(ACCESS_NOTICE_KEY); } catch { return null; }
}

export function clearAccessNotice() {
  try { sessionStorage.removeItem(ACCESS_NOTICE_KEY); } catch { return; }
}

export function currentUserId() {
  return currentUser()?.id ?? 'anonymous';
}

export async function handleCaseAccessRevoked(payload, deps) {
  const revoked = norm(payload?.case_id);
  if (!revoked) return { scope: 'ignored', duplicate: false };
  const current = norm(deps.currentCaseId);
  const scope = current && current === revoked ? 'current' : 'other';
  const now = deps.now();
  const last = handled.get(revoked);
  if (last !== undefined && now - last < DUPLICATE_WINDOW_MS) return { scope, duplicate: true };
  handled.set(revoked, now);

  if (scope === 'other') {
    const name = deps.caseName(revoked);
    if (name) deps.notify('info', 'casedetail.access_revoked_other_named', { name }, { listLink: false });
    else deps.notify('info', 'casedetail.access_revoked_other', {}, { listLink: true });
    return { scope, duplicate: false };
  }

  const unsent = readUnsentDraft(revoked);
  let key = 'casedetail.access_revoked';
  if (unsent.trim()) {
    deps.saveDraft(deps.userId, revoked, unsent);
    key = 'casedetail.access_revoked_draft_kept';
  }
  deps.saveNotice(key);
  deps.navigate('/cases', { replace: true });
  return { scope, duplicate: false };
}
