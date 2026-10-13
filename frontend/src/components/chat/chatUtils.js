import { horodatageUtc } from '../../utils/notebookSource';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(id) {
  return typeof id === 'string' && UUID_RE.test(id);
}

function intlLocale(locale) {
  return locale?.startsWith('en') ? 'en-GB' : (locale || 'en-GB');
}

function validDate(ts) {
  if (!ts) return null;
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatTimeUtc(ts) {
  const d = validDate(ts);
  if (!d) return '';
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${hh}:${mm} UTC`;
}

export function formatLocalTitle(ts, locale, timeZone) {
  const d = validDate(ts);
  if (!d) return '';
  return d.toLocaleString(intlLocale(locale), {
    day: 'numeric', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short', timeZone,
  });
}

const IOC_LABELS = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', ipv4: 'IPv4' };

export function iocLabel(type) {
  return IOC_LABELS[type] || String(type).toUpperCase();
}

export function dayKeyUtc(ts) {
  const d = validDate(ts);
  return d ? d.toISOString().slice(0, 10) : '';
}

export function formatDayUtc(ts, locale) {
  const d = validDate(ts);
  if (!d) return '';
  return d.toLocaleDateString(intlLocale(locale), { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

export function shareDraft({ timestamp, artifact_type, description } = {}) {
  const ts = horodatageUtc(timestamp) || '';
  return `\u{1F517} [${artifact_type || '?'}] ${ts}\n${description || ''}`;
}

const IOC_RE = /(?<!\w)(@\w+)|(?<!\w)(?:([a-fA-F0-9]{64})|([a-fA-F0-9]{40})|([a-fA-F0-9]{32}))(?!\w)|(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)/g;
const VERSION_BEFORE_RE = /(?:\bversion|\bver|\bv)\.?\s*$/i;

function validIpv4(value) {
  return value.split('.').every((o) => Number(o) <= 255);
}

export function tokenizeContent(text) {
  const source = String(text ?? '');
  const out = [];
  const push = (t, v) => {
    const last = out[out.length - 1];
    if (t === 'text' && last && last.t === 'text') last.v += v;
    else out.push({ t, v });
  };
  const re = new RegExp(IOC_RE.source, 'g');
  let last = 0;
  let m;
  while ((m = re.exec(source)) !== null) {
    const [full, mention, sha256, sha1, md5, ipv4] = m;
    let type = null;
    if (mention) type = 'mention';
    else if (sha256) type = 'sha256';
    else if (sha1) type = 'sha1';
    else if (md5) type = 'md5';
    else if (ipv4 && validIpv4(ipv4) && !VERSION_BEFORE_RE.test(source.slice(0, m.index))) type = 'ipv4';
    if (!type) continue;
    if (m.index > last) push('text', source.slice(last, m.index));
    push(type, full);
    last = m.index + full.length;
  }
  if (last < source.length) push('text', source.slice(last));
  return out;
}

export function buildReactMap(reactions = [], nameOf = () => '') {
  const m = new Map();
  for (const r of reactions) {
    if (!m.has(r.emoji)) m.set(r.emoji, new Map());
    m.get(r.emoji).set(r.user_id, r.full_name || r.username || nameOf(r.user_id));
  }
  return m;
}

export function reactionTitle(users) {
  return [...users.values()].join(', ');
}

function time(m) {
  const t = new Date(m.created_at).getTime();
  return Number.isNaN(t) ? 0 : t;
}

function compareMessages(a, b) {
  const d = time(a) - time(b);
  if (d !== 0) return d;
  if (isUuid(a.id) && isUuid(b.id)) {
    const x = a.id.toLowerCase();
    const y = b.id.toLowerCase();
    return x < y ? -1 : x > y ? 1 : 0;
  }
  return 0;
}

export function mergeMessages(existing, incoming, { dropMissingInWindow = false } = {}) {
  const base = Array.isArray(existing) ? existing : [];
  const fresh = Array.isArray(incoming) ? incoming : [];
  const byId = new Map();
  const freshIds = new Set(fresh.map((m) => m.id));
  let min = Infinity;
  let max = -Infinity;
  if (dropMissingInWindow) {
    for (const m of fresh) {
      const t = time(m);
      if (t < min) min = t;
      if (t > max) max = t;
    }
  }
  for (const m of base) {
    if (dropMissingInWindow && isUuid(m.id) && !freshIds.has(m.id)) {
      const t = time(m);
      if (t >= min && t <= max) continue;
    }
    byId.set(m.id, m);
  }
  for (const m of fresh) byId.set(m.id, { ...(byId.get(m.id) || {}), ...m });
  return [...byId.values()].sort(compareMessages);
}

export function applyPinEvent(messages, ev) {
  return messages.map((m) => {
    if (m.id === ev.message_id) {
      return ev.pinned
        ? { ...m, pinned: true, pinned_by_username: ev.pinned_by ?? m.pinned_by_username ?? null }
        : { ...m, pinned: false, pinned_by_username: null };
    }
    if (ev.pinned && m.pinned) return { ...m, pinned: false, pinned_by_username: null };
    return m;
  });
}

export function bannerAfterPinEvent(banner, messages, ev) {
  if (!ev.pinned) {
    return { banner: banner && banner.id === ev.message_id ? null : banner, refetch: false };
  }
  const m = messages.find((x) => x.id === ev.message_id);
  if (!m) return { banner: null, refetch: true };
  return {
    banner: {
      id: m.id,
      content: m.content,
      created_at: m.created_at,
      username: m.username,
      full_name: m.full_name,
      pinned_by_username: ev.pinned_by || null,
    },
    refetch: false,
  };
}

export function oldestPersistedId(messages) {
  const m = (messages || []).find((x) => !x.is_ping && isUuid(x.id));
  return m ? m.id : null;
}

export function serverErrorKey(err) {
  const code = err?.code;
  const message = err?.message || err?.error;
  if (code === 'forbidden' || message === 'Accès refusé') return 'chat.err_forbidden';
  if (code === 'not_found' || message === 'Ressource introuvable') return 'chat.err_not_found';
  if (code === 'invalid') return 'chat.err_invalid';
  return 'chat.err_send';
}

export async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_e) {}
  if (typeof document.execCommand !== 'function') return false;
  const active = document.activeElement;
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.className = 'fl-chat-offscreen';
  document.body.appendChild(area);
  try {
    area.focus({ preventScroll: true });
    area.select();
    return document.execCommand('copy') === true;
  } catch (_e) {
    return false;
  } finally {
    area.remove();
    if (active && active !== document.body && typeof active.focus === 'function') active.focus({ preventScroll: true });
  }
}
