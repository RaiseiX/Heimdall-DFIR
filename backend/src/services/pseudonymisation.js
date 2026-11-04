const IP_KEYS = new Set([
  'remotehost', 'remoteaddress', 'dstip', 'dst_ip', 'destinationip', 'id.resp_h', 'sourceip', 'src_ip', 'ip',
]);
const USER_KEYS = new Set([
  'user', 'username', 'subjectusername', 'targetusername', 'email', 'user_name',
]);
const HOST_KEYS = new Set([
  'computer', 'hostname', 'host', 'workstationname', 'host_name', 'src_host',
]);

const IOC_HOST_TYPES = new Set(['hostname', 'host', 'computer']);
const IOC_USER_TYPES = new Set(['username', 'user', 'account', 'email']);

const MAX_DEPTH = 32;

const H = '[0-9a-f]{1,4}';
const V4_TAIL = '(?:\\.\\d{1,3}){3}';
const IPV6_RE = new RegExp(
  `(?<![\\w:])(?:(?:${H}:){7}${H}|${H}(?::${H}){0,6}::(?:${H}(?::${H}){0,6}(?:${V4_TAIL})?)?|::${H}(?::${H}){0,6}(?:${V4_TAIL})?)(?![\\w:])`,
  'gi',
);
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const PROFILE_RE = /(?<![\\/])((?:[A-Za-z]:)?[\\/]+(?:Users|home)[\\/]+)([^\\/\s"'<>|:*?]+)/gi;

function validIPv4(value) {
  return value.split('.').every((o) => Number(o) <= 255);
}

const PSEUDO_LIKE_RE = /^(?:user|host|anon)(?:_\d+)?$/i;

const MAX_KNOWN_NAME = 128;
const LOCAL_CHAR = /[A-Za-z0-9._%+-]/;
const DOMAIN_CHAR = /[A-Za-z0-9.-]/;
const WORD_CHAR = /[A-Za-z0-9_]/;

function replaceEmails(value, pseudonym) {
  if (value.indexOf('@') === -1) return value;
  let out = '';
  let last = 0;
  let at = value.indexOf('@');
  while (at !== -1) {
    if (at === last || !LOCAL_CHAR.test(value[at - 1])) {
      at = value.indexOf('@', at + 1);
      continue;
    }
    let start = at;
    while (start > last && LOCAL_CHAR.test(value[start - 1])) start -= 1;
    let end = at + 1;
    while (end < value.length && DOMAIN_CHAR.test(value[end])) end += 1;
    let domainEnd = end;
    while (domainEnd > at + 1 && (value[domainEnd - 1] === '.' || value[domainEnd - 1] === '-')) domainEnd -= 1;
    const labels = value.slice(at + 1, domainEnd).split('.');
    const valid = start < at && labels.length >= 2 && labels.every((l) => l.length > 0);
    if (valid) {
      out += value.slice(last, start) + pseudonym(value.slice(start, domainEnd));
      last = domainEnd;
      at = value.indexOf('@', domainEnd);
    } else {
      at = value.indexOf('@', at + 1);
    }
  }
  return out + value.slice(last);
}

function newNode() {
  return { next: new Map(), value: null };
}

function unit(ch) {
  const lc = ch.toLowerCase();
  return lc.length === 1 ? lc : ch;
}

function createPseudonymizer() {
  const ipMap = new Map();
  const userMap = new Map();
  const hostMap = new Map();

  function ip(value) {
    if (!value || typeof value !== 'string') return value;
    const key = value.trim().toLowerCase();
    if (!ipMap.has(key)) {
      const idx = ipMap.size + 1;
      ipMap.set(key, `10.ANON.${Math.floor((idx - 1) / 254) + 1}.${((idx - 1) % 254) + 1}`);
    }
    return ipMap.get(key);
  }

  function name(value, map, prefix) {
    if (!value || typeof value !== 'string' || !value.trim()) return value;
    const key = value.trim().toLowerCase();
    if (!map.has(key)) map.set(key, `${prefix}_${map.size + 1}`);
    learn(key, map.get(key), prefix === 'USER');
    return map.get(key);
  }

  const user = (value) => name(value, userMap, 'USER');
  const host = (value) => name(value, hostMap, 'HOST');

  const trie = newNode();
  let trieSize = 0;

  function learn(key, pseudonym, priority) {
    if (key.length < 3 || key.length > MAX_KNOWN_NAME || key.includes('@') || PSEUDO_LIKE_RE.test(key)) return;
    let node = trie;
    for (let i = 0; i < key.length; i += 1) {
      const c = unit(key[i]);
      let child = node.next.get(c);
      if (!child) { child = newNode(); node.next.set(c, child); }
      node = child;
    }
    if (node.value === null) trieSize += 1;
    if (node.value === null || priority) node.value = pseudonym;
  }

  function replaceKnown(value) {
    if (trieSize === 0) return value;
    let out = '';
    let last = 0;
    let i = 0;
    const n = value.length;
    while (i < n) {
      if (i > 0 && WORD_CHAR.test(value[i - 1])) {
        i += 1;
        continue;
      }
      let node = trie;
      let bestEnd = -1;
      let bestValue = null;
      for (let j = i; j < n; j += 1) {
        node = node.next.get(unit(value[j]));
        if (!node) break;
        if (node.value !== null && (j + 1 >= n || !WORD_CHAR.test(value[j + 1]))) {
          bestEnd = j + 1;
          bestValue = node.value;
        }
      }
      if (bestEnd > i) {
        out += value.slice(last, i) + bestValue;
        last = bestEnd;
        i = bestEnd;
      } else {
        i += 1;
      }
    }
    return last === 0 ? value : out + value.slice(last);
  }

  function text(value) {
    if (typeof value !== 'string' || !value) return value;
    return replaceKnown(replacePatterns(value));
  }

  function replacePatterns(value) {
    return replaceEmails(value, user)
      .replace(PROFILE_RE, (_m, prefix, who) => `${prefix}${user(who)}`)
      .replace(IPV6_RE, (m) => ip(m))
      .replace(IPV4_RE, (m) => (validIPv4(m) ? ip(m) : m));
  }

  function scalar(value, fn) {
    if (typeof value === 'number' || typeof value === 'boolean') return fn(String(value));
    return fn(value);
  }

  function walk(value, depth) {
    if (typeof value === 'string') return text(value);
    if (value === null || typeof value !== 'object') return value;
    if (depth >= MAX_DEPTH) return null;
    if (Array.isArray(value)) return value.map((v) => walk(v, depth + 1));
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const lk = k.toLowerCase();
      const nested = v !== null && typeof v === 'object';
      if (!nested && v !== '' && v != null && v !== false) {
        if (IP_KEYS.has(lk)) { out[k] = scalar(v, ip); continue; }
        if (USER_KEYS.has(lk)) { out[k] = scalar(v, user); continue; }
        if (HOST_KEYS.has(lk)) { out[k] = scalar(v, host); continue; }
      }
      out[k] = walk(v, depth + 1);
    }
    return out;
  }

  const raw = (value) => walk(value, 0);

  function ioc(type, value) {
    const t = String(type || '').toLowerCase();
    if (t === 'ip') return ip(value);
    if (IOC_USER_TYPES.has(t)) return user(value);
    if (IOC_HOST_TYPES.has(t)) return host(value);
    return text(value);
  }

  return { ip, user, host, text, raw, ioc };
}

module.exports = { createPseudonymizer };
