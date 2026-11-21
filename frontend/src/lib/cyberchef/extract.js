const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'ps1', 'psm1', 'txt', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'jar', 'sys', 'log', 'ini', 'doc', 'docx', 'docm',
  'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg', 'zip', 'rar', 'tmp', 'dat', 'bin',
  'lnk', 'msi', 'py', 'sh', 'md', 'json', 'xml', 'csv', 'html', 'htm', 'css', 'tar', 'gz', 'tgz', 'iso', 'dmp', 'evtx', 'reg',
  'cfg', 'conf', 'yml', 'yaml', 'php', 'asp', 'aspx', 'jsp', 'class', 'cab', 'dmg', 'img', 'mp3', 'mp4', 'avi', 'wav', 'ttf',
]);

const DOMAIN_RE = /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])/gi;
const IPV4_RE = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)/g;
const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>]+/gi;
const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}/g;
const TRAILING_PUNCT = /[.,;:)\]]+$/;

function unique(list) {
  return [...new Set(list)];
}

export function isValidIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

export function isValidIpv6(value) {
  if (!/^[0-9a-fA-F:]+$/.test(value) || value.includes(':::')) return false;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const groups = h => (h === '' ? [] : h.split(':'));
  const left = groups(halves[0]);
  const right = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...left, ...right];
  if (!all.every(g => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  if (halves.length === 1) return left.length === 8;
  return all.length <= 7 && value !== '::';
}

export function isDomainCandidate(value) {
  const tld = value.slice(value.lastIndexOf('.') + 1).toLowerCase();
  return !FILE_EXTENSIONS.has(tld);
}

export function extractIpv4(text) {
  return unique((text.match(IPV4_RE) || []).filter(isValidIpv4));
}

export function extractIpv6(text) {
  const candidates = text.match(/(?<![0-9a-zA-Z:])[0-9a-fA-F:]{2,39}(?![0-9a-zA-Z:])/g) || [];
  return unique(candidates.filter(c => c.includes(':') && isValidIpv6(c)));
}

export function extractDomains(text) {
  return unique((text.match(DOMAIN_RE) || []).filter(isDomainCandidate));
}

export function extractUrls(text) {
  return unique((text.match(URL_RE) || []).map(u => u.replace(TRAILING_PUNCT, '')).filter(u => /:\/\/./.test(u)));
}

export function extractEmails(text) {
  return unique(text.match(EMAIL_RE) || []).map(e => e.replace(/\.+$/, ''));
}

export function extractHashes(text) {
  const grab = n => unique(text.match(new RegExp(`(?<![0-9a-fA-F])[0-9a-fA-F]{${n}}(?![0-9a-fA-F])`, 'g')) || []);
  return { md5: grab(32), sha1: grab(40), sha256: grab(64), sha512: grab(128) };
}

export function extractStrings(bytes, minLen = 4) {
  const min = Math.max(1, Math.floor(Number(minLen)) || 1);
  const ascii = [];
  let run = '';
  for (let i = 0; i <= bytes.length; i++) {
    const b = i < bytes.length ? bytes[i] : -1;
    if (b >= 0x20 && b <= 0x7e) run += String.fromCharCode(b);
    else {
      if (run.length >= min) ascii.push(run);
      run = '';
    }
  }
  const utf16le = [];
  let wide = '';
  let i = 0;
  while (i <= bytes.length) {
    const lo = i < bytes.length ? bytes[i] : -1;
    const hi = i + 1 < bytes.length ? bytes[i + 1] : -1;
    if (lo >= 0x20 && lo <= 0x7e && hi === 0) {
      wide += String.fromCharCode(lo);
      i += 2;
    } else {
      if (wide.length >= min) utf16le.push(wide);
      wide = '';
      i += 1;
    }
  }
  return { ascii, utf16le };
}

function defangHost(host) {
  return host.replace(/\./g, '[.]');
}

function defangUrl(url) {
  const m = /^([a-z]+):\/\/([^/?#:]*)(.*)$/i.exec(url);
  if (!m) return url;
  const scheme = m[1].replace(/^http/i, 'hxxp');
  return `${scheme}[://]${defangHost(m[2])}${m[3]}`;
}

const DEFANG_RE = new RegExp(
  `(?<url>\\b(?:https?|ftp):\\/\\/[^\\s"'<>]+)|(?<email>${EMAIL_RE.source})|(?<ip>${IPV4_RE.source})|(?<dom>${DOMAIN_RE.source})`,
  'gi',
);

export function defangIoc(text) {
  return text.replace(DEFANG_RE, (match, ...args) => {
    const groups = args[args.length - 1];
    if (groups.url) {
      const trailing = match.match(TRAILING_PUNCT)?.[0] || '';
      return defangUrl(match.slice(0, match.length - trailing.length)) + trailing;
    }
    if (groups.email) {
      const at = match.lastIndexOf('@');
      return `${match.slice(0, at)}[@]${defangHost(match.slice(at + 1))}`;
    }
    if (groups.ip) return isValidIpv4(match) ? defangHost(match) : match;
    if (groups.dom) return isDomainCandidate(match) ? defangHost(match) : match;
    return match;
  });
}

export function refangIoc(text) {
  return text
    .replace(/\[\.\]|\(\.\)|\(dot\)|\[dot\]/gi, '.')
    .replace(/\[@\]|\(at\)|\[at\]/gi, '@')
    .replace(/\[:\/\/\]|\[:\]/g, '://')
    .replace(/\bhxxp(s?)(?=:)/gi, 'http$1');
}

