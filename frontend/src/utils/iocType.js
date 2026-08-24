// ── IOC type auto-detection — single source of truth ─────────────────────────
// Every "add IOC" button (DetailPanel header, Details/Schema tabs, parsed data,
// collection artifacts, detections) used to ship its own copy of this logic,
// which drifted: the domain regex matched bare executables like wctBB855.exe
// (".exe" looked like a TLD), and DetectionsTab emitted 'sha256'/'md5' which
// are not valid values of the DB ioc_type enum ('hash_sha256', 'hash_md5'…).
//
// Order matters. File-ish values (paths, bare names with a known file
// extension, registry keys) are checked BEFORE domains so a binary is never
// classified as a domain. The DB enum is:
//   ip, domain, url, hash_md5, hash_sha1, hash_sha256, filename,
//   registry_key, mutex, user_agent, email, other

const RE = {
  // Each octet validated 0-255 (999.1.1.1 is not an IP).
  ip:        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
  md5:       /^[a-f0-9]{32}$/i,
  sha1:      /^[a-f0-9]{40}$/i,
  sha256:    /^[a-f0-9]{64}$/i,
  url:       /^https?:\/\//i,
  email:     /^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/,
  winPath:   /^[a-zA-Z]:\\[^*?"<>|]+$/,
  posixPath: /^\/[^\0]+$/,
  registry:  /^(HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)(\\[^*?"<>|]+)+$/i,
  // Domain: label(.label)+.tld — tld is letters only. A leading dot, trailing
  // dot or a file extension are excluded by the checks that run before it.
  domain:    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,
  // Bare file name with a known extension, e.g. wctBB855.exe, cron.service,
  // report.pdf — matched AFTER paths/registry but BEFORE domains.
  fileExt:   /^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]{1,8}$/,
  // Bare executable/unit names without extension: thermald, sshd, curl, cron…
  name:      /^[a-z_][a-z0-9_-]{0,63}$/i,
};

// Known file extensions — used to decide "filename" before "domain" so an
// .exe/.dll/.service value is never mistaken for a domain. Keep it broad
// (forensic values come from any OS).
// Note: 'com' is intentionally NOT in the list — as an IOC it is almost always
// a .com domain (evil.com), not a legacy DOS executable.
const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bat', 'cmd', 'scr', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'msi', 'msp',
  'sh', 'bash', 'zsh', 'py', 'pl', 'rb', 'php', 'asp', 'aspx', 'jsp', 'jar', 'war', 'class',
  'json', 'xml', 'yml', 'yaml', 'toml', 'ini', 'conf', 'cfg', 'cnf', 'log', 'txt', 'md',
  'csv', 'tsv', 'dat', 'db', 'sqlite', 'sql', 'db3',
  'service', 'socket', 'timer', 'target', 'mount', 'swap', 'device', 'automount', 'path', 'slice', 'scope', 'network', 'netdev',
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img', 'dmp', 'bin', 'raw', 'dump',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'bmp', 'ico', 'webp', 'tiff',
  'wav', 'mp3', 'mp4', 'avi', 'mkv', 'mov', 'flv',
  'evtx', 'hive', 'lnk', 'pcap', 'pcapng', 'cap', 'vmdk', 'vhd', 'vhdx', 'mem',
]);

function isKnownFileExt(s) {
  const i = s.lastIndexOf('.');
  if (i < 0 || i === s.length - 1) return false;
  return FILE_EXTENSIONS.has(s.slice(i + 1).toLowerCase());
}

// Returns { type, label } where type is a valid ioc_type enum value.
// Fallback is 'other' so every non-trivial value keeps a button.
export function detectIocType(value) {
  const s = String(value ?? '').trim();
  if (!s || s === '—' || s.length < 2 || s.length > 512) return { type: 'other', label: 'Value' };

  if (RE.ip.test(s))            return { type: 'ip',         label: 'IP' };
  if (RE.md5.test(s))           return { type: 'hash_md5',   label: 'MD5' };
  if (RE.sha1.test(s))          return { type: 'hash_sha1',  label: 'SHA1' };
  if (RE.sha256.test(s))        return { type: 'hash_sha256', label: 'SHA256' };
  if (RE.url.test(s))           return { type: 'url',        label: 'URL' };
  if (RE.email.test(s))         return { type: 'email',      label: 'Email' };
  if (RE.winPath.test(s) || RE.posixPath.test(s)) return { type: 'filename', label: 'Path' };
  if (RE.registry.test(s))      return { type: 'registry_key', label: 'Registry' };
  if (RE.fileExt.test(s) && isKnownFileExt(s)) return { type: 'filename', label: 'File' };
  if (RE.domain.test(s))        return { type: 'domain',     label: 'Domain' };
  if (RE.name.test(s))          return { type: 'other',      label: 'Name' };
  return { type: 'other', label: 'Value' };
}

export default detectIocType;
