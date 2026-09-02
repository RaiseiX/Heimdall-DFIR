const MAX = 28;
const EXT = /\.(zip|tar\.gz|tgz|tar|7z|gz|e01|ad1|vhdx?)$/i;
const STAMP = /[_-]\d{4}[.-]?\d{2}[.-]?\d{2}([_-]\d{2}[.:]?\d{2}([.:]?\d{2})?)?$/;

export function collectionLabel(name) {
  let out = String(name ?? '').trim();
  if (!out) return '';
  out = out.replace(EXT, '');
  out = out.replace(STAMP, '');
  if (out.length > MAX) out = `${out.slice(0, MAX - 1)}…`;
  return out;
}
