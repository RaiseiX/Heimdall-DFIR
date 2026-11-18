import { utf8DecodeLossy, shannonEntropy } from './bytes.js';

const QUALITY_KEYWORDS = /\b(https?|www|cmd|powershell|invoke|iex|function|select|insert|update|user|password|admin|token|true|false|null|var|const|return|the|and|for|with|system|windows|microsoft|program|file|path|script|host|error|enable|disable)\b/gi;

export function decodeQuality(bytes) {
  if (!bytes || !bytes.length) return 0;
  const s = utf8DecodeLossy(bytes);
  if (!s.length) return 0;
  const good = (s.match(/[\t\n\r\x20-\x7e -￼]/g) || []).length;
  const printable = good / s.length;
  const keywords = (s.match(QUALITY_KEYWORDS) || []).length;
  let q = printable * 68;
  q += Math.min(keywords, 6) * 4.5;
  if (shannonEntropy(bytes) < 4.5) q += 6;
  if (printable < 0.7) q *= 0.5;
  return Math.max(0, Math.min(100, q));
}
