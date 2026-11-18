import { shannonEntropy, isHighEntropy, utf8DecodeLossy } from './bytes.js';
import { decodeQuality } from './quality.js';
import { OPS, defaultParams } from './registry.js';

const STRUCTURAL = new Set(['refangIoc', 'decimalToIp', 'jwtDecode']);

function runSync(opIds, start) {
  let out = start;
  for (const id of opIds) {
    const op = OPS[id];
    if (!op || op.async) return null;
    out = op.fn(out, defaultParams(op));
  }
  return out;
}

function sameBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function detectObfuscation(input) {
  if (!input || input.length < 4) return [];
  const s = utf8DecodeLossy(input).trim();
  if (s.length < 4 && !(input[0] === 0x1f && input[1] === 0x8b)) return [];
  const b64 = s.replace(/\s/g, '');
  const cand = [];

  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$/.test(s))
    cand.push({ ops: ['jwtDecode'], labelKey: 'detect.jwt', color: 'var(--fl-danger)', base: 96 });
  if (/hxxps?|\[\.\]|\[:\/\/\]|\[@\]|\(dot\)|\(at\)/i.test(s))
    cand.push({ ops: ['refangIoc'], labelKey: 'detect.defanged_ioc', color: 'var(--fl-ok)', base: 92 });
  if (/#@~\^.{6}==[\s\S]+==\^#~@/.test(s))
    cand.push({ ops: ['jscriptDecode'], labelKey: 'detect.ms_script', color: 'var(--fl-danger)', base: 97 });

  if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(b64)) {
    const decoded = (() => {
      try { return OPS.fromBase64.fn(input, {}); } catch { return null; }
    })();
    if (decoded) {
      const isUtf16 = decoded.length >= 4 && decoded[1] === 0 && decoded[3] === 0;
      if (isUtf16) cand.push({ ops: ['psCommandDecode'], labelKey: 'detect.powershell', color: 'var(--fl-danger)', base: 95 });
      else cand.push({ ops: ['fromBase64'], labelKey: /[-_]/.test(b64) ? 'detect.base64_url' : 'detect.base64', color: 'var(--fl-warn)', base: 80 });
    }
  }
  if (/^[A-Z2-7]+=*$/.test(b64) && b64.length >= 8) cand.push({ ops: ['fromBase32'], labelKey: 'detect.base32', color: 'var(--fl-accent)', base: 70 });
  if (/^[1-9A-HJ-NP-Za-km-z]{16,}$/.test(b64)) cand.push({ ops: ['fromBase58'], labelKey: 'detect.base58', color: 'var(--fl-purple)', base: 60 });

  if (/(?:\\x[0-9a-fA-F]{2}){3,}/.test(s)) cand.push({ ops: ['fromHex'], labelKey: 'detect.hex_escapes', color: 'var(--fl-gold)', base: 90 });
  const hexOnly = s.replace(/[\s,]/g, '');
  if (/^[0-9a-fA-F]+$/.test(hexOnly) && hexOnly.length % 2 === 0 && hexOnly.length >= 10) cand.push({ ops: ['fromHex'], labelKey: 'detect.hex_plain', color: 'var(--fl-purple)', base: 66 });
  if (/\\u[0-9a-fA-F]{4}/.test(s)) cand.push({ ops: ['fromUnicodeEscape'], labelKey: 'detect.unicode_escape', color: 'var(--fl-accent)', base: 84 });

  const urlCount = (s.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (urlCount > 2 || (urlCount > 0 && urlCount / s.length > 0.05)) cand.push({ ops: ['urlDecode'], labelKey: 'detect.url_encoded', color: 'var(--fl-accent)', base: 85 });
  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(s)) cand.push({ ops: ['fromHtmlEntity'], labelKey: 'detect.html_entities', color: 'var(--fl-purple)', base: 85 });
  if (/^\d+(?:\s*[,\s]\s*\d+){5,}$/.test(s)) cand.push({ ops: ['fromCharcode'], labelKey: 'detect.char_codes', color: 'var(--fl-ok)', base: 76 });
  if (/^[01]{8}(?:\s[01]{8})+$/.test(s)) cand.push({ ops: ['fromBinary'], labelKey: 'detect.binary_8bit', color: 'var(--fl-gold)', base: 90 });
  if (/^[.\-]+(?:\s*\/?\s*[.\-]+)+$/.test(s) && /[ /]/.test(s)) cand.push({ ops: ['fromMorse'], labelKey: 'detect.morse', color: 'var(--fl-gold)', base: 88 });
  if ((s.match(/=[0-9A-F]{2}/g) || []).length > 1) cand.push({ ops: ['fromQuotedPrintable'], labelKey: 'detect.quoted_printable', color: 'var(--fl-accent)', base: 70 });
  if (/^<~/.test(s) || /[!-u]{20,}~>$/.test(s)) cand.push({ ops: ['fromBase85'], labelKey: 'detect.ascii85', color: 'var(--fl-accent)', base: 72 });
  if (/(?:\\[0-7]{2,3}){3,}/.test(s)) cand.push({ ops: ['fromOctal'], labelKey: 'detect.octal_escapes', color: 'var(--fl-gold)', base: 80 });

  if (input[0] === 0x1f && input[1] === 0x8b) cand.push({ ops: ['gunzip'], labelKey: 'detect.gzip', color: 'var(--fl-danger)', base: 88 });
  if (input[0] === 0x78 && [0x01, 0x9c, 0xda].includes(input[1])) cand.push({ ops: ['zlibInflate'], labelKey: 'detect.zlib', color: 'var(--fl-purple)', base: 82 });
  if (/^\d{8,10}$/.test(s) && Number(s) >= 16777216 && Number(s) <= 4294967295) cand.push({ ops: ['decimalToIp'], labelKey: 'detect.decimal_ip', color: 'var(--fl-ok)', base: 50 });

  const results = [];
  for (const c of cand) {
    let out = null;
    try { out = runSync(c.ops, input); } catch { out = null; }
    let conf;
    if (out && out.length && !sameBytes(out, input)) {
      const q = decodeQuality(out);
      conf = Math.round(c.base * 0.4 + q * 0.6);
      if (q < 28 && !STRUCTURAL.has(c.ops[0])) conf = Math.round(conf * 0.45);
    } else {
      conf = Math.round(c.base * 0.5);
    }
    results.push({ confidence: Math.max(1, Math.min(99, conf)), ops: c.ops, labelKey: c.labelKey, color: c.color });
  }

  if (isHighEntropy(input) && results.every(r => r.confidence < 50)) {
    results.push({ confidence: 45, ops: ['extractStrings'], labelKey: 'detect.high_entropy', labelParams: { entropy: shannonEntropy(input).toFixed(2) }, color: 'var(--fl-dim)' });
  }

  const seen = new Map();
  for (const r of results.sort((a, b) => b.confidence - a.confidence)) {
    const key = r.ops.join('>');
    if (!seen.has(key)) seen.set(key, r);
  }
  return [...seen.values()].sort((a, b) => b.confidence - a.confidence);
}

export function magicChain(input) {
  const chain = [];
  const seen = [input];
  let cur = input;
  for (let depth = 0; depth < 6; depth++) {
    const best = detectObfuscation(cur)[0];
    if (!best || best.confidence < 60 || !best.ops.length) break;
    let out;
    try { out = runSync(best.ops, cur); } catch { break; }
    if (!out || !out.length || seen.some(prev => sameBytes(prev, out))) break;
    seen.push(out);
    chain.push(...best.ops);
    cur = out;
  }
  return chain;
}
