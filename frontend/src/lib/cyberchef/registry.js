import { utf8Encode, asText, shannonEntropy, isHighEntropy } from './bytes.js';
import { cyberchefError, tr } from './errors.js';
import {
  fromBase64, toBase64, fromBase32, toBase32, fromBase58, toBase58, fromHex, toHex, fromBinary, toBinary,
  fromUnicodeEscape, toUnicodeEscape, urlDecode, urlEncode, decodeHtmlEntities, toHtmlEntity, fromCharcode, toCharcode,
  decodeUtf16le, encodeUtf16le, fromMorse, toMorse, fromQuotedPrintable, toQuotedPrintable, fromAscii85, fromOctal, fromHexdump,
} from './encodings.js';
import { md5, ntlm, crc32, sha } from './hashes.js';
import {
  rot, rot47, atbash, vigenere, xorSingle, xorMultibyte, rc4, aesDecrypt, caesarBrute, xorBruteForce,
} from './ciphers.js';
import { decompress } from './compress.js';
import {
  extractIpv4, extractIpv6, extractUrls, extractEmails, extractDomains, extractHashes, extractStrings, defangIoc, refangIoc,
} from './extract.js';
import { filetimeToDate, unixToDate, dateToUnix, dateToFiletime } from './timestamps.js';
import {
  jwtDecode, ipToDecimal, decimalToIp, prettifyJson, minifyJson, prettifyXml, psCommandEncode, psCommandDecode, decodeMsScript,
} from './formats.js';

const text = s => utf8Encode(s);
const textOp = fn => bytes => text(fn(asText(bytes)));
const listOrNone = (list, noneKey) => text(list.length ? list.join('\n') : tr(noneKey));
const defaultsOf = op => Object.fromEntries((op.params || []).map(p => [p.id, p.default]));

const opt = (value, labelKey) => ({ value, labelKey });
const literalOpt = (value, label = value) => ({ value, label });
const radixOptions = () => [opt('decimal', 'options.decimal'), opt('hex', 'options.hex'), opt('octal', 'options.octal')];

const DEFINITIONS = [
  ['psCommandDecode', 'specialized', { label: 'PowerShell -EncodedCommand', fn: psCommandDecode }],
  ['fromBase64', 'encoding', { fn: fromBase64 }],
  ['toBase64', 'encoding', { fn: toBase64 }],
  ['fromBase32', 'encoding', { fn: fromBase32 }],
  ['toBase32', 'encoding', { fn: toBase32 }],
  ['fromBase58', 'encoding', { fn: fromBase58 }],
  ['fromHex', 'encoding', { fn: fromHex }],
  ['toHex', 'encoding', {
    params: [{ id: 'sep', labelKey: 'param_sep', type: 'select', default: 'space', options: [
      opt('space', 'options.space'), opt('none', 'options.none'), literalOpt('backslash_x', '\\x'), literalOpt('prefix_0x', '0x'),
    ] }],
    fn: toHex,
  }],
  ['fromBinary', 'encoding', { fn: fromBinary }],
  ['toBinary', 'encoding', { fn: toBinary }],
  ['fromUnicodeEscape', 'encoding', { fn: fromUnicodeEscape }],
  ['toUnicodeEscape', 'encoding', { fn: toUnicodeEscape }],
  ['urlDecode', 'encoding', { fn: urlDecode }],
  ['urlEncode', 'encoding', { fn: urlEncode }],
  ['fromHtmlEntity', 'encoding', { fn: decodeHtmlEntities }],
  ['fromCharcode', 'encoding', { params: [{ id: 'base', labelKey: 'param_base', type: 'select', default: 'decimal', options: radixOptions() }], fn: fromCharcode }],
  ['decodeUtf16le', 'encoding', { fn: decodeUtf16le }],
  ['md5Hash', 'hash', { label: 'MD5', fn: bytes => text(md5(bytes)) }],
  ['sha1Hash', 'hash', { label: 'SHA-1', async: true, fn: async bytes => text(await sha('SHA-1', bytes)) }],
  ['sha256Hash', 'hash', { label: 'SHA-256', async: true, fn: async bytes => text(await sha('SHA-256', bytes)) }],
  ['sha512Hash', 'hash', { label: 'SHA-512', async: true, fn: async bytes => text(await sha('SHA-512', bytes)) }],
  ['ntlmHash', 'hash', { label: 'NTLM (MD4)', fn: bytes => text(ntlm(bytes)) }],
  ['rot13', 'cipher', { params: [{ id: 'amount', labelKey: 'param_amount', type: 'number', default: 13, min: 1, max: 25 }], fn: rot }],
  ['atbash', 'cipher', { label: 'Atbash', fn: atbash }],
  ['vigenereDecode', 'cipher', { params: [{ id: 'key', labelKey: 'param_key', type: 'text', default: 'SECRET' }], fn: (b, p) => vigenere(b, p, true) }],
  ['vigenereEncode', 'cipher', { params: [{ id: 'key', labelKey: 'param_key', type: 'text', default: 'SECRET' }], fn: (b, p) => vigenere(b, p, false) }],
  ['xorDecode', 'cipher', { params: [{ id: 'key', labelKey: 'param_key', type: 'text', default: '0x41' }], fn: xorSingle }],
  ['xorMultibyte', 'cipher', { params: [{ id: 'key', labelKey: 'param_key', type: 'text', default: 'deadbeef' }], fn: xorMultibyte }],
  ['rc4Decode', 'cipher', { label: 'RC4', params: [{ id: 'key', labelKey: 'param_key', type: 'text', default: 'secret' }], fn: rc4 }],
  ['reverseString', 'formatting', {
    params: [{ id: 'by', labelKey: 'param_by', type: 'select', default: 'char', options: [opt('char', 'options.char'), opt('line', 'options.line'), opt('word', 'options.word')] }],
    fn: (bytes, { by = 'char' } = {}) => text(by === 'line' ? asText(bytes).split('\n').reverse().join('\n') : by === 'word' ? asText(bytes).split(/\s+/).reverse().join(' ') : [...asText(bytes)].reverse().join('')),
  }],
  ['stripNulls', 'formatting', { fn: bytes => bytes.filter(b => b !== 0) }],
  ['jsonPrettify', 'formatting', { label: 'JSON Prettify', fn: prettifyJson }],
  ['jsonMinify', 'formatting', { label: 'JSON Minify', fn: minifyJson }],
  ['xmlPrettify', 'formatting', { label: 'XML Prettify', fn: prettifyXml }],
  ['toUpper', 'formatting', { fn: textOp(s => s.toUpperCase()) }],
  ['toLower', 'formatting', { fn: textOp(s => s.toLowerCase()) }],
  ['sortLines', 'formatting', {
    params: [{ id: 'order', labelKey: 'param_order', type: 'select', default: 'asc', options: [opt('asc', 'options.asc'), opt('desc', 'options.desc')] }],
    fn: (bytes, { order = 'asc' } = {}) => {
      const lines = asText(bytes).split('\n').sort();
      return text((order === 'desc' ? lines.reverse() : lines).join('\n'));
    },
  }],
  ['removeDuplicates', 'formatting', { fn: textOp(s => [...new Set(s.split('\n'))].join('\n')) }],
  ['removeBlankLines', 'formatting', { fn: textOp(s => s.split('\n').filter(l => l.trim()).join('\n')) }],
  ['extractStrings', 'extraction', {
    params: [{ id: 'minLen', labelKey: 'param_min_len', type: 'number', default: 4, min: 1, max: 100 }],
    fn: (bytes, { minLen = 4 } = {}) => {
      const { ascii, utf16le } = extractStrings(bytes, minLen);
      if (!ascii.length && !utf16le.length) return text(tr('outputs.none_string'));
      const sections = [];
      if (ascii.length) sections.push(`ASCII (${ascii.length}):\n${ascii.join('\n')}`);
      if (utf16le.length) sections.push(`UTF-16LE (${utf16le.length}):\n${utf16le.join('\n')}`);
      return text(sections.join('\n\n'));
    },
  }],
  ['extractUrls', 'extraction', { fn: bytes => listOrNone(extractUrls(asText(bytes)), 'outputs.none_url') }],
  ['extractIps', 'extraction', {
    fn: bytes => {
      const s = asText(bytes);
      return listOrNone([...extractIpv4(s), ...extractIpv6(s)], 'outputs.none_ip');
    },
  }],
  ['extractEmails', 'extraction', { fn: bytes => listOrNone(extractEmails(asText(bytes)), 'outputs.none_email') }],
  ['extractDomains', 'extraction', { fn: bytes => listOrNone(extractDomains(asText(bytes)), 'outputs.none_domain') }],
  ['extractHashes', 'extraction', {
    fn: bytes => {
      const found = extractHashes(asText(bytes));
      const names = { md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
      const sections = Object.entries(names).filter(([k]) => found[k].length).map(([k, name]) => `${name} (${found[k].length}):\n${found[k].join('\n')}`);
      return text(sections.length ? sections.join('\n\n') : tr('outputs.none_hash'));
    },
  }],
  ['extractWinPaths', 'extraction', {
    fn: bytes => listOrNone([...new Set(asText(bytes).match(/(?:[A-Za-z]:\\|\\\\)[^\s"'<>|*?\x00-\x1f]+/g) || [])], 'outputs.none_windows_path'),
  }],
  ['extractLinuxPaths', 'extraction', {
    fn: bytes => listOrNone([...new Set(asText(bytes).match(/(?:\/(?:etc|tmp|var|home|usr|opt|proc|sys|dev|run|lib|bin|sbin|boot|root|srv)(?:\/[^\s"'<>|*?\x00-\x1f]*)?)/g) || [])], 'outputs.none_linux_path'),
  }],
  ['extractGuids', 'extraction', {
    fn: bytes => listOrNone([...new Set(asText(bytes).match(/\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?/g) || [])], 'outputs.none_guid'),
  }],
  ['regexExtract', 'extraction', {
    params: [
      { id: 'pattern', labelKey: 'param_pattern', type: 'text', default: '[A-Za-z0-9+/=]{20,}' },
      { id: 'flags', labelKey: 'param_flags', type: 'text', default: 'g' },
    ],
    fn: (bytes, { pattern = '[A-Za-z0-9+/=]{20,}', flags = 'g' } = {}) => {
      let re;
      try {
        re = new RegExp(pattern, flags);
      } catch (e) {
        throw cyberchefError('errors.regex_invalid', { detail: e.message });
      }
      return listOrNone(asText(bytes).match(re) || [], 'outputs.none_result');
    },
  }],
  ['filetimeConvert', 'timestamps', { fn: filetimeToDate }],
  ['unixConvert', 'timestamps', { fn: unixToDate }],
  ['dateToUnix', 'timestamps', { fn: dateToUnix }],
  ['countChars', 'info', {
    fn: bytes => {
      const e = shannonEntropy(bytes);
      const printable = bytes.reduce((n, b) => n + (b >= 0x20 && b <= 0x7e ? 1 : 0), 0);
      const freq = new Map();
      for (const b of bytes) freq.set(b, (freq.get(b) || 0) + 1);
      const top = [...freq.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, 5)
        .map(([b, n]) => `\\x${b.toString(16).padStart(2, '0')}x${n}`).join('  ');
      return text([
        `${tr('output_length')} : ${tr('output_bytes_count', { count: bytes.length })}`,
        `${tr('output_entropy')} : ${tr('output_bits_per_byte', { value: e.toFixed(4) })}${isHighEntropy(bytes) ? `  ${tr('output_high')}` : ''}`,
        `${tr('output_printable')} : ${printable}/${bytes.length} (${((printable / Math.max(bytes.length, 1)) * 100).toFixed(1)}%)`,
        `${tr('output_top_bytes')} : ${top}`,
      ].join('\n'));
    },
  }],
  ['defangIoc', 'network', { fn: textOp(defangIoc) }],
  ['refangIoc', 'network', { fn: textOp(refangIoc) }],
  ['ipToDecimal', 'network', { fn: ipToDecimal }],
  ['decimalToIp', 'network', { fn: decimalToIp }],
  ['jwtDecode', 'specialized', { label: 'JWT Decode', fn: jwtDecode }],
  ['rot47', 'cipher', { label: 'ROT47', fn: rot47 }],
  ['crc32Hash', 'hash', { label: 'CRC32', fn: bytes => text(crc32(bytes)) }],
  ['toBase58', 'encoding', { fn: toBase58 }],
  ['toCharcode', 'encoding', { params: [{ id: 'base', labelKey: 'param_base', type: 'select', default: 'decimal', options: radixOptions() }], fn: toCharcode }],
  ['toHtmlEntity', 'encoding', { fn: toHtmlEntity }],
  ['encodeUtf16le', 'encoding', { fn: encodeUtf16le }],
  ['fromMorse', 'encoding', { fn: fromMorse }],
  ['toMorse', 'encoding', { fn: toMorse }],
  ['fromQuotedPrintable', 'encoding', { fn: fromQuotedPrintable }],
  ['toQuotedPrintable', 'encoding', { fn: toQuotedPrintable }],
  ['psCommandEncode', 'specialized', { label: 'PowerShell → EncodedCommand', fn: psCommandEncode }],
  ['dateToFiletime', 'timestamps', { fn: dateToFiletime }],
  ['gunzip', 'encoding', { label: 'Gunzip', async: true, fn: bytes => decompress(bytes, 'gzip') }],
  ['rawInflate', 'encoding', { label: 'Raw Inflate (DEFLATE)', async: true, fn: bytes => decompress(bytes, 'deflate-raw') }],
  ['zlibInflate', 'encoding', { label: 'Zlib Inflate', async: true, fn: bytes => decompress(bytes, 'deflate') }],
  ['aesDecrypt', 'cipher', {
    label: 'AES Decrypt',
    async: true,
    params: [
      { id: 'key', labelKey: 'param_key', type: 'text', default: '' },
      { id: 'iv', labelKey: 'param_iv', type: 'text', default: '' },
      { id: 'mode', label: 'Mode', type: 'select', default: 'CBC', options: [literalOpt('CBC'), literalOpt('GCM'), literalOpt('CTR')] },
      { id: 'inputFormat', labelKey: 'param_input_format', type: 'select', default: 'base64', options: [literalOpt('base64', 'Base64'), literalOpt('hex', 'Hex')] },
    ],
    fn: aesDecrypt,
  }],
  ['xorBruteForce', 'cipher', { fn: xorBruteForce }],
  ['caesarBruteForce', 'cipher', { label: 'Caesar Brute-Force', fn: caesarBrute }],
  ['fromBase85', 'encoding', { fn: fromAscii85 }],
  ['fromOctal', 'encoding', { fn: fromOctal }],
  ['fromHexdump', 'encoding', { fn: fromHexdump }],
  ['jscriptDecode', 'specialized', { label: 'JScript.Encode / VBE Decode', fn: decodeMsScript }],
];

export const OPS = Object.fromEntries(DEFINITIONS.map(([id, category, def]) => [id, {
  id,
  category,
  label: def.label,
  labelKey: def.label ? undefined : `ops.${id}.label`,
  descKey: `ops.${id}.desc`,
  params: (def.params || []).map(p => ({ ...p, labelKey: p.labelKey ? `ops.${id}.${p.labelKey}` : undefined })),
  async: Boolean(def.async),
  fn: def.fn,
}]));

export const CATEGORIES = ['specialized', 'encoding', 'hash', 'cipher', 'network', 'extraction', 'timestamps', 'formatting', 'info'];

export const opLabel = op => op.label ?? tr(op.labelKey);
export const opDescription = op => tr(op.descKey);
export const categoryLabel = category => tr(`categories.${category}`);
export const paramLabel = param => param.label ?? tr(param.labelKey);
export const optionLabel = option => option.label ?? tr(option.labelKey);
export const defaultParams = op => defaultsOf(op);

export function matchesSearch(op, query) {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [opLabel(op), opDescription(op), categoryLabel(op.category), op.id].some(v => v.toLowerCase().includes(q));
}

export async function runOp(op, bytes, params) {
  const out = op.fn(bytes, params || {});
  return op.async ? await out : out;
}

export async function applyRecipe(input, recipe) {
  let current = input;
  const steps = [];
  for (const step of recipe) {
    const op = OPS[step.opId];
    if (!op) {
      steps.push({ opId: step.opId, output: current, error: tr('errors.unknown_operation') });
      continue;
    }
    try {
      const out = await runOp(op, current, step.params);
      steps.push({ opId: step.opId, output: out, error: null });
      current = out;
    } catch (e) {
      steps.push({ opId: step.opId, output: current, error: e?.message || String(e) });
      break;
    }
  }
  return { final: current, steps };
}
