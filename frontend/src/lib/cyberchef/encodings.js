import { utf8Encode, latin1Decode, latin1Encode, asText, concatBytes } from './bytes.js';
import { cyberchefError } from './errors.js';

const text = s => utf8Encode(s);
const hex2 = n => n.toString(16).padStart(2, '0');

export function toBase64(bytes) {
  return text(btoa(latin1Decode(bytes)));
}

export function fromBase64(bytes) {
  let s = asText(bytes).replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 === 1) throw cyberchefError('errors.base64_invalid');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  try {
    return latin1Encode(atob(s));
  } catch {
    throw cyberchefError('errors.base64_invalid');
  }
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function toBase32(bytes) {
  let bits = 0, val = 0, out = '';
  for (let i = 0; i < bytes.length; i++) {
    val = ((val << 8) | bytes[i]) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_CHARS[(val >> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32_CHARS[(val << (5 - bits)) & 31];
  return text(out + '='.repeat((8 - (out.length % 8)) % 8));
}

export function fromBase32(bytes) {
  const s = asText(bytes).trim().toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  let bits = 0, val = 0;
  const out = [];
  for (const ch of s) {
    const i = BASE32_CHARS.indexOf(ch);
    if (i < 0) throw cyberchefError('errors.base32_invalid', { char: ch });
    val = ((val << 5) | i) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((val >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function toBase58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
  return text(out);
}

export function fromBase58(bytes) {
  const s = asText(bytes).trim();
  let n = 0n;
  for (const ch of s) {
    const idx = B58.indexOf(ch);
    if (idx < 0) throw cyberchefError('errors.base58_invalid', { char: ch });
    n = n * 58n + BigInt(idx);
  }
  let hex = n === 0n ? '' : n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = new Uint8Array(hex.length / 2);
  for (let i = 0; i < body.length; i++) body[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const zeros = s.match(/^1*/)[0].length;
  return concatBytes([new Uint8Array(zeros), body]);
}

export function toHex(bytes, { sep = 'space' } = {}) {
  const parts = Array.from(bytes, b => {
    const h = hex2(b);
    return sep === 'backslash_x' ? `\\x${h}` : sep === 'prefix_0x' ? `0x${h}` : h;
  });
  return text(parts.join(sep === 'space' ? ' ' : ''));
}

export function fromHex(bytes) {
  let s = asText(bytes).trim().replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[,\s]+/g, '');
  if (!/^[0-9a-fA-F]+$/.test(s)) throw cyberchefError('errors.hex_invalid');
  if (s.length % 2) s = '0' + s;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBinary(bytes) {
  return text(Array.from(bytes, b => b.toString(2).padStart(8, '0')).join(' '));
}

export function fromBinary(bytes) {
  const chunks = asText(bytes).trim().replace(/\s+/g, ' ').split(' ');
  if (chunks.some(c => !/^[01]{8}$/.test(c))) throw cyberchefError('errors.binary_format_expected');
  return Uint8Array.from(chunks, c => parseInt(c, 2));
}

export function toUnicodeEscape(bytes) {
  return text(Array.from(asText(bytes), ch => {
    const cp = ch.codePointAt(0);
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, '0')}`;
  }).join(''));
}

export function fromUnicodeEscape(bytes) {
  return text(asText(bytes)
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, h) => {
      const cp = parseInt(h, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
}

export function urlEncode(bytes) {
  let out = '';
  for (const b of bytes) {
    const ch = String.fromCharCode(b);
    out += /[A-Za-z0-9\-_.~!*'()]/.test(ch) ? ch : `%${hex2(b).toUpperCase()}`;
  }
  return text(out);
}

export function urlDecode(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x2b) out.push(0x20);
    else if (b === 0x25 && i + 2 < bytes.length + 0 && /^[0-9a-fA-F]{2}$/.test(String.fromCharCode(bytes[i + 1], bytes[i + 2]))) {
      out.push(parseInt(String.fromCharCode(bytes[i + 1], bytes[i + 2]), 16));
      i += 2;
    } else out.push(b);
  }
  return Uint8Array.from(out);
}

const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

export function decodeHtmlEntities(bytes) {
  return text(asText(bytes).replace(/&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos|nbsp);/g, (m, body) => {
    if (body[0] !== '#') return NAMED_ENTITIES[body];
    const cp = body[1] === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
    return cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : m;
  }));
}

export function toHtmlEntity(bytes) {
  const named = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return text(Array.from(asText(bytes), ch => {
    if (named[ch]) return named[ch];
    const cp = ch.codePointAt(0);
    return cp > 0x7f ? `&#${cp};` : ch;
  }).join(''));
}

export function fromCharcode(bytes, { base = 'decimal' } = {}) {
  const radix = base === 'hex' ? 16 : base === 'octal' ? 8 : 10;
  const codes = asText(bytes).trim().split(/[\s,]+/).map(s => parseInt(s, radix));
  if (codes.some(c => Number.isNaN(c) || c < 0 || c > 0x10ffff)) throw cyberchefError('errors.invalid_charcodes');
  return text(codes.map(c => String.fromCodePoint(c)).join(''));
}

export function toCharcode(bytes, { base = 'decimal' } = {}) {
  const radix = base === 'hex' ? 16 : base === 'octal' ? 8 : 10;
  return text(Array.from(asText(bytes), ch => ch.codePointAt(0).toString(radix)).join(' '));
}

export function encodeUtf16le(bytes) {
  const s = asText(bytes);
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = code >> 8;
  }
  return out;
}

export function decodeUtf16le(bytes) {
  return text(new TextDecoder('utf-16le').decode(bytes));
}

const MORSE = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--',
  N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
  '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', _: '..--.-', '"': '.-..-.', '@': '.--.-.',
};
const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

export function toMorse(bytes) {
  return text(asText(bytes).toUpperCase().split('').map(c => (c === ' ' ? '/' : MORSE[c] || '')).filter(Boolean).join(' '));
}

export function fromMorse(bytes) {
  const words = asText(bytes).trim().split(/\s*\/\s*/);
  return text(words.map(w => w.split(/\s+/).filter(Boolean).map(code => MORSE_REV[code] ?? '').join('')).join(' '));
}

export function toQuotedPrintable(bytes) {
  let out = '';
  for (const c of bytes) {
    if ((c >= 33 && c <= 126 && c !== 61) || c === 32 || c === 9) out += String.fromCharCode(c);
    else out += `=${hex2(c).toUpperCase()}`;
  }
  return text(out);
}

export function fromQuotedPrintable(bytes) {
  const s = asText(bytes).replace(/=\r?\n/g, '');
  const chunks = [];
  let buffer = '';
  const flush = () => {
    if (buffer) chunks.push(text(buffer));
    buffer = '';
  };
  for (let i = 0; i < s.length; i++) {
    const m = s[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3));
    if (m) {
      flush();
      chunks.push(Uint8Array.of(parseInt(s.slice(i + 1, i + 3), 16)));
      i += 2;
    } else buffer += s[i];
  }
  flush();
  return concatBytes(chunks);
}

export function fromAscii85(bytes) {
  const s = asText(bytes).trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s/g, '');
  const out = [];
  let tuple = [];
  const emit = (group, count) => {
    let n = 0;
    for (const t of group) n = n * 85 + t;
    const b = [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
    out.push(...b.slice(0, count));
  };
  for (const ch of s) {
    if (ch === 'z' && tuple.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    const v = ch.charCodeAt(0) - 33;
    if (v < 0 || v > 84) throw cyberchefError('errors.ascii85_invalid', { char: ch });
    tuple.push(v);
    if (tuple.length === 5) {
      emit(tuple, 4);
      tuple = [];
    }
  }
  if (tuple.length === 1) throw cyberchefError('errors.ascii85_invalid', { char: '' });
  if (tuple.length) {
    const len = tuple.length;
    while (tuple.length < 5) tuple.push(84);
    emit(tuple, len - 1);
  }
  return Uint8Array.from(out);
}

export function fromOctal(bytes) {
  const s = asText(bytes).trim();
  if (/\\[0-7]{1,3}/.test(s)) {
    const chunks = [];
    let last = 0;
    for (const m of s.matchAll(/\\([0-7]{1,3})/g)) {
      if (m.index > last) chunks.push(text(s.slice(last, m.index)));
      const v = parseInt(m[1], 8);
      if (v > 255) throw cyberchefError('errors.octal_invalid');
      chunks.push(Uint8Array.of(v));
      last = m.index + m[0].length;
    }
    if (last < s.length) chunks.push(text(s.slice(last)));
    return concatBytes(chunks);
  }
  const parts = s.split(/[\s,]+/).filter(Boolean);
  if (!parts.length || parts.some(p => !/^[0-7]+$/.test(p) || parseInt(p, 8) > 255)) throw cyberchefError('errors.octal_invalid');
  return Uint8Array.from(parts, p => parseInt(p, 8));
}

export function fromHexdump(bytes) {
  const out = [];
  for (const rawLine of asText(bytes).split(/\r?\n/)) {
    let line = rawLine;
    const pipe = line.indexOf('|');
    if (pipe >= 0) line = line.slice(0, pipe);
    line = line.replace(/^\s*(?:[0-9a-fA-F]{4,}:|[0-9a-fA-F]{8}(?=\s|$))/, '');
    if (pipe < 0) line = line.trim().split(/\s{2,}/)[0];
    const compact = line.replace(/\s+/g, '');
    if (!compact || !/^(?:[0-9a-fA-F]{2})+$/.test(compact)) continue;
    for (let i = 0; i < compact.length; i += 2) out.push(parseInt(compact.slice(i, i + 2), 16));
  }
  if (!out.length) throw cyberchefError('errors.hexdump_empty');
  return Uint8Array.from(out);
}
