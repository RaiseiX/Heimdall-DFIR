import { utf8Encode, asText, utf8DecodeLossy } from './bytes.js';
import { cyberchefError, tr } from './errors.js';
import { fromBase64, fromHex } from './encodings.js';
import { decodeQuality } from './quality.js';

const text = s => utf8Encode(s);

export function parseHexKey(value) {
  const k = String(value ?? '').replace(/0x|\\x|\s/gi, '');
  if (!k || !/^[0-9a-fA-F]+$/.test(k) || k.length % 2 !== 0) return null;
  return Uint8Array.from({ length: k.length / 2 }, (_, i) => parseInt(k.slice(i * 2, i * 2 + 2), 16));
}

export function xorBytes(bytes, keyBytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
  return out;
}

export function xorSingle(bytes, { key = '0x41' } = {}) {
  const k = parseHexKey(key);
  if (!k || k.length !== 1) throw cyberchefError('errors.invalid_key_single_byte');
  return xorBytes(bytes, k);
}

export function xorMultibyte(bytes, { key = 'deadbeef' } = {}) {
  const k = parseHexKey(key);
  if (!k) throw cyberchefError('errors.invalid_hex_key');
  return xorBytes(bytes, k);
}

export function rc4(bytes, { key = 'secret' } = {}) {
  const keyBytes = text(String(key ?? ''));
  if (!keyBytes.length) throw cyberchefError('errors.empty_key');
  const S = Uint8Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + keyBytes[i % keyBytes.length]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(bytes.length);
  let a = 0;
  j = 0;
  for (let n = 0; n < bytes.length; n++) {
    a = (a + 1) & 255;
    j = (j + S[a]) & 255;
    [S[a], S[j]] = [S[j], S[a]];
    out[n] = bytes[n] ^ S[(S[a] + S[j]) & 255];
  }
  return out;
}

export function rot(bytes, { amount = 13 } = {}) {
  const n = Number(amount);
  return text(asText(bytes).replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((((c.charCodeAt(0) - base + n) % 26) + 26) % 26 + base);
  }));
}

export function rot47(bytes) {
  return text(asText(bytes).replace(/[\x21-\x7e]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94))));
}

export function atbash(bytes) {
  return text(asText(bytes).replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base));
  }));
}

export function vigenere(bytes, { key = 'SECRET' } = {}, decode = false) {
  if (!key) throw cyberchefError('errors.empty_key');
  const k = String(key).toUpperCase().replace(/[^A-Z]/g, '');
  if (!k) throw cyberchefError('errors.key_must_contain_letters');
  let ki = 0;
  return text(Array.from(asText(bytes), c => {
    if (!/[a-zA-Z]/.test(c)) return c;
    const base = c <= 'Z' ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 65;
    ki++;
    return String.fromCharCode(((c.charCodeAt(0) - base + (decode ? 26 - shift : shift)) % 26) + base);
  }).join(''));
}

export function caesarBrute(bytes) {
  const s = asText(bytes);
  const out = [];
  for (let sh = 1; sh < 26; sh++) {
    const t = s.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + sh) % 26) + base);
    });
    out.push(`ROT${String(sh).padStart(2, '0')}: ${t}`);
  }
  return text(out.join('\n'));
}

export function xorBruteForce(bytes) {
  if (!bytes.length) return new Uint8Array(0);
  const results = [];
  for (let k = 0; k < 256; k++) {
    const candidate = bytes.map(b => b ^ k);
    results.push({ k, candidate, q: decodeQuality(candidate) });
  }
  results.sort((a, b) => b.q - a.q || a.k - b.k);
  return text(results.slice(0, 8)
    .map(r => `${tr('output_xor_key', { hex: r.k.toString(16).padStart(2, '0'), dec: r.k, score: r.q.toFixed(0) })}\n${utf8DecodeLossy(r.candidate.subarray(0, 240))}`)
    .join('\n\n'));
}

function parseKeyMaterial(value) {
  const t = String(value ?? '').trim();
  if (t && /^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g, '').length % 2 === 0) return fromHex(text(t));
  return text(t);
}

export async function aesDecrypt(bytes, { key = '', iv = '', mode = 'CBC', inputFormat = 'base64' } = {}) {
  const keyBytes = parseKeyMaterial(key);
  if (![16, 24, 32].includes(keyBytes.length)) throw cyberchefError('errors.aes_key_invalid');
  const data = inputFormat === 'hex' ? fromHex(bytes) : fromBase64(bytes);
  const algo = mode === 'GCM' ? 'AES-GCM' : mode === 'CTR' ? 'AES-CTR' : 'AES-CBC';
  const ivBytes = parseKeyMaterial(iv);
  const params = mode === 'GCM' ? { name: algo, iv: ivBytes }
    : mode === 'CTR' ? { name: algo, counter: ivBytes, length: 64 }
      : { name: algo, iv: ivBytes };
  try {
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: algo }, false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt(params, cryptoKey, data));
  } catch (e) {
    throw cyberchefError('errors.aes_decrypt_failed', { detail: e?.message || String(e) });
  }
}

