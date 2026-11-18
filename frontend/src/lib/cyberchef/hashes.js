import { bytesToHex } from './bytes.js';

const rol = (x, n) => (x << n) | (x >>> (32 - n));

function padMessage(bytes) {
  const bitLenLow = (bytes.length << 3) >>> 0;
  const bitLenHigh = Math.floor(bytes.length / 0x20000000) >>> 0;
  const total = (((bytes.length + 8) >> 6) + 1) << 6;
  const out = new Uint8Array(total);
  out.set(bytes);
  out[bytes.length] = 0x80;
  const view = new DataView(out.buffer);
  view.setUint32(total - 8, bitLenLow, true);
  view.setUint32(total - 4, bitLenHigh, true);
  return view;
}

function digestToHex(words) {
  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  words.forEach((w, i) => view.setUint32(i * 4, w >>> 0, true));
  return bytesToHex(out);
}

export function md4(bytes) {
  const view = padMessage(bytes);
  let a = 0x67452301, b = 0xefcdab89 | 0, c = 0x98badcfe | 0, d = 0x10325476;
  const F = (x, y, z) => (x & y) | (~x & z);
  const G = (x, y, z) => (x & y) | (x & z) | (y & z);
  const H = (x, y, z) => x ^ y ^ z;
  const x = new Int32Array(16);
  for (let off = 0; off < view.byteLength; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(off + i * 4, true);
    const [aa, bb, cc, dd] = [a, b, c, d];
    const r1 = [3, 7, 11, 19];
    for (let i = 0; i < 16; i += 4) {
      a = rol((a + F(b, c, d) + x[i]) | 0, r1[0]);
      d = rol((d + F(a, b, c) + x[i + 1]) | 0, r1[1]);
      c = rol((c + F(d, a, b) + x[i + 2]) | 0, r1[2]);
      b = rol((b + F(c, d, a) + x[i + 3]) | 0, r1[3]);
    }
    const r2 = [3, 5, 9, 13];
    for (let i = 0; i < 4; i++) {
      a = rol((a + G(b, c, d) + x[i] + 0x5a827999) | 0, r2[0]);
      d = rol((d + G(a, b, c) + x[i + 4] + 0x5a827999) | 0, r2[1]);
      c = rol((c + G(d, a, b) + x[i + 8] + 0x5a827999) | 0, r2[2]);
      b = rol((b + G(c, d, a) + x[i + 12] + 0x5a827999) | 0, r2[3]);
    }
    const r3 = [3, 9, 11, 15];
    for (const i of [0, 2, 1, 3]) {
      a = rol((a + H(b, c, d) + x[i] + 0x6ed9eba1) | 0, r3[0]);
      d = rol((d + H(a, b, c) + x[i + 8] + 0x6ed9eba1) | 0, r3[1]);
      c = rol((c + H(d, a, b) + x[i + 4] + 0x6ed9eba1) | 0, r3[2]);
      b = rol((b + H(c, d, a) + x[i + 12] + 0x6ed9eba1) | 0, r3[3]);
    }
    a = (a + aa) | 0; b = (b + bb) | 0; c = (c + cc) | 0; d = (d + dd) | 0;
  }
  return digestToHex([a, b, c, d]);
}

const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0);
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

export function md5(bytes) {
  const view = padMessage(bytes);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  const m = new Int32Array(16);
  for (let off = 0; off < view.byteLength; off += 64) {
    for (let i = 0; i < 16; i++) m[i] = view.getInt32(off + i * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c;
      c = b;
      b = (b + rol((a + f + MD5_K[i] + m[g]) | 0, MD5_S[i])) | 0;
      a = tmp;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  return digestToHex([a0, b0, c0, d0]);
}

export function utf16leBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = code >> 8;
  }
  return out;
}

export function ntlm(bytes) {
  return md4(utf16leBytes(bytes));
}

let crcTable = null;

export function crc32(bytes) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 0xff];
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
}

export async function sha(algorithm, bytes) {
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return bytesToHex(new Uint8Array(digest));
}
