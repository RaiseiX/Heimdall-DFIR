import { cyberchefError } from './errors.js';

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });
const lossyDecoder = new TextDecoder('utf-8', { fatal: false });

export function utf8Encode(text) {
  return encoder.encode(text);
}

export function utf8DecodeStrict(bytes) {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

export function utf8DecodeLossy(bytes) {
  return lossyDecoder.decode(bytes);
}

export function latin1Decode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return out;
}

export function latin1Encode(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

export function bytesToHex(bytes, separator = '') {
  const parts = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = bytes[i].toString(16).padStart(2, '0');
  return parts.join(separator);
}

export function concatBytes(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export function describeBytes(bytes) {
  const text = utf8DecodeStrict(bytes);
  if (text !== null) return { kind: 'text', text };
  return { kind: 'binary', hex: bytesToHex(bytes, ' ') };
}

export function shannonEntropy(bytes) {
  if (!bytes || !bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export const HIGH_ENTROPY_THRESHOLD = 7.2;
export const HIGH_ENTROPY_MIN_LENGTH = 256;

export function isHighEntropy(bytes) {
  return bytes.length >= HIGH_ENTROPY_MIN_LENGTH && shannonEntropy(bytes) >= HIGH_ENTROPY_THRESHOLD;
}

export function asText(bytes) {
  const text = utf8DecodeStrict(bytes);
  if (text === null) throw cyberchefError('errors.input_not_text');
  return text;
}
