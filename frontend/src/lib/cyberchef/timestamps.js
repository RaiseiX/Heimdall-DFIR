import i18n from '../../i18n/index.js';
import { utf8Encode, asText } from './bytes.js';
import { cyberchefError, tr } from './errors.js';

const EPOCH_DIFF_MS = 11644473600000n;
const text = s => utf8Encode(s);

function localeString(d) {
  return d.toLocaleString(i18n.language);
}

export function parseDateAsUtc(value) {
  const s = value.trim();
  const naive = /^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?))?$/.exec(s);
  const d = naive ? new Date(`${naive[1]}T${naive[2] || '00:00:00'}Z`) : new Date(s);
  if (Number.isNaN(d.getTime())) throw cyberchefError('errors.invalid_iso_date');
  return d;
}

export function filetimeToDate(bytes) {
  const s = asText(bytes).trim().replace(/[\s,_]/g, '');
  let ft;
  try {
    if (/^(?:0x)?[0-9a-fA-F]{16}$/.test(s)) ft = BigInt(s.startsWith('0x') || s.startsWith('0X') ? s : `0x${s}`);
    else ft = BigInt(s.replace(/n$/, ''));
  } catch {
    throw cyberchefError('errors.filetime_invalid');
  }
  const ms = ft / 10000n - EPOCH_DIFF_MS;
  const d = new Date(Number(ms));
  if (Number.isNaN(d.getTime())) throw cyberchefError('errors.filetime_invalid');
  return text([
    `${tr('output_utc')} : ${d.toISOString()}`,
    `${tr('output_local')} : ${localeString(d)}`,
    `${tr('output_unix')} : ${Math.floor(Number(ms) / 1000)}`,
    `${tr('output_raw_value')} : ${ft.toString()} (${tr('output_100ns_since_1601')})`,
  ].join('\n'));
}

export function unixToDate(bytes) {
  const s = asText(bytes).trim();
  if (!/^-?\d+(?:\.\d+)?$/.test(s)) throw cyberchefError('errors.timestamp_invalid');
  const n = Number(s);
  const ms = Math.abs(n) >= 1e11 ? Math.trunc(n) : Math.round(n * 1000);
  const d = new Date(ms);
  if (!Number.isFinite(ms) || Number.isNaN(d.getTime())) throw cyberchefError('errors.timestamp_invalid');
  const ft = (BigInt(ms) + EPOCH_DIFF_MS) * 10000n;
  return text([
    `${tr('output_utc')} : ${d.toISOString()}`,
    `${tr('output_local')} : ${localeString(d)}`,
    `${tr('output_filetime')} : ${ft.toString()}`,
  ].join('\n'));
}

export function dateToUnix(bytes) {
  const d = parseDateAsUtc(asText(bytes));
  return text(`${tr('output_unix_seconds')} : ${Math.floor(d.getTime() / 1000)}\n${tr('output_unix_milliseconds')} : ${d.getTime()}\nISO : ${d.toISOString()}`);
}

export function dateToFiletime(bytes) {
  const d = parseDateAsUtc(asText(bytes));
  const ft = (BigInt(d.getTime()) + EPOCH_DIFF_MS) * 10000n;
  return text(`${tr('output_filetime_dec')} : ${ft.toString()}\n${tr('output_filetime_hex')} : ${ft.toString(16).toUpperCase().padStart(16, '0')}`);
}
