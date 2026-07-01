
import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import i18n from '../i18n/index.js';
import {
  FlaskConical, Wand2, Plus, X, ChevronDown, Copy,
  AlertTriangle, Play, RotateCcw, ChevronRight, Sparkles, GripVertical,
} from 'lucide-react';

const tr = (key, options) => i18n.t(`cyberchef.${key}`, options);
const resolveText = value => (typeof value === 'string' && value.startsWith('cyberchef.')) ? i18n.t(value) : value;

// ─── Hash helpers ────────────────────────────────────────────────────────────

function md5(str) {
  const s = unescape(encodeURIComponent(str));
  const add = (a,b) => { const l=(a&0xFFFF)+(b&0xFFFF); return (((a>>>16)+(b>>>16)+(l>>>16))<<16)|(l&0xFFFF); };
  const rol = (n,c) => (n<<c)|(n>>>(32-c));
  const cmn = (q,a,b,x,s,t) => add(rol(add(add(a,q),add(x,t)),s),b);
  const ff=(a,b,c,d,x,s,t)=>cmn((b&c)|(~b&d),a,b,x,s,t);
  const gg=(a,b,c,d,x,s,t)=>cmn((b&d)|(c&~d),a,b,x,s,t);
  const hh=(a,b,c,d,x,s,t)=>cmn(b^c^d,a,b,x,s,t);
  const ii=(a,b,c,d,x,s,t)=>cmn(c^(b|~d),a,b,x,s,t);
  const bl = []; const mask=255;
  for(let i=0;i<s.length*8;i+=8) bl[i>>5]|=(s.charCodeAt(i/8)&mask)<<(i%32);
  bl[s.length>>2]|=0x80<<(s.length%4*8); bl[(((s.length+8)>>6)<<4)+14]=s.length*8;
  const h2x = b => { let r=''; for(let i=0;i<b.length*4;i++) r+='0123456789abcdef'.charAt((b[i>>2]>>((i%4)*8+4))&0xF)+'0123456789abcdef'.charAt((b[i>>2]>>((i%4)*8))&0xF); return r; };
  let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for(let i=0;i<bl.length;i+=16){
    const[oa,ob,oc,od]=[a,b,c,d];
    a=ff(a,b,c,d,bl[i+0],7,-680876936);d=ff(d,a,b,c,bl[i+1],12,-389564586);c=ff(c,d,a,b,bl[i+2],17,606105819);b=ff(b,c,d,a,bl[i+3],22,-1044525330);
    a=ff(a,b,c,d,bl[i+4],7,-176418897);d=ff(d,a,b,c,bl[i+5],12,1200080426);c=ff(c,d,a,b,bl[i+6],17,-1473231341);b=ff(b,c,d,a,bl[i+7],22,-45705983);
    a=ff(a,b,c,d,bl[i+8],7,1770035416);d=ff(d,a,b,c,bl[i+9],12,-1958414417);c=ff(c,d,a,b,bl[i+10],17,-42063);b=ff(b,c,d,a,bl[i+11],22,-1990404162);
    a=ff(a,b,c,d,bl[i+12],7,1804603682);d=ff(d,a,b,c,bl[i+13],12,-40341101);c=ff(c,d,a,b,bl[i+14],17,-1502002290);b=ff(b,c,d,a,bl[i+15],22,1236535329);
    a=gg(a,b,c,d,bl[i+1],5,-165796510);d=gg(d,a,b,c,bl[i+6],9,-1069501632);c=gg(c,d,a,b,bl[i+11],14,643717713);b=gg(b,c,d,a,bl[i+0],20,-373897302);
    a=gg(a,b,c,d,bl[i+5],5,-701558691);d=gg(d,a,b,c,bl[i+10],9,38016083);c=gg(c,d,a,b,bl[i+15],14,-660478335);b=gg(b,c,d,a,bl[i+4],20,-405537848);
    a=gg(a,b,c,d,bl[i+9],5,568446438);d=gg(d,a,b,c,bl[i+14],9,-1019803690);c=gg(c,d,a,b,bl[i+3],14,-187363961);b=gg(b,c,d,a,bl[i+8],20,1163531501);
    a=gg(a,b,c,d,bl[i+13],5,-1444681467);d=gg(d,a,b,c,bl[i+2],9,-51403784);c=gg(c,d,a,b,bl[i+7],14,1735328473);b=gg(b,c,d,a,bl[i+12],20,-1926607734);
    a=hh(a,b,c,d,bl[i+5],4,-378558);d=hh(d,a,b,c,bl[i+8],11,-2022574463);c=hh(c,d,a,b,bl[i+11],16,1839030562);b=hh(b,c,d,a,bl[i+14],23,-35309556);
    a=hh(a,b,c,d,bl[i+1],4,-1530992060);d=hh(d,a,b,c,bl[i+4],11,1272893353);c=hh(c,d,a,b,bl[i+7],16,-155497632);b=hh(b,c,d,a,bl[i+10],23,-1094730640);
    a=hh(a,b,c,d,bl[i+13],4,681279174);d=hh(d,a,b,c,bl[i+0],11,-358537222);c=hh(c,d,a,b,bl[i+3],16,-722521979);b=hh(b,c,d,a,bl[i+6],23,76029189);
    a=hh(a,b,c,d,bl[i+9],4,-640364487);d=hh(d,a,b,c,bl[i+12],11,-421815835);c=hh(c,d,a,b,bl[i+15],16,530742520);b=hh(b,c,d,a,bl[i+2],23,-995338651);
    a=ii(a,b,c,d,bl[i+0],6,-198630844);d=ii(d,a,b,c,bl[i+7],10,1126891415);c=ii(c,d,a,b,bl[i+14],15,-1416354905);b=ii(b,c,d,a,bl[i+5],21,-57434055);
    a=ii(a,b,c,d,bl[i+12],6,1700485571);d=ii(d,a,b,c,bl[i+3],10,-1894986606);c=ii(c,d,a,b,bl[i+10],15,-1051523);b=ii(b,c,d,a,bl[i+1],21,-2054922799);
    a=ii(a,b,c,d,bl[i+8],6,1873313359);d=ii(d,a,b,c,bl[i+15],10,-30611744);c=ii(c,d,a,b,bl[i+6],15,-1560198380);b=ii(b,c,d,a,bl[i+13],21,1309151649);
    a=ii(a,b,c,d,bl[i+4],6,-145523070);d=ii(d,a,b,c,bl[i+11],10,-1120210379);c=ii(c,d,a,b,bl[i+2],15,718787259);b=ii(b,c,d,a,bl[i+9],21,-343485551);
    a=add(a,oa);b=add(b,ob);c=add(c,oc);d=add(d,od);
  }
  return h2x([a,b,c,d]);
}

async function sha(algo, str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest(algo, buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function ntlm(str) {
  const utf16 = [];
  for(let i=0;i<str.length;i++){ utf16.push(str.charCodeAt(i)&0xFF); utf16.push((str.charCodeAt(i)>>8)&0xFF); }
  const add=(a,b)=>(a+b)|0, rol=(n,c)=>(n<<c)|(n>>>(32-c));
  const bl=new Int32Array(((utf16.length+8)>>6)*16+2);
  for(let i=0;i<utf16.length;i++) bl[i>>2]|=utf16[i]<<((i&3)*8);
  bl[utf16.length>>2]|=0x80<<((utf16.length&3)*8); bl[bl.length-2]=utf16.length*8;
  let a=0x67452301,b=0xEFCDAB89|0,c=0x98BADCFE|0,d=0x10325476;
  const F=(b,c,d)=>(b&c)|(~b&d), G=(b,c,d)=>(b&c)|(b&d)|(c&d), H=(b,c,d)=>b^c^d;
  for(let i=0;i<bl.length;i+=16){
    const[oa,ob,oc,od]=[a,b,c,d];
    for(const[j,s,fn,k]of[[0,3,F,0],[1,7,F,0],[2,11,F,0],[3,19,F,0],[4,3,F,0],[5,7,F,0],[6,11,F,0],[7,19,F,0],[8,3,F,0],[9,7,F,0],[10,11,F,0],[11,19,F,0],[12,3,F,0],[13,7,F,0],[14,11,F,0],[15,19,F,0]]){
      if(j%4===0)a=rol(add(add(a,fn(b,c,d)),add(bl[i+j],k)),s);
      else if(j%4===1)d=rol(add(add(d,fn(a,b,c)),add(bl[i+j],k)),s);
      else if(j%4===2)c=rol(add(add(c,fn(d,a,b)),add(bl[i+j],k)),s);
      else b=rol(add(add(b,fn(c,d,a)),add(bl[i+j],k)),s);
    }
    const S2=[[0,3],[4,5],[8,9],[12,13],[1,3],[5,5],[9,9],[13,13],[2,3],[6,5],[10,9],[14,13],[3,3],[7,5],[11,9],[15,13]];
    for(const[j,s]of S2){
      if(j%4===0)a=rol(add(add(a,G(b,c,d)),add(bl[i+j],0x5A827999)),s);
      else if(j%4===1)d=rol(add(add(d,G(a,b,c)),add(bl[i+j],0x5A827999)),s);
      else if(j%4===2)c=rol(add(add(c,G(d,a,b)),add(bl[i+j],0x5A827999)),s);
      else b=rol(add(add(b,G(c,d,a)),add(bl[i+j],0x5A827999)),s);
    }
    const S3=[[0,3],[8,9],[4,11],[12,15],[2,3],[10,9],[6,11],[14,15],[1,3],[9,9],[5,11],[13,15],[3,3],[11,9],[7,11],[15,15]];
    for(const[j,s]of S3){
      if(j%4===0)a=rol(add(add(a,H(b,c,d)),add(bl[i+j],0x6ED9EBA1)),s);
      else if(j%4===1)d=rol(add(add(d,H(a,b,c)),add(bl[i+j],0x6ED9EBA1)),s);
      else if(j%4===2)c=rol(add(add(c,H(d,a,b)),add(bl[i+j],0x6ED9EBA1)),s);
      else b=rol(add(add(b,H(c,d,a)),add(bl[i+j],0x6ED9EBA1)),s);
    }
    a=add(a,oa);b=add(b,ob);c=add(c,oc);d=add(d,od);
  }
  return [a,b,c,d].map(n=>Array.from({length:4},(_,i)=>((n>>>(i*8))&0xFF).toString(16).padStart(2,'0')).join('')).join('');
}

// ─── Other helpers ────────────────────────────────────────────────────────────

function shannonEntropy(str) {
  if (!str || !str.length) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const l = str.length;
  return -Object.values(freq).reduce((s,f) => { const p=f/l; return s+p*Math.log2(p); }, 0);
}

let _crcTable = null;
function crc32(str) {
  if (!_crcTable) {
    _crcTable = [];
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; _crcTable[n] = c; }
  }
  const bytes = unescape(encodeURIComponent(str));
  let crc = 0 ^ (-1);
  for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ _crcTable[(crc ^ bytes.charCodeAt(i)) & 0xFF];
  return ((crc ^ (-1)) >>> 0).toString(16).padStart(8, '0');
}

function defangIoc(input) {
  return input
    .replace(/\bhttp(s?):\/\//gi, 'hxxp$1[://]')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}
function refangIoc(input) {
  return input
    .replace(/\[\.\]|\(\.\)|\(dot\)|\[dot\]/gi, '.')
    .replace(/\[@\]|\(at\)|\[at\]/gi, '@')
    .replace(/\[:\/\/\]|\[:\]/g, '://')
    .replace(/hxxp(s?)/gi, 'http$1');
}
function b64urlDecode(p) {
  let s = p.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  return decodeURIComponent(escape(atob(s)));
}
function jwtDecode(input) {
  const parts = input.trim().split('.');
  if (parts.length < 2) throw new Error(tr('errors.jwt_expected'));
  let header, payload;
  try { header = JSON.parse(b64urlDecode(parts[0])); payload = JSON.parse(b64urlDecode(parts[1])); }
  catch (e) { throw new Error(`${tr('errors.jwt_invalid')} — ${e.message}`); }
  const out = ['── HEADER ──', JSON.stringify(header, null, 2), '', '── PAYLOAD ──', JSON.stringify(payload, null, 2)];
  const claims = [];
  if (payload.iat) claims.push(`${tr('jwt_claim_iat')}   : ${new Date(payload.iat * 1000).toISOString()}`);
  if (payload.nbf) claims.push(`${tr('jwt_claim_nbf')} : ${new Date(payload.nbf * 1000).toISOString()}`);
  if (payload.exp) claims.push(`${tr('jwt_claim_exp')} : ${new Date(payload.exp * 1000).toISOString()}${payload.exp * 1000 < Date.now() ? `  ${tr('expired')}` : ''}`);
  if (claims.length) out.push('', '── CLAIMS ──', ...claims);
  out.push('', `${tr('signature')}: ${parts[2] || tr('no_signature')}`);
  return out.join('\n');
}
function decimalToIp(input) {
  const n = BigInt(input.trim().replace(/[^\d]/g, ''));
  if (n < 0n || n > 4294967295n) throw new Error(tr('errors.ipv4_integer_expected'));
  return `${(n >> 24n) & 255n}.${(n >> 16n) & 255n}.${(n >> 8n) & 255n}.${n & 255n}`;
}
function ipToDecimal(input) {
  const p = input.trim().split('.').map(Number);
  if (p.length !== 4 || p.some(x => isNaN(x) || x < 0 || x > 255)) throw new Error(tr('errors.ipv4_dotted_expected'));
  const dec = (BigInt(p[0]) << 24n) + (BigInt(p[1]) << 16n) + (BigInt(p[2]) << 8n) + BigInt(p[3]);
  return `${tr('output_decimal')}: ${dec.toString()}\n${tr('output_hex')}: 0x${dec.toString(16).padStart(8, '0')}`;
}

function toBase58(input) {
  if (!input.length) return '';
  let n = 0n;
  for (let i = 0; i < input.length; i++) n = n * 256n + BigInt(input.charCodeAt(i) & 0xFF);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (let i = 0; i < input.length && input.charCodeAt(i) === 0; i++) out = '1' + out;
  return out;
}

const MORSE = {
  A:'.-',B:'-...',C:'-.-.',D:'-..',E:'.',F:'..-.',G:'--.',H:'....',I:'..',J:'.---',K:'-.-',L:'.-..',M:'--',
  N:'-.',O:'---',P:'.--.',Q:'--.-',R:'.-.',S:'...',T:'-',U:'..-',V:'...-',W:'.--',X:'-..-',Y:'-.--',Z:'--..',
  0:'-----',1:'.----',2:'..---',3:'...--',4:'....-',5:'.....',6:'-....',7:'--...',8:'---..',9:'----.',
  '.':'.-.-.-',',':'--..--','?':'..--..',"'":'.----.','!':'-.-.--','/':'-..-.','(':'-.--.',')':'-.--.-',
  '&':'.-...',':':'---...',';':'-.-.-.','=':'-...-','+':'.-.-.','-':'-....-','_':'..--.-','"':'.-..-.','@':'.--.-.',
};
const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k,v]) => [v,k]));
function toMorse(input) {
  return input.toUpperCase().split('').map(c => c === ' ' ? '/' : (MORSE[c] || '')).filter(Boolean).join(' ');
}
function fromMorse(input) {
  return input.trim().split(/\s*\/\s*|\s+/).map(code => code === '' ? ' ' : (MORSE_REV[code] ?? '')).join('')
    .replace(/\s{2,}/g, ' ');
}

function toQuotedPrintable(input) {
  const bytes = unescape(encodeURIComponent(input));
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes.charCodeAt(i);
    if ((c >= 33 && c <= 126 && c !== 61) || c === 32 || c === 9) out += bytes[i];
    else out += '=' + c.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}
function fromQuotedPrintable(input) {
  const decoded = input.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  try { return decodeURIComponent(escape(decoded)); } catch { return decoded; }
}

function toHtmlEntity(input) {
  return input.replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]))
    .replace(/[\x80-\uffff]/g, c => '&#' + c.charCodeAt(0) + ';');
}

function decodeHtmlEntities(input) {
  return input
    .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"')
    .replace(/&#39;/g,"'").replace(/&apos;/g,"'").replace(/&nbsp;/g,'\u00a0')
    .replace(/&#x([0-9A-Fa-f]+);/g,(_,h)=>String.fromCharCode(parseInt(h,16)))
    .replace(/&#(\d+);/g,(_,d)=>String.fromCharCode(parseInt(d,10)));
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function fromBase32(input) {
  const s = input.trim().toUpperCase().replace(/=+$/,'').replace(/\s/g,'');
  let bits = 0, val = 0, out = '';
  for (const ch of s) {
    const i = BASE32_CHARS.indexOf(ch);
    if (i < 0) throw new Error(`${tr('errors.base32_invalid')}: ${ch}`);
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { bits -= 8; out += String.fromCharCode((val >> bits) & 0xFF); }
  }
  return out;
}
function toBase32(input) {
  let bits = 0, val = 0, out = '';
  for (let i=0; i<input.length; i++) { val=(val<<8)|input.charCodeAt(i); bits+=8; while(bits>=5){bits-=5;out+=BASE32_CHARS[(val>>bits)&31];} }
  if (bits > 0) out += BASE32_CHARS[(val<<(5-bits))&31];
  const pad = (4 - out.length % 4) % 4;
  return out + '='.repeat(pad === 4 ? 0 : pad);
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function fromBase58(input) {
  const s = input.trim();
  let result = BigInt(0);
  for (const ch of s) {
    const idx = B58.indexOf(ch);
    if (idx < 0) throw new Error(`${tr('errors.base58_invalid')}: ${ch}`);
    result = result * 58n + BigInt(idx);
  }
  let hex = result.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let out = '';
  for (let i = 0; i < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.slice(i,i+2),16));
  const leadingZeros = s.match(/^1*/)[0].length;
  return '\x00'.repeat(leadingZeros) + out;
}

function rc4(input, key) {
  const S = Array.from({length:256},(_,i)=>i);
  let j = 0;
  for (let i=0;i<256;i++){j=(j+S[i]+key.charCodeAt(i%key.length))%256;[S[i],S[j]]=[S[j],S[i]];}
  let i=0;j=0; let out='';
  for(const c of input){i=(i+1)%256;j=(j+S[i])%256;[S[i],S[j]]=[S[j],S[i]];out+=String.fromCharCode(c.charCodeAt(0)^S[(S[i]+S[j])%256]);}
  return out;
}

function vigenere(input, key, decode) {
  if (!key) throw new Error(tr('errors.empty_key'));
  const k = key.toUpperCase().replace(/[^A-Z]/g,'');
  if (!k) throw new Error(tr('errors.key_must_contain_letters'));
  let ki=0, out='';
  for(const c of input){
    if(/[a-zA-Z]/.test(c)){
      const base=c<='Z'?65:97, shift=k.charCodeAt(ki%k.length)-65;
      out+=String.fromCharCode((c.charCodeAt(0)-base+(decode?26-shift:shift))%26+base);
      ki++;
    } else out+=c;
  }
  return out;
}

function filetimeToDate(input) {
  const s = input.trim().replace(/[\s,_]/g,'');
  let ft;
  if (/^[0-9a-fA-F]{16}$/.test(s)) {
    const hi = parseInt(s.slice(0,8),16), lo = parseInt(s.slice(8),16);
    ft = BigInt(hi)*0x100000000n + BigInt(lo);
  } else {
    ft = BigInt(s.replace(/n$/,''));
  }
  const EPOCH_DIFF = 11644473600000n;
  const ms = ft / 10000n - EPOCH_DIFF;
  const d = new Date(Number(ms));
  if (isNaN(d)) throw new Error(tr('errors.filetime_invalid'));
  return [
    `${tr('output_utc')} : ${d.toISOString()}`,
    `${tr('output_local')} : ${d.toLocaleString()}`,
    `${tr('output_unix')} : ${Math.floor(Number(ms)/1000)}`,
    `${tr('output_raw_value')} : ${ft.toString()} (${tr('output_100ns_since_1601')})`,
  ].join('\n');
}

function unixToDate(input) {
  const s = input.trim();
  let ts = parseInt(s);
  if (isNaN(ts)) throw new Error(tr('errors.timestamp_invalid'));
  if (s.length === 13) ts = ts;
  else ts = ts * 1000;
  const d = new Date(ts);
  const ft = (BigInt(ts) + 11644473600000n) * 10000n;
  return [
    `${tr('output_utc')} : ${d.toISOString()}`,
    `${tr('output_local')} : ${d.toLocaleString()}`,
    `${tr('output_filetime')} : ${ft.toString()}`,
  ].join('\n');
}

function prettifyJson(input) {
  try { return JSON.stringify(JSON.parse(input), null, 2); }
  catch (e) { throw new Error(`${tr('errors.json_invalid')} — ${e.message}`); }
}

function prettifyXml(input) {
  let indent = 0, out = '';
  const lines = input.replace(/>\s*</g, '>\n<').split('\n');
  for (const line of lines) {
    const l = line.trim();
    if (!l) continue;
    if (/^<\//.test(l)) indent--;
    out += '  '.repeat(Math.max(0,indent)) + l + '\n';
    if (!/^<\//.test(l) && !/\/>$/.test(l) && /^<[^!?]/.test(l) && !/<\//.test(l)) indent++;
  }
  return out.trim();
}

// ─── Compression (native browser DecompressionStream) ─────────────────────────
// Attacker payloads (esp. PowerShell `IO.Compression.DeflateStream` / `GzipStream`)
// are almost always Base64 → compressed bytes. Pipe fromBase64 → one of these.

async function decompress(input, format) {
  if (typeof DecompressionStream === 'undefined')
    throw new Error('DecompressionStream non supporté par ce navigateur');
  const bytes = Uint8Array.from(input, c => c.charCodeAt(0) & 0xFF);
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  const buf = await new Response(stream).arrayBuffer();
  return new TextDecoder('utf-8', { fatal: false }).decode(buf);
}

// ─── Symmetric crypto (native Web Crypto) ─────────────────────────────────────

function hexToBytes(h) {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) throw new Error('Hex de longueur impaire');
  const a = new Uint8Array(clean.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(clean.substr(i * 2, 2), 16);
  return a;
}
// Keys/IVs are accepted as hex (even-length hex string) or raw UTF-8 text.
function parseKeyMaterial(v) {
  const t = (v || '').trim();
  if (/^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g, '').length % 2 === 0 && t.length)
    return hexToBytes(t);
  return Uint8Array.from(unescape(encodeURIComponent(t)), c => c.charCodeAt(0));
}

async function aesDecrypt(input, { key = '', iv = '', mode = 'CBC', inputFormat = 'base64' } = {}) {
  const keyBytes = parseKeyMaterial(key);
  if (![16, 24, 32].includes(keyBytes.length)) throw new Error('Clé AES invalide — 16/24/32 octets attendus (128/192/256 bits)');
  let data;
  if (inputFormat === 'hex') data = hexToBytes(input);
  else data = Uint8Array.from(atob(input.trim().replace(/\s/g, '')), c => c.charCodeAt(0));
  const algo = mode === 'GCM' ? 'AES-GCM' : mode === 'CTR' ? 'AES-CTR' : 'AES-CBC';
  const ck = await crypto.subtle.importKey('raw', keyBytes, { name: algo }, false, ['decrypt']);
  const ivBytes = parseKeyMaterial(iv);
  let params;
  if (mode === 'GCM') params = { name: 'AES-GCM', iv: ivBytes };
  else if (mode === 'CTR') params = { name: 'AES-CTR', counter: ivBytes, length: 64 };
  else params = { name: 'AES-CBC', iv: ivBytes };
  let pt;
  try { pt = await crypto.subtle.decrypt(params, ck, data); }
  catch (e) { throw new Error(`Échec du déchiffrement AES (clé/IV/mode/format incorrects ?) — ${e.message || e}`); }
  return new TextDecoder('utf-8', { fatal: false }).decode(pt);
}

// ─── Brute-force helpers ──────────────────────────────────────────────────────

// Try all 256 single-byte XOR keys, rank by the same quality scorer used by Magic.
function xorBruteForce(input) {
  const bytes = Array.from(input, c => c.charCodeAt(0) & 0xFF);
  if (!bytes.length) return '';
  const results = [];
  for (let k = 0; k < 256; k++) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b ^ k);
    results.push({ k, s, q: decodeQuality(s) });
  }
  results.sort((a, b) => b.q - a.q);
  return results.slice(0, 8)
    .map(r => `── clé 0x${r.k.toString(16).padStart(2, '0')} (${r.k})  score ${r.q.toFixed(0)} ──\n${r.s.slice(0, 240)}`)
    .join('\n\n');
}

// Show every Caesar/ROT shift so the analyst can eyeball the readable one.
function caesarBrute(input) {
  const out = [];
  for (let sh = 1; sh < 26; sh++) {
    const t = input.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + sh) % 26 + base);
    });
    out.push(`ROT${String(sh).padStart(2, '0')}: ${t}`);
  }
  return out.join('\n');
}

// ─── Ascii85 / Base85 ─────────────────────────────────────────────────────────

function fromAscii85(input) {
  let s = input.trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s/g, '');
  let out = '', tuple = [];
  for (const ch of s) {
    if (ch === 'z' && tuple.length === 0) { out += '\x00\x00\x00\x00'; continue; }
    const v = ch.charCodeAt(0) - 33;
    if (v < 0 || v > 84) throw new Error(`Caractère Ascii85 invalide : ${ch}`);
    tuple.push(v);
    if (tuple.length === 5) {
      let n = 0; for (const t of tuple) n = n * 85 + t;
      out += String.fromCharCode((n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF);
      tuple = [];
    }
  }
  if (tuple.length) {
    const len = tuple.length;
    while (tuple.length < 5) tuple.push(84);
    let n = 0; for (const t of tuple) n = n * 85 + t;
    const b = [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF];
    for (let i = 0; i < len - 1; i++) out += String.fromCharCode(b[i]);
  }
  return out;
}

// ─── Octal escapes ────────────────────────────────────────────────────────────
// Common in bash/python obfuscation: \101\102 or space/comma separated octal.
function fromOctal(input) {
  const s = input.trim();
  if (/\\[0-7]{1,3}/.test(s))
    return s.replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
  const parts = s.split(/[\s,]+/).filter(Boolean);
  if (parts.some(p => !/^[0-7]+$/.test(p))) throw new Error('Octal invalide');
  return parts.map(p => String.fromCharCode(parseInt(p, 8))).join('');
}

// ─── Microsoft Script Encoder (JScript.Encode / VBScript.Encode — .jse/.vbe) ──
// Verified against the CyberChef "Microsoft Script Decoder" reference (Didier
// Stevens' algorithm) and its #@~^…^#~@ test vector. Tables are exact.
const MS_D_DECODE = [
  '','','','','','','','','',
  '\x57\x6E\x7B','\x4A\x4C\x41','\x0B\x0B\x0B','\x0C\x0C\x0C','\x4A\x4C\x41','\x0E\x0E\x0E','\x0F\x0F\x0F',
  '\x10\x10\x10','\x11\x11\x11','\x12\x12\x12','\x13\x13\x13','\x14\x14\x14','\x15\x15\x15','\x16\x16\x16','\x17\x17\x17',
  '\x18\x18\x18','\x19\x19\x19','\x1A\x1A\x1A','\x1B\x1B\x1B','\x1C\x1C\x1C','\x1D\x1D\x1D','\x1E\x1E\x1E','\x1F\x1F\x1F',
  '\x2E\x2D\x32','\x47\x75\x30','\x7A\x52\x21','\x56\x60\x29','\x42\x71\x5B','\x6A\x5E\x38','\x2F\x49\x33','\x26\x5C\x3D',
  '\x49\x62\x58','\x41\x7D\x3A','\x34\x29\x35','\x32\x36\x65','\x5B\x20\x39','\x76\x7C\x5C','\x72\x7A\x56','\x43\x7F\x73',
  '\x38\x6B\x66','\x39\x63\x4E','\x70\x33\x45','\x45\x2B\x6B','\x68\x68\x62','\x71\x51\x59','\x4F\x66\x78','\x09\x76\x5E',
  '\x62\x31\x7D','\x44\x64\x4A','\x23\x54\x6D','\x75\x43\x71','\x4A\x4C\x41','\x7E\x3A\x60','\x4A\x4C\x41','\x5E\x7E\x53',
  '\x40\x4C\x40','\x77\x45\x42','\x4A\x2C\x27','\x61\x2A\x48','\x5D\x74\x72','\x22\x27\x75','\x4B\x37\x31','\x6F\x44\x37',
  '\x4E\x79\x4D','\x3B\x59\x52','\x4C\x2F\x22','\x50\x6F\x54','\x67\x26\x6A','\x2A\x72\x47','\x7D\x6A\x64','\x74\x39\x2D',
  '\x54\x7B\x20','\x2B\x3F\x7F','\x2D\x38\x2E','\x2C\x77\x4C','\x30\x67\x5D','\x6E\x53\x7E','\x6B\x47\x6C','\x66\x34\x6F',
  '\x35\x78\x79','\x25\x5D\x74','\x21\x30\x43','\x64\x23\x26','\x4D\x5A\x76','\x52\x5B\x25','\x63\x6C\x24','\x3F\x48\x2B',
  '\x7B\x55\x28','\x78\x70\x23','\x29\x69\x41','\x28\x2E\x34','\x73\x4C\x09','\x59\x21\x2A','\x33\x24\x44','\x7F\x4E\x3F',
  '\x6D\x50\x77','\x55\x09\x3B','\x53\x56\x55','\x7C\x73\x69','\x3A\x35\x61','\x5F\x61\x63','\x65\x4B\x50','\x46\x58\x67',
  '\x58\x3B\x51','\x31\x57\x49','\x69\x22\x4F','\x6C\x6D\x46','\x5A\x4D\x68','\x48\x25\x7C','\x27\x28\x36','\x5C\x46\x70',
  '\x3D\x4A\x6E','\x24\x32\x7A','\x79\x41\x2F','\x37\x3D\x5F','\x60\x5F\x4B','\x51\x4F\x5A','\x20\x42\x2C','\x36\x65\x57',
];
const MS_D_COMBINATION = [0,1,2,0,1,2,1,2,2,1,2,1,0,2,1,2,0,2,1,2,0,0,1,2,2,1,0,2,1,2,2,1,0,0,2,1,2,1,2,0,2,0,0,1,2,0,2,1,0,2,1,2,0,0,1,2,2,0,0,1,2,0,2,1];

function decodeMsScript(input) {
  const m = /#@~\^.{6}==([\s\S]+)==\^#~@/.exec(input.trim());
  if (!m && !/[@^]/.test(input)) throw new Error('Aucun bloc encodé #@~^…^#~@ détecté');
  // Body lies between the leading length token (……==) and the trailing 6-char
  // checksum + ==^#~@. Strip the plain-base64 checksum before decoding.
  let data = m ? m[1].slice(0, -6) : input;
  data = data.replace(/@&/g, '\n').replace(/@#/g, '\r').replace(/@\*/g, '>').replace(/@!/g, '<').replace(/@\$/g, '@');
  const result = [];
  let index = -1;
  for (let i = 0; i < data.length; i++) {
    const byte = data.charCodeAt(i);
    let ch = data.charAt(i);
    if (byte < 128) index++;
    if ((byte === 9 || (byte > 31 && byte < 128)) && byte !== 60 && byte !== 62 && byte !== 64)
      ch = MS_D_DECODE[byte].charAt(MS_D_COMBINATION[index % 64]);
    result.push(ch);
  }
  return result.join('');
}

// ─── Hexdump → bytes (xxd / hexdump -C / PowerShell Format-Hex) ────────────────
function fromHexdump(input) {
  const out = input.split('\n').map(line => {
    // Drop a leading offset column (hex digits, optional ':').
    let l = line.replace(/^\s*[0-9A-Fa-f]{4,}:?\s+/, '');
    // Cut the ASCII gutter (a '|' or a run of 2+ spaces separating it).
    l = l.split(/\s{2,}|\|/)[0];
    return (l.match(/[0-9A-Fa-f]{2}/g) || []).map(h => String.fromCharCode(parseInt(h, 16))).join('');
  }).join('');
  if (!out) throw new Error('Aucun octet hex trouvé dans le hexdump');
  return out;
}

// ─── Operations ──────────────────────────────────────────────────────────────

const OPS = {
  psCommandDecode: {
    label: 'PowerShell -EncodedCommand', category: 'specialized',
    desc: tr('ops.psCommandDecode.desc'),
    params: [],
    fn: (input) => {
      const s = input.trim().replace(/\s/g,''), raw = atob(s), bytes = Array.from(raw).map(c=>c.charCodeAt(0)), out=[];
      for(let i=0;i+1<bytes.length;i+=2){const code=bytes[i]|(bytes[i+1]<<8);if(code>0)out.push(String.fromCharCode(code));}
      return out.join('');
    },
  },
  fromBase64: {
    label: tr('ops.fromBase64.label'), category: 'encoding',
    desc: tr('ops.fromBase64.desc'),
    params: [],
    fn: (input) => {
      let s = input.trim().replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');
      const pad = s.length % 4; if (pad) s += '='.repeat(4 - pad);
      try { return atob(s); } catch(e) { throw new Error(`${tr('errors.base64_invalid')} — ${e.message}`); }
    },
  },
  toBase64: {
    label: tr('ops.toBase64.label'), category: 'encoding', desc: tr('ops.toBase64.desc'), params: [],
    fn: (input) => { try{return btoa(input);}catch{return btoa(unescape(encodeURIComponent(input)));} },
  },
  fromBase32: {
    label: tr('ops.fromBase32.label'), category: 'encoding', desc: tr('ops.fromBase32.desc'), params: [],
    fn: (input) => fromBase32(input),
  },
  toBase32: {
    label: tr('ops.toBase32.label'), category: 'encoding', desc: tr('ops.toBase32.desc'), params: [],
    fn: (input) => toBase32(input),
  },
  fromBase58: {
    label: tr('ops.fromBase58.label'), category: 'encoding', desc: tr('ops.fromBase58.desc'), params: [],
    fn: (input) => fromBase58(input),
  },
  fromHex: {
    label: tr('ops.fromHex.label'), category: 'encoding', desc: tr('ops.fromHex.desc'), params: [],
    fn: (input) => {
      let s=input.trim().replace(/0x/gi,'').replace(/\\x/gi,'').replace(/[,\s]+/g,'');
      if(!/^[0-9a-fA-F]+$/.test(s)) throw new Error(tr('errors.hex_invalid'));
      if(s.length%2!==0) s='0'+s;
      let r=''; for(let i=0;i<s.length;i+=2) r+=String.fromCharCode(parseInt(s.substr(i,2),16)); return r;
    },
  },
  toHex: {
    label: tr('ops.toHex.label'), category: 'encoding', desc: tr('ops.toHex.desc'),
    params: [{ id:'sep', label:tr('ops.toHex.param_sep'), type:'select', options:[
      { value:'space', label:tr('options.space') },
      { value:'none', label:tr('options.none') },
      { value:'backslash_x', label:'\\x' },
      { value:'prefix_0x', label:'0x' },
    ], default:'space' }],
    fn: (input, {sep='space'}={}) => Array.from(input).map(ch=>{const h=ch.charCodeAt(0).toString(16).padStart(2,'0');return sep==='backslash_x'?'\\x'+h:sep==='prefix_0x'?'0x'+h:h;}).join(sep==='space'?' ':''),
  },
  fromBinary: {
    label: tr('ops.fromBinary.label'), category: 'encoding', desc: tr('ops.fromBinary.desc'), params: [],
    fn: (input) => {
      const chunks = input.trim().replace(/\s+/g,' ').split(' ');
      if(chunks.some(ch=>!/^[01]{8}$/.test(ch))) throw new Error(tr('errors.binary_format_expected'));
      return chunks.map(c=>String.fromCharCode(parseInt(c,2))).join('');
    },
  },
  toBinary: {
    label: tr('ops.toBinary.label'), category: 'encoding', desc: tr('ops.toBinary.desc'), params: [],
    fn: (input) => Array.from(input).map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '),
  },
  fromUnicodeEscape: {
    label: tr('ops.fromUnicodeEscape.label'), category: 'encoding', desc: tr('ops.fromUnicodeEscape.desc'), params: [],
    fn: (input) => input.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  },
  toUnicodeEscape: {
    label: tr('ops.toUnicodeEscape.label'), category: 'encoding', desc: tr('ops.toUnicodeEscape.desc'), params: [],
    fn: (input) => Array.from(input).map(c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join(''),
  },
  urlDecode: {
    label: tr('ops.urlDecode.label'), category: 'encoding', desc: tr('ops.urlDecode.desc'), params: [],
    fn: (input) => { try{return decodeURIComponent(input.replace(/\+/g,' '));}catch{return unescape(input);} },
  },
  urlEncode: {
    label: tr('ops.urlEncode.label'), category: 'encoding', desc: tr('ops.urlEncode.desc'), params: [],
    fn: (input) => encodeURIComponent(input),
  },
  fromHtmlEntity: {
    label: tr('ops.fromHtmlEntity.label'), category: 'encoding', desc: tr('ops.fromHtmlEntity.desc'), params: [],
    fn: (input) => decodeHtmlEntities(input),
  },
  fromCharcode: {
    label: tr('ops.fromCharcode.label'), category: 'encoding', desc: tr('ops.fromCharcode.desc'),
    params: [{ id:'base', label:tr('ops.fromCharcode.param_base'), type:'select', options:[
      { value:'decimal', label:tr('options.decimal') },
      { value:'hex', label:tr('options.hex') },
      { value:'octal', label:tr('options.octal') },
    ], default:'decimal' }],
    fn: (input, {base='decimal'}={}) => {
      const radix=base==='hex'?16:base==='octal'?8:10;
      const codes=input.trim().split(/[\s,]+/).map(s=>parseInt(s,radix));
      if(codes.some(isNaN)) throw new Error(tr('errors.invalid_charcodes'));
      return codes.map(c=>String.fromCharCode(c)).join('');
    },
  },
  decodeUtf16le: {
    label: tr('ops.decodeUtf16le.label'), category: 'encoding', desc: tr('ops.decodeUtf16le.desc'), params: [],
    fn: (input) => {
      const bytes=Array.from(input).map(c=>c.charCodeAt(0)), out=[];
      for(let i=0;i+1<bytes.length;i+=2){const code=bytes[i]|(bytes[i+1]<<8);if(code>0)out.push(String.fromCharCode(code));}
      return out.join('');
    },
  },
  md5Hash: {
    label: 'MD5', category: 'hash', desc: tr('ops.md5Hash.desc'), params: [],
    fn: (input) => md5(input),
  },
  sha1Hash: {
    label: 'SHA-1', category: 'hash', desc: tr('ops.sha1Hash.desc'), params: [],
    async: true,
    fn: async (input) => sha('SHA-1', input),
  },
  sha256Hash: {
    label: 'SHA-256', category: 'hash', desc: tr('ops.sha256Hash.desc'), params: [],
    async: true,
    fn: async (input) => sha('SHA-256', input),
  },
  sha512Hash: {
    label: 'SHA-512', category: 'hash', desc: tr('ops.sha512Hash.desc'), params: [],
    async: true,
    fn: async (input) => sha('SHA-512', input),
  },
  ntlmHash: {
    label: 'NTLM (MD4)', category: 'hash', desc: tr('ops.ntlmHash.desc'), params: [],
    fn: (input) => ntlm(input),
  },
  rot13: {
    label: tr('ops.rot13.label'), category: 'cipher', desc: tr('ops.rot13.desc'),
    params: [{ id:'amount', label:tr('ops.rot13.param_amount'), type:'number', default:13, min:1, max:25 }],
    fn: (input, {amount=13}={}) => input.replace(/[a-zA-Z]/g, c=>{const base=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-base+Number(amount))%26+base);}),
  },
  atbash: {
    label: 'Atbash', category: 'cipher', desc: tr('ops.atbash.desc'), params: [],
    fn: (input) => input.replace(/[a-zA-Z]/g, c=>{const base=c<='Z'?65:97;return String.fromCharCode(base+25-(c.charCodeAt(0)-base));}),
  },
  vigenereDecode: {
    label: tr('ops.vigenereDecode.label'), category: 'cipher', desc: tr('ops.vigenereDecode.desc'),
    params: [{ id:'key', label:tr('ops.vigenereDecode.param_key'), type:'text', default:'SECRET' }],
    fn: (input, {key='SECRET'}={}) => vigenere(input, key, true),
  },
  vigenereEncode: {
    label: tr('ops.vigenereEncode.label'), category: 'cipher', desc: tr('ops.vigenereEncode.desc'),
    params: [{ id:'key', label:tr('ops.vigenereEncode.param_key'), type:'text', default:'SECRET' }],
    fn: (input, {key='SECRET'}={}) => vigenere(input, key, false),
  },
  xorDecode: {
    label: tr('ops.xorDecode.label'), category: 'cipher', desc: tr('ops.xorDecode.desc'),
    params: [{ id:'key', label:tr('ops.xorDecode.param_key'), type:'text', default:'0x41' }],
    fn: (input, {key='0x41'}={}) => {
      const k=parseInt(key,16); if(isNaN(k)) throw new Error(tr('errors.invalid_key_single_byte'));
      return Array.from(input).map(c=>String.fromCharCode(c.charCodeAt(0)^k)).join('');
    },
  },
  xorMultibyte: {
    label: tr('ops.xorMultibyte.label'), category: 'cipher', desc: tr('ops.xorMultibyte.desc'),
    params: [{ id:'key', label:tr('ops.xorMultibyte.param_key'), type:'text', default:'deadbeef' }],
    fn: (input, {key='deadbeef'}={}) => {
      const k=key.replace(/0x|\\x|\s/gi,'');
      if(!/^[0-9a-fA-F]+$/.test(k)||k.length%2!==0) throw new Error(tr('errors.invalid_hex_key'));
      const keyBytes=Array.from({length:k.length/2},(_,i)=>parseInt(k.slice(i*2,i*2+2),16));
      return Array.from(input).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^keyBytes[i%keyBytes.length])).join('');
    },
  },
  rc4Decode: {
    label: 'RC4', category: 'cipher', desc: tr('ops.rc4Decode.desc'),
    params: [{ id:'key', label:tr('ops.rc4Decode.param_key'), type:'text', default:'secret' }],
    fn: (input, {key='secret'}={}) => { if(!key) throw new Error(tr('errors.empty_key')); return rc4(input, key); },
  },
  reverseString: {
    label: tr('ops.reverseString.label'), category: 'formatting', desc: tr('ops.reverseString.desc'),
    params: [{ id:'by', label:tr('ops.reverseString.param_by'), type:'select', options:[
      { value:'char', label:tr('options.char') },
      { value:'line', label:tr('options.line') },
      { value:'word', label:tr('options.word') },
    ], default:'char' }],
    fn: (input, {by='char'}={}) => by==='line'?input.split('\n').reverse().join('\n'):by==='word'?input.split(/\s+/).reverse().join(' '):[...input].reverse().join(''),
  },
  stripNulls: {
    label: tr('ops.stripNulls.label'), category: 'formatting', desc: tr('ops.stripNulls.desc'), params: [],
    fn: (input) => input.replace(/\x00/g,''),
  },
  jsonPrettify: {
    label: 'JSON Prettify', category: 'formatting', desc: tr('ops.jsonPrettify.desc'), params: [],
    fn: (input) => prettifyJson(input),
  },
  jsonMinify: {
    label: 'JSON Minify', category: 'formatting', desc: tr('ops.jsonMinify.desc'), params: [],
    fn: (input) => { try{return JSON.stringify(JSON.parse(input));}catch(e){throw new Error(`${tr('errors.json_invalid')} — ${e.message}`);} },
  },
  xmlPrettify: {
    label: 'XML Prettify', category: 'formatting', desc: tr('ops.xmlPrettify.desc'), params: [],
    fn: (input) => prettifyXml(input),
  },
  toUpper: {
    label: tr('ops.toUpper.label'), category: 'formatting', desc: tr('ops.toUpper.desc'), params: [],
    fn: (input) => input.toUpperCase(),
  },
  toLower: {
    label: tr('ops.toLower.label'), category: 'formatting', desc: tr('ops.toLower.desc'), params: [],
    fn: (input) => input.toLowerCase(),
  },
  sortLines: {
    label: tr('ops.sortLines.label'), category: 'formatting', desc: tr('ops.sortLines.desc'),
    params: [{ id:'order', label:tr('ops.sortLines.param_order'), type:'select', options:[
      { value:'asc', label:tr('options.asc') },
      { value:'desc', label:tr('options.desc') },
    ], default:'asc' }],
    fn: (input, {order='asc'}={}) => { const l=input.split('\n').sort(); return order==='desc'?l.reverse().join('\n'):l.join('\n'); },
  },
  removeDuplicates: {
    label: tr('ops.removeDuplicates.label'), category: 'formatting', desc: tr('ops.removeDuplicates.desc'), params: [],
    fn: (input) => [...new Set(input.split('\n'))].join('\n'),
  },
  removeBlankLines: {
    label: tr('ops.removeBlankLines.label'), category: 'formatting', desc: tr('ops.removeBlankLines.desc'), params: [],
    fn: (input) => input.split('\n').filter(l=>l.trim()).join('\n'),
  },
  extractStrings: {
    label: tr('ops.extractStrings.label'), category: 'extraction', desc: tr('ops.extractStrings.desc'),
    params: [{ id:'minLen', label:tr('ops.extractStrings.param_min_len'), type:'number', default:4, min:1, max:100 }],
    fn: (input, {minLen=4}={}) => { const re=new RegExp(`[\\x20-\\x7e]{${minLen},}`,'g'); return(input.match(re)||[]).join('\n')||tr('outputs.none_string'); },
  },
  extractUrls: {
    label: tr('ops.extractUrls.label'), category: 'extraction', desc: tr('ops.extractUrls.desc'), params: [],
    fn: (input) => (input.match(/https?:\/\/[^\s"'<>)\]]+/g)||[]).join('\n')||tr('outputs.none_url'),
  },
  extractIps: {
    label: tr('ops.extractIps.label'), category: 'extraction', desc: tr('ops.extractIps.desc'), params: [],
    fn: (input) => {
      const v4=(input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]);
      const v6=(input.match(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g)||[]);
      return [...new Set([...v4,...v6])].join('\n')||tr('outputs.none_ip');
    },
  },
  extractEmails: {
    label: tr('ops.extractEmails.label'), category: 'extraction', desc: tr('ops.extractEmails.desc'), params: [],
    fn: (input) => (input.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[]).join('\n')||tr('outputs.none_email'),
  },
  extractDomains: {
    label: tr('ops.extractDomains.label'), category: 'extraction', desc: tr('ops.extractDomains.desc'), params: [],
    fn: (input) => {
      const re=/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|fr|de|uk|ru|cn|info|biz|xyz|onion|local|internal|corp)\b/gi;
      return [...new Set(input.match(re)||[])].join('\n')||tr('outputs.none_domain');
    },
  },
  extractHashes: {
    label: tr('ops.extractHashes.label'), category: 'extraction', desc: tr('ops.extractHashes.desc'), params: [],
    fn: (input) => {
      const md5m=(input.match(/\b[0-9a-fA-F]{32}\b/g)||[]);
      const sha1m=(input.match(/\b[0-9a-fA-F]{40}\b/g)||[]);
      const sha256m=(input.match(/\b[0-9a-fA-F]{64}\b/g)||[]);
      const lines=[];
      if(md5m.length) lines.push(`MD5 (${md5m.length}):\n`+[...new Set(md5m)].join('\n'));
      if(sha1m.length) lines.push(`SHA-1 (${sha1m.length}):\n`+[...new Set(sha1m)].join('\n'));
      if(sha256m.length) lines.push(`SHA-256 (${sha256m.length}):\n`+[...new Set(sha256m)].join('\n'));
      return lines.join('\n\n')||tr('outputs.none_hash');
    },
  },
  extractWinPaths: {
    label: tr('ops.extractWinPaths.label'), category: 'extraction', desc: tr('ops.extractWinPaths.desc'), params: [],
    fn: (input) => {
      const re=/(?:[A-Za-z]:\\|\\\\)[^\s"'<>|*?\x00-\x1f]+/g;
      return [...new Set(input.match(re)||[])].join('\n')||tr('outputs.none_windows_path');
    },
  },
  extractLinuxPaths: {
    label: tr('ops.extractLinuxPaths.label'), category: 'extraction', desc: tr('ops.extractLinuxPaths.desc'), params: [],
    fn: (input) => {
      const re=/(?:\/(?:etc|tmp|var|home|usr|opt|proc|sys|dev|run|lib|bin|sbin|boot|root|srv)(?:\/[^\s"'<>|*?\x00-\x1f]*)?)/g;
      return [...new Set(input.match(re)||[])].join('\n')||tr('outputs.none_linux_path');
    },
  },
  extractGuids: {
    label: tr('ops.extractGuids.label'), category: 'extraction', desc: tr('ops.extractGuids.desc'), params: [],
    fn: (input) => {
      const re=/\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?/g;
      return [...new Set(input.match(re)||[])].join('\n')||tr('outputs.none_guid');
    },
  },
  regexExtract: {
    label: tr('ops.regexExtract.label'), category: 'extraction', desc: tr('ops.regexExtract.desc'),
    params: [
      { id:'pattern', label:tr('ops.regexExtract.param_pattern'), type:'text', default:'[A-Za-z0-9+/=]{20,}' },
      { id:'flags', label:tr('ops.regexExtract.param_flags'), type:'text', default:'g' },
    ],
    fn: (input, {pattern='[A-Za-z0-9+/=]{20,}',flags='g'}={}) => {
      try{return(input.match(new RegExp(pattern,flags))||[]).join('\n')||tr('outputs.none_result');}
      catch(e){throw new Error(`${tr('errors.regex_invalid')} — ${e.message}`);}
    },
  },
  filetimeConvert: {
    label: tr('ops.filetimeConvert.label'), category: 'timestamps', desc: tr('ops.filetimeConvert.desc'),
    params: [],
    fn: (input) => filetimeToDate(input),
  },
  unixConvert: {
    label: tr('ops.unixConvert.label'), category: 'timestamps', desc: tr('ops.unixConvert.desc'),
    params: [],
    fn: (input) => unixToDate(input),
  },
  dateToUnix: {
    label: tr('ops.dateToUnix.label'), category: 'timestamps', desc: tr('ops.dateToUnix.desc'),
    params: [],
    fn: (input) => {
      const d=new Date(input.trim()); if(isNaN(d)) throw new Error(tr('errors.invalid_iso_date'));
      return `${tr('output_unix_seconds')} : ${Math.floor(d.getTime()/1000)}\n${tr('output_unix_milliseconds')} : ${d.getTime()}\nISO : ${d.toISOString()}`;
    },
  },
  countChars: {
    label: tr('ops.countChars.label'), category: 'info', desc: tr('ops.countChars.desc'), params: [],
    fn: (input) => {
      const e=shannonEntropy(input);
      const printable=(input.match(/[\x20-\x7e]/g)||[]).length;
      const freq={};
      for(const c of input){const h=c.charCodeAt(0).toString(16).padStart(2,'0');freq[h]=(freq[h]||0)+1;}
      const top=Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([h,n])=>`\\x${h}x${n}`).join('  ');
      return [`${tr('output_length')} : ${input.length} chars`,`${tr('output_entropy')} : ${e.toFixed(4)} bits/byte${e>5.5?`  ${tr('output_high')}`:''}`,`${tr('output_printable')} : ${printable}/${input.length} (${((printable/Math.max(input.length,1))*100).toFixed(1)}%)`,`${tr('output_top_bytes')} : ${top}`].join('\n');
    },
  },
  defangIoc: {
    label: tr('ops.defangIoc.label'), category: 'network', desc: tr('ops.defangIoc.desc'), params: [],
    fn: (input) => defangIoc(input),
  },
  refangIoc: {
    label: tr('ops.refangIoc.label'), category: 'network', desc: tr('ops.refangIoc.desc'), params: [],
    fn: (input) => refangIoc(input),
  },
  ipToDecimal: {
    label: tr('ops.ipToDecimal.label'), category: 'network', desc: tr('ops.ipToDecimal.desc'), params: [],
    fn: (input) => ipToDecimal(input),
  },
  decimalToIp: {
    label: tr('ops.decimalToIp.label'), category: 'network', desc: tr('ops.decimalToIp.desc'), params: [],
    fn: (input) => decimalToIp(input),
  },
  jwtDecode: {
    label: 'JWT Decode', category: 'specialized', desc: tr('ops.jwtDecode.desc'), params: [],
    fn: (input) => jwtDecode(input),
  },
  rot47: {
    label: 'ROT47', category: 'cipher', desc: tr('ops.rot47.desc'), params: [],
    fn: (input) => input.replace(/[\x21-\x7e]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94))),
  },
  crc32Hash: {
    label: 'CRC32', category: 'hash', desc: tr('ops.crc32Hash.desc'), params: [],
    fn: (input) => crc32(input),
  },
  toBase58: {
    label: tr('ops.toBase58.label'), category: 'encoding', desc: tr('ops.toBase58.desc'), params: [],
    fn: (input) => toBase58(input),
  },
  toCharcode: {
    label: tr('ops.toCharcode.label'), category: 'encoding', desc: tr('ops.toCharcode.desc'),
    params: [{ id:'base', label:tr('ops.toCharcode.param_base'), type:'select', options:[
      { value:'decimal', label:tr('options.decimal') },
      { value:'hex', label:tr('options.hex') },
      { value:'octal', label:tr('options.octal') },
    ], default:'decimal' }],
    fn: (input, {base='decimal'}={}) => { const radix=base==='hex'?16:base==='octal'?8:10; return Array.from(input).map(ch=>ch.charCodeAt(0).toString(radix)).join(' '); },
  },
  toHtmlEntity: {
    label: tr('ops.toHtmlEntity.label'), category: 'encoding', desc: tr('ops.toHtmlEntity.desc'), params: [],
    fn: (input) => toHtmlEntity(input),
  },
  encodeUtf16le: {
    label: tr('ops.encodeUtf16le.label'), category: 'encoding', desc: tr('ops.encodeUtf16le.desc'), params: [],
    fn: (input) => { let o=''; for (const c of input) { const code=c.charCodeAt(0); o+=String.fromCharCode(code&0xFF)+String.fromCharCode((code>>8)&0xFF); } return o; },
  },
  fromMorse: {
    label: tr('ops.fromMorse.label'), category: 'encoding', desc: tr('ops.fromMorse.desc'), params: [],
    fn: (input) => fromMorse(input),
  },
  toMorse: {
    label: tr('ops.toMorse.label'), category: 'encoding', desc: tr('ops.toMorse.desc'), params: [],
    fn: (input) => toMorse(input),
  },
  fromQuotedPrintable: {
    label: tr('ops.fromQuotedPrintable.label'), category: 'encoding', desc: tr('ops.fromQuotedPrintable.desc'), params: [],
    fn: (input) => fromQuotedPrintable(input),
  },
  toQuotedPrintable: {
    label: tr('ops.toQuotedPrintable.label'), category: 'encoding', desc: tr('ops.toQuotedPrintable.desc'), params: [],
    fn: (input) => toQuotedPrintable(input),
  },
  psCommandEncode: {
    label: 'PowerShell → EncodedCommand', category: 'specialized', desc: tr('ops.psCommandEncode.desc'), params: [],
    fn: (input) => { let u=''; for (const c of input) { const code=c.charCodeAt(0); u+=String.fromCharCode(code&0xFF)+String.fromCharCode((code>>8)&0xFF); } return btoa(u); },
  },
  dateToFiletime: {
    label: tr('ops.dateToFiletime.label'), category: 'timestamps', desc: tr('ops.dateToFiletime.desc'), params: [],
    fn: (input) => { const d=new Date(input.trim()); if (isNaN(d)) throw new Error(tr('errors.invalid_iso_date')); const ft=(BigInt(d.getTime())+11644473600000n)*10000n; return `${tr('output_filetime_dec')} : ${ft.toString()}\n${tr('output_filetime_hex')} : ${ft.toString(16).toUpperCase().padStart(16,'0')}`; },
  },

  // ─── Compression (PowerShell DeflateStream / GzipStream payloads) ───────────
  gunzip: {
    label: 'Gunzip', category: 'encoding',
    desc: 'Décompresse des octets Gzip (magic 1f 8b). Chaîner après "From Base64".',
    params: [], async: true,
    fn: async (input) => decompress(input, 'gzip'),
  },
  rawInflate: {
    label: 'Raw Inflate (DEFLATE)', category: 'encoding',
    desc: 'DEFLATE brut sans en-tête — produit par PowerShell IO.Compression.DeflateStream. Chaîner après "From Base64".',
    params: [], async: true,
    fn: async (input) => decompress(input, 'deflate-raw'),
  },
  zlibInflate: {
    label: 'Zlib Inflate', category: 'encoding',
    desc: 'Décompresse un flux zlib (en-tête 78 9c / 78 01 / 78 da). Chaîner après "From Base64".',
    params: [], async: true,
    fn: async (input) => decompress(input, 'deflate'),
  },

  // ─── Symmetric crypto ───────────────────────────────────────────────────────
  aesDecrypt: {
    label: 'AES Decrypt', category: 'cipher',
    desc: 'Déchiffre AES (CBC/GCM/CTR). Clé et IV en hex ou texte UTF-8. Entrée Base64 ou Hex.',
    params: [
      { id:'key', label:'Clé', type:'text', default:'' },
      { id:'iv', label:'IV / Nonce', type:'text', default:'' },
      { id:'mode', label:'Mode', type:'select', options:[
        { value:'CBC', label:'CBC' }, { value:'GCM', label:'GCM' }, { value:'CTR', label:'CTR' },
      ], default:'CBC' },
      { id:'inputFormat', label:'Entrée', type:'select', options:[
        { value:'base64', label:'Base64' }, { value:'hex', label:'Hex' },
      ], default:'base64' },
    ],
    async: true,
    fn: async (input, params) => aesDecrypt(input, params),
  },
  xorBruteForce: {
    label: 'XOR Brute-Force (1 octet)', category: 'cipher',
    desc: 'Teste les 256 clés XOR mono-octet et classe les résultats par qualité de décodage.',
    params: [],
    fn: (input) => xorBruteForce(input),
  },
  caesarBruteForce: {
    label: 'Caesar Brute-Force', category: 'cipher',
    desc: 'Affiche les 25 décalages ROT pour repérer le texte lisible.',
    params: [],
    fn: (input) => caesarBrute(input),
  },

  // ─── Encodings ──────────────────────────────────────────────────────────────
  fromBase85: {
    label: 'From Base85 (Ascii85)', category: 'encoding',
    desc: 'Décode Ascii85 / Base85 (avec ou sans délimiteurs <~ ~>).',
    params: [],
    fn: (input) => fromAscii85(input),
  },
  fromOctal: {
    label: 'From Octal', category: 'encoding',
    desc: 'Décode des échappements octaux \\NNN ou des nombres octaux séparés.',
    params: [],
    fn: (input) => fromOctal(input),
  },
  fromHexdump: {
    label: 'From Hexdump', category: 'encoding',
    desc: 'Reconstitue les octets depuis un hexdump (xxd, hexdump -C, Format-Hex).',
    params: [],
    fn: (input) => fromHexdump(input),
  },

  // ─── Microsoft Script Encoder ───────────────────────────────────────────────
  jscriptDecode: {
    label: 'JScript.Encode / VBE Decode', category: 'specialized',
    desc: 'Décode les scripts encodés Microsoft (#@~^…^#~@) — fichiers .jse / .vbe.',
    params: [],
    fn: (input) => decodeMsScript(input),
  },
};

const CATEGORY_KEYS = {
  specialized: 'cyberchef.categories.specialized',
  encoding: 'cyberchef.categories.encoding',
  hash: 'cyberchef.categories.hash',
  cipher: 'cyberchef.categories.cipher',
  network: 'cyberchef.categories.network',
  extraction: 'cyberchef.categories.extraction',
  timestamps: 'cyberchef.categories.timestamps',
  formatting: 'cyberchef.categories.formatting',
  info: 'cyberchef.categories.info',
};
const CATEGORIES = ['specialized', 'encoding', 'hash', 'cipher', 'network', 'extraction', 'timestamps', 'formatting', 'info'];
const CAT_COLOR = {
  specialized: 'var(--fl-danger)', encoding: 'var(--fl-accent)', hash: 'var(--fl-warn)',
  cipher: 'var(--fl-gold)', network: 'var(--fl-ok)', extraction: 'var(--fl-ok)', timestamps: 'var(--fl-purple)',
  formatting: 'var(--fl-purple)', info: 'var(--fl-dim)',
};

// ─── Auto-detect ──────────────────────────────────────────────────────────────

// Score how "clean" a decoded string looks — higher = more likely a true decode.
const QUALITY_KEYWORDS = /\b(https?|www|cmd|powershell|invoke|iex|function|select|insert|update|user|password|admin|token|true|false|null|var|const|return|the|and|for|with|system|windows|microsoft|program|file|path|script|host|error|enable|disable)\b/gi;
function decodeQuality(s) {
  if (!s || !s.length) return 0;
  const printable = (s.match(/[\x09\x0a\x0d\x20-\x7e]/g) || []).length / s.length;
  const kw = (s.match(QUALITY_KEYWORDS) || []).length;
  const ent = shannonEntropy(s);
  let q = printable * 68;
  q += Math.min(kw, 6) * 4.5;
  if (ent < 4.5) q += 6;            // structured / low-entropy text bonus
  if (printable < 0.7) q *= 0.5;    // mostly binary → probably a wrong decode
  return Math.max(0, Math.min(100, q));
}

function detectObfuscation(input) {
  if (!input || input.trim().length < 4) return [];
  const s = input.trim();
  const b64 = s.replace(/\s/g,'');
  const cand = [];   // { ops, label, color, base }

  // High-signal exact formats first.
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$/.test(s))
    cand.push({ ops:['jwtDecode'], label:'JSON Web Token (JWT)', color:'var(--fl-danger)', base:96 });
  if (/hxxps?|\[\.\]|\[:\/\/\]|\[@\]|\(dot\)|\(at\)/i.test(s))
    cand.push({ ops:['refangIoc'], label:'Defanged IOC', color:'var(--fl-ok)', base:92 });
  if (/#@~\^.{6}==[\s\S]+==\^#~@/.test(s))
    cand.push({ ops:['jscriptDecode'], label:'Microsoft Script Encoder (.jse/.vbe)', color:'var(--fl-danger)', base:97 });

  // Base64 family.
  if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(b64)) {
    try {
      const raw = atob(b64.replace(/-/g,'+').replace(/_/g,'/').padEnd(b64.length + ((4 - b64.length%4)%4), '='));
      const isUtf16 = raw.length>=4 && raw.charCodeAt(1)===0 && raw.charCodeAt(3)===0;
      if (isUtf16) cand.push({ ops:['psCommandDecode'], label:'PowerShell -EncodedCommand (Base64+UTF-16LE)', color:'var(--fl-danger)', base:95 });
      else cand.push({ ops:['fromBase64'], label:/[-_]/.test(b64)?'Base64 URL-safe':'Base64', color:'var(--fl-warn)', base:80 });
    } catch {}
  }
  if (/^[A-Z2-7]+=*$/.test(b64) && b64.length >= 8) cand.push({ ops:['fromBase32'], label:'Base32', color:'var(--fl-accent)', base:70 });
  if (/^[1-9A-HJ-NP-Za-km-z]{16,}$/.test(b64)) cand.push({ ops:['fromBase58'], label:'Base58 (BTC / key)', color:'var(--fl-purple)', base:60 });

  // Hex / escapes.
  if (/(?:\\x[0-9a-fA-F]{2}){3,}/.test(s)) cand.push({ ops:['fromHex'], label:'\\xAB sequences', color:'var(--fl-gold)', base:90 });
  const hexOnly = s.replace(/[\s,]/g,'');
  if (/^[0-9a-fA-F]+$/.test(hexOnly) && hexOnly.length%2===0 && hexOnly.length>=10) cand.push({ ops:['fromHex'], label:'Hex pur', color:'var(--fl-purple)', base:66 });
  if (/\\u[0-9a-fA-F]{4}/.test(s)) cand.push({ ops:['fromUnicodeEscape'], label:'Unicode \\uXXXX', color:'var(--fl-accent)', base:84 });

  // URL / HTML / char codes / binary / morse / quoted-printable.
  const urlCount = (s.match(/%[0-9A-Fa-f]{2}/g)||[]).length;
  if (urlCount>2 || (urlCount>0 && urlCount/s.length>0.05)) cand.push({ ops:['urlDecode'], label:'URL (%XX)', color:'var(--fl-accent)', base:85 });
  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(s)) cand.push({ ops:['fromHtmlEntity'], label:'HTML entities', color:'var(--fl-purple)', base:85 });
  if (/^\d+(?:\s*[,\s]\s*\d+){5,}$/.test(s)) cand.push({ ops:['fromCharcode'], label:'Character codes', color:'var(--fl-ok)', base:76 });
  if (/^[01]{8}(?:\s[01]{8})+$/.test(s)) cand.push({ ops:['fromBinary'], label:'Binaire 8 bits', color:'var(--fl-gold)', base:90 });
  if (/^[.\-]+(?:[ /][.\-]+)+$/.test(s)) cand.push({ ops:['fromMorse'], label:'Code Morse', color:'var(--fl-gold)', base:88 });
  if ((s.match(/=[0-9A-F]{2}/g)||[]).length > 1) cand.push({ ops:['fromQuotedPrintable'], label:'Quoted-Printable', color:'var(--fl-accent)', base:70 });
  if (/^<~/.test(s) || /[!-u]{20,}~>$/.test(s)) cand.push({ ops:['fromBase85'], label:'Ascii85 / Base85', color:'var(--fl-accent)', base:72 });
  if (/(?:\\[0-7]{2,3}){3,}/.test(s)) cand.push({ ops:['fromOctal'], label:'Échappements octaux \\NNN', color:'var(--fl-gold)', base:80 });

  // Compressed bytes pasted raw (magic header). Async ops — won't auto-chain via Magic.
  if (s.charCodeAt(0) === 0x1f && s.charCodeAt(1) === 0x8b) cand.push({ ops:['gunzip'], label:'Gzip (magic 1f 8b)', color:'var(--fl-danger)', base:88 });
  if (s.charCodeAt(0) === 0x78 && [0x01,0x9c,0xda].includes(s.charCodeAt(1))) cand.push({ ops:['zlibInflate'], label:'Zlib (en-tête 78)', color:'var(--fl-purple)', base:82 });
  if (/^\d{8,10}$/.test(s) && Number(s)>=16777216 && Number(s)<=4294967295) cand.push({ ops:['decimalToIp'], label:'Decimal IP', color:'var(--fl-ok)', base:50 });

  // Re-rank by the quality of the ACTUAL decode output (CyberChef "Magic" style).
  const results = [];
  for (const c of cand) {
    let out = s, ok = true;
    try {
      for (const opId of c.ops) {
        const op = OPS[opId];
        if (!op || op.async) { ok = false; break; }
        out = op.fn(out, Object.fromEntries((op.params||[]).map(p=>[p.id,p.default])));
      }
    } catch { ok = false; }
    let conf;
    if (ok && out && out !== s) {
      const q = decodeQuality(out);
      conf = Math.round(c.base*0.4 + q*0.6);
      const structural = ['refangIoc','decimalToIp','jwtDecode'].includes(c.ops[0]);
      if (q < 28 && !structural) conf = Math.round(conf*0.45);   // garbage decode → demote
    } else {
      conf = Math.round(c.base*0.5);
    }
    results.push({ confidence: Math.max(1, Math.min(99, conf)), ops:c.ops, label:c.label, color:c.color });
  }

  const e = shannonEntropy(s);
  if (e > 5.5 && results.every(r=>r.confidence<50)) results.push({ confidence:45, ops:['extractStrings'], label:`High entropy (${e.toFixed(2)} bits) — string extraction recommended`, color:'var(--fl-dim)' });

  // De-dup identical op-chains, keep the highest confidence.
  const seen = new Map();
  for (const r of results.sort((a,b)=>b.confidence-a.confidence)) {
    const key = r.ops.join('>'); if (!seen.has(key)) seen.set(key, r);
  }
  return [...seen.values()].sort((a,b)=>b.confidence-a.confidence);
}

// Magic: greedily peel decoding layers — apply the highest-confidence detection,
// re-detect on the result, repeat until nothing left or the output stabilises.
function magicChain(input) {
  const chain = [];
  const seen = new Set([input]);
  let cur = input;
  for (let depth = 0; depth < 6; depth++) {
    const det = detectObfuscation(cur);
    const best = det[0];
    if (!best || best.confidence < 60 || !best.ops.length) break;
    let out = cur;
    try {
      for (const opId of best.ops) {
        const op = OPS[opId];
        if (!op || op.async) { out = null; break; }
        out = op.fn(out, Object.fromEntries((op.params || []).map(p => [p.id, p.default])));
      }
    } catch { break; }
    if (out == null || out === cur || seen.has(out) || !out.length) break;
    seen.add(out);
    chain.push(...best.ops);
    cur = out;
  }
  return chain;
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

async function applyRecipe(input, recipe) {
  let current = input;
  const steps = [];
  for (const step of recipe) {
    const op = OPS[step.opId];
    if (!op) { steps.push({ opId:step.opId, output:current, error:'Unknown operation' }); continue; }
    try {
      const out = op.async ? await op.fn(current, step.params||{}) : op.fn(current, step.params||{});
      steps.push({ opId:step.opId, output:out, error:null });
      current = out;
    } catch(e) {
      steps.push({ opId:step.opId, output:current, error:e.message });
      break;
    }
  }
  return { final:current, steps };
}

// ─── React components ────────────────────────────────────────────────────────

const mono = { fontFamily:'var(--f-mono, "JetBrains Mono", monospace)' };

function OpBadge({ category }) {
  const labelKey = CATEGORY_KEYS[category] || category;
  return (
    <span style={{
      fontSize:8, padding:'0 5px', borderRadius:3,
      background:`color-mix(in srgb, ${CAT_COLOR[category]||'var(--fl-dim)'} 13%, transparent)`,
      color:CAT_COLOR[category]||'var(--fl-dim)',
      border:`1px solid color-mix(in srgb, ${CAT_COLOR[category]||'var(--fl-dim)'} 25%, transparent)`,
      ...mono, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.05em',
    }}>
      {resolveText(labelKey)}
    </span>
  );
}

function RecipeStep({ step, index, result, onRemove, onChange, onDragStart, onDragOver, onDrop, dragging }) {
  const op = OPS[step.opId];
  if (!op) return null;
  const [open, setOpen] = useState(false);
  const hasParams = op.params.length > 0;
  const out = result?.output;
  const err = result?.error;
  return (
    <div draggable
      onDragStart={e => onDragStart(e, index)}
      onDragOver={e => onDragOver(e, index)}
      onDrop={e => onDrop(e, index)}
      style={{ border:`1px solid ${err?'color-mix(in srgb, var(--fl-danger) 35%, transparent)':'var(--fl-border)'}`, borderRadius:5, marginBottom:4, background:'var(--fl-bg)', overflow:'hidden', opacity:dragging?0.4:1, transition:'opacity 0.12s' }}>
      <div
        style={{ display:'flex', alignItems:'center', gap:6, padding:'5px 8px', cursor:'pointer', borderBottom:open?'1px solid var(--fl-border)':'none' }}
        onClick={() => setOpen(o=>!o)}
      >
        <GripVertical size={11} style={{ color:'var(--fl-subtle)', flexShrink:0, cursor:'grab' }} onClick={e=>e.stopPropagation()} />
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0, minWidth:12 }}>{index+1}.</span>
        <span style={{ ...mono, fontSize:10, color:'var(--fl-on-dark)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{op.label}</span>
        {err && <AlertTriangle size={10} style={{ color:'var(--fl-danger)', flexShrink:0 }} />}
        <OpBadge category={op.category} />
        <ChevronDown size={10} style={{ color:'var(--fl-subtle)', transform:open?'rotate(180deg)':'none', transition:'transform 0.15s', flexShrink:0 }} />
        <button onClick={e=>{e.stopPropagation();onRemove(index);}} style={{ background:'none', border:'none', cursor:'pointer', padding:0, color:'var(--fl-subtle)', display:'flex', flexShrink:0 }}>
          <X size={10} />
        </button>
      </div>
      {open && (
        <div style={{ padding:'6px 8px', display:'flex', flexDirection:'column', gap:6 }}>
          {hasParams && op.params.map(p => (
            <div key={p.id} style={{ display:'flex', alignItems:'center', gap:6 }}>
              <label style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', minWidth:70 }}>{p.label}</label>
              {p.type==='select'?(
                <select value={step.params?.[p.id]??p.default} onChange={e=>onChange(index,p.id,e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 4px', flex:1 }}>
                  {p.options.map(o=><option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              ):(
                <input type={p.type==='number'?'number':'text'} value={step.params?.[p.id]??p.default} min={p.min} max={p.max}
                  onChange={e=>onChange(index,p.id,p.type==='number'?Number(e.target.value):e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 6px', flex:1, outline:'none' }} />
              )}
            </div>
          ))}
          {result && (
            <div>
              <div style={{ ...mono, fontSize:8, color:'var(--fl-subtle)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:3, display:'flex', justifyContent:'space-between', gap:8 }}>
                <span>{err ? 'Error' : 'Step output'}</span>
                {!err && out != null && <span>{out.length} chars · {shannonEntropy(out).toFixed(2)} bits</span>}
              </div>
              <div style={{ ...mono, fontSize:9, color:err?'var(--fl-danger)':'var(--fl-dim)', background:'var(--fl-panel)', border:`1px solid ${err?'color-mix(in srgb, var(--fl-danger) 25%, transparent)':'var(--fl-border)'}`, borderRadius:4, padding:'5px 7px', maxHeight:110, overflow:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all', scrollbarWidth:'thin' }}>
                {err ? err : ((out || '(vide)').slice(0,600) + (!err && out && out.length>600 ? '…' : ''))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CyberChefPage() {
  const [input, setInput] = useState('');
  const [recipe, setRecipe] = useState([]);
  const [result, setResult] = useState({ final:'', steps:[] });
  const [running, setRunning] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [pickerCat, setPickerCat] = useState('Specialized');
  const [pickerSearch, setPickerSearch] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [copied, setCopied] = useState(false);
  const [dragIndex, setDragIndex] = useState(null);

  useEffect(() => {
    if (!input || recipe.length === 0) { setResult({ final:input, steps:[] }); return; }
    let cancelled = false;
    setRunning(true);
    applyRecipe(input, recipe).then(r => { if(!cancelled){ setResult(r); setRunning(false); } });
    return () => { cancelled = true; };
  }, [input, recipe]);

  const { final:output, steps } = result;
  const lastError = steps.find(s => s.error);
  const entropy = input ? shannonEntropy(input).toFixed(2) : null;

  const handleDetect = useCallback(() => {
    const single = detectObfuscation(input);
    const chain = magicChain(input);
    const out = [];
    if (chain.length > 1) out.push({ confidence:99, ops:chain, label:'Chain: ' + chain.map(o=>OPS[o]?.label||o).join(' → '), color:'var(--fl-purple)' });
    out.push(...single);
    setSuggestions(out.length>0 ? out : [{ confidence:0, label:'No known obfuscation detected', color:'var(--fl-ok)', ops:[] }]);
  }, [input]);

  const applySuggestion = useCallback((ops) => {
    if (!ops.length) return;
    setRecipe(ops.map(opId => ({ opId, params:Object.fromEntries((OPS[opId]?.params||[]).map(p=>[p.id,p.default])) })));
    setSuggestions([]);
  }, []);

  // Magic — recursively peel decoding layers and load the resulting chain.
  const handleMagic = useCallback(() => {
    const chain = magicChain(input);
    if (chain.length) applySuggestion(chain);
    else setSuggestions([{ confidence:0, label:'Magic: no decodable layer detected', color:'var(--fl-dim)', ops:[] }]);
  }, [input, applySuggestion]);

  // Drag-to-reorder recipe steps.
  const onStepDragStart = useCallback((e, i) => { setDragIndex(i); e.dataTransfer.effectAllowed = 'move'; }, []);
  const onStepDragOver  = useCallback((e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; }, []);
  const onStepDrop = useCallback((e, i) => {
    e.preventDefault();
    setRecipe(r => {
      if (dragIndex == null || dragIndex === i || dragIndex >= r.length) return r;
      const next = [...r];
      const [moved] = next.splice(dragIndex, 1);
      next.splice(i, 0, moved);
      return next;
    });
    setDragIndex(null);
  }, [dragIndex]);

  const addOp = useCallback((opId) => {
    const op = OPS[opId];
    setRecipe(r => [...r, { opId, params:Object.fromEntries((op.params||[]).map(p=>[p.id,p.default])) }]);
    setShowPicker(false);
    setPickerSearch('');
  }, []);

  const removeOp = useCallback((i) => setRecipe(r => r.filter((_,idx)=>idx!==i)), []);
  const changeParam = useCallback((si,pid,val) => setRecipe(r=>r.map((s,i)=>i===si?{...s,params:{...s.params,[pid]:val}}:s)), []);

  const copyOutput = useCallback(() => {
    if (!output) return;
    navigator.clipboard.writeText(output).then(()=>{ setCopied(true); setTimeout(()=>setCopied(false),1500); });
  }, [output]);

  const filteredOps = Object.entries(OPS).filter(([id, op]) => {
    if (pickerSearch) {
      const q = pickerSearch.toLowerCase();
      return op.label.toLowerCase().includes(q) || op.desc.toLowerCase().includes(q) || op.category.toLowerCase().includes(q);
    }
    return op.category === pickerCat;
  });

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:'var(--fl-bg)', overflow:'hidden' }}>

      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'0 14px', height:36, flexShrink:0, background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)' }}>
        <FlaskConical size={13} style={{ color:'var(--fl-accent)' }} />
        <span style={{ ...mono, fontSize:11, color:'var(--fl-on-dark)', fontWeight:700 }}>CyberChef Forensic</span>
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)' }}>— {Object.keys(OPS).length} operations</span>
        <div style={{ flex:1 }} />
        {running && <span style={{ ...mono, fontSize:9, color:'var(--fl-warn)' }}>⟳ calcul…</span>}
        <button onClick={handleMagic} disabled={!input} title="Magic — recursively decodes detected obfuscation layers"
          style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-purple) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-purple) 40%, transparent)', color:'var(--fl-purple)', cursor:input?'pointer':'default', opacity:input?1:0.5, ...mono, fontSize:10 }}>
          <Sparkles size={10} /> Magic
        </button>
        <button onClick={handleDetect} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:10 }}>
          <Wand2 size={10} /> Auto-detect
        </button>
        <button onClick={()=>{setRecipe([]);setInput('');setSuggestions([]);}} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'none', border:'1px solid var(--fl-border)', color:'var(--fl-subtle)', cursor:'pointer', ...mono, fontSize:10 }}>
          <RotateCcw size={10} /> Reset
        </button>
      </div>

      {suggestions.length>0 && (
        <div style={{ padding:'5px 14px', background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
          <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0 }}>DETECTION :</span>
          {suggestions.map((s,i)=>(
            <button key={i} onClick={()=>s.ops.length>0&&applySuggestion(s.ops)}
              style={{ display:'flex', alignItems:'center', gap:5, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:`color-mix(in srgb, ${s.color} 8%, transparent)`, border:`1px solid color-mix(in srgb, ${s.color} 25%, transparent)`, color:s.color, cursor:s.ops.length>0?'pointer':'default', ...mono, fontSize:9 }}>
              {s.confidence>0&&<span style={{ opacity:0.55 }}>{s.confidence}%</span>}
              {s.label}
              {s.ops.length>0&&<ChevronRight size={9} />}
            </button>
          ))}
          <button onClick={()=>setSuggestions([])} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--fl-subtle)', marginLeft:'auto', display:'flex' }}><X size={10} /></button>
        </div>
      )}

      <div style={{ display:'flex', flex:1, minHeight:0, overflow:'hidden' }}>

        <div style={{ width:250, flexShrink:0, display:'flex', flexDirection:'column', borderRight:'1px solid var(--fl-border)', background:'var(--fl-bg)', overflow:'hidden' }}>
          <div style={{ padding:'6px 10px', borderBottom:'1px solid var(--fl-border)', display:'flex', alignItems:'center', justifyContent:'space-between', flexShrink:0 }}>
            <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
              Recipe · {recipe.length} step{recipe.length!==1?'s':''}
            </span>
            <button onClick={()=>setShowPicker(p=>!p)} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 7px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:9 }}>
              <Plus size={9} /> Ajouter
            </button>
          </div>

          {showPicker && (
            <div style={{ background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', flexShrink:0 }}>
              <div style={{ padding:'4px 8px', borderBottom:'1px solid var(--fl-border)' }}>
                <input value={pickerSearch} onChange={e=>setPickerSearch(e.target.value)} placeholder="Search for an operation…"
                  style={{ width:'100%', boxSizing:'border-box', ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:'var(--fl-radius-sm)', padding:'3px 6px', outline:'none' }} />
              </div>
              {!pickerSearch && (
                <div style={{ display:'flex', overflowX:'auto', scrollbarWidth:'none', padding:'4px 6px', gap:3, borderBottom:'1px solid var(--fl-border)' }}>
                  {CATEGORIES.map(cat=>(
                    <button key={cat} onClick={()=>setPickerCat(cat)} style={{ flexShrink:0, padding:'2px 6px', borderRadius:'var(--fl-radius-sm)', cursor:'pointer', ...mono, fontSize:8, background:pickerCat===cat?`color-mix(in srgb, ${CAT_COLOR[cat]} 13%, transparent)`:'none', border:`1px solid ${pickerCat===cat?CAT_COLOR[cat]+'60':'transparent'}`, color:pickerCat===cat?CAT_COLOR[cat]:'var(--fl-subtle)' }}>
                      {cat}
                    </button>
                  ))}
                </div>
              )}
              <div style={{ maxHeight:220, overflowY:'auto', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
                {filteredOps.length===0
                  ? <div style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', padding:'10px', textAlign:'center' }}>No operation found</div>
                  : filteredOps.map(([id,op])=>(
                    <button key={id} onClick={()=>addOp(id)} style={{ display:'block', width:'100%', textAlign:'left', padding:'5px 10px', background:'none', border:'none', borderBottom:'1px solid var(--fl-border)', cursor:'pointer', ...mono, fontSize:9, color:'var(--fl-on-dark)' }}
                      onMouseEnter={e=>{e.currentTarget.style.background='var(--fl-panel)';}}
                      onMouseLeave={e=>{e.currentTarget.style.background='none';}}>
                      <div style={{ display:'flex', alignItems:'center', gap:4, marginBottom:2 }}>
                        <span style={{ fontWeight:700, flex:1 }}>{op.label}</span>
                        <OpBadge category={op.category} />
                      </div>
                      <div style={{ fontSize:8, color:'var(--fl-subtle)' }}>{op.desc}</div>
                    </button>
                  ))
                }
              </div>
            </div>
          )}

          <div style={{ flex:1, overflowY:'auto', padding:'6px 8px', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
            {recipe.length===0?(
              <div style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', textAlign:'center', marginTop:28, lineHeight:1.9 }}>
                Click "Add" to<br />build a recipe<br /><br />— or —<br /><br />Paste a payload and<br />run <span style={{ color:'var(--fl-purple)' }}>Magic</span> 🪄<br /><br /><span style={{ fontSize:8, opacity:0.7 }}>Drag steps to reorder them.<br />Expand a step to see its output.</span>
              </div>
            ):(
              recipe.map((step,i)=>(
                <RecipeStep key={i} step={step} index={i} result={steps[i]} onRemove={removeOp} onChange={changeParam}
                  onDragStart={onStepDragStart} onDragOver={onStepDragOver} onDrop={onStepDrop} dragging={dragIndex===i} />
              ))
            )}
          </div>

          {recipe.length>0&&(
            <div style={{ padding:'5px 8px', borderTop:'1px solid var(--fl-border)', flexShrink:0 }}>
              {lastError?(
                <div style={{ display:'flex', alignItems:'flex-start', gap:4 }}>
                  <AlertTriangle size={9} style={{ color:'var(--fl-danger)', flexShrink:0, marginTop:1 }} />
                  <span style={{ ...mono, fontSize:8, color:'var(--fl-danger)', wordBreak:'break-all' }}>{lastError.error}</span>
                </div>
              ):(
                <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <Play size={9} style={{ color:'var(--fl-ok)' }} />
                  <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)' }}>Auto-run</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0, overflow:'hidden' }}>
          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0, borderBottom:'2px solid var(--fl-border)' }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-accent)', textTransform:'uppercase', letterSpacing:'0.1em', fontWeight:700 }}>Input</span>
              {input&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{input.length} chars · entropie {entropy} bits{''}</span>}
              {input&&parseFloat(entropy)>5.5&&<span style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-danger) 12%, transparent)', color:'var(--fl-danger)', border:'1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)' }}>High entropy</span>}
            </div>
            <textarea value={input} onChange={e=>setInput(e.target.value)}
              placeholder={'Paste the payload to analyze…\n\nThe recipe applies automatically.\nUse "Auto-detect" for a suggestion.'}
              spellCheck={false}
              style={{ flex:1, resize:'none', outline:'none', background:'var(--fl-bg)', color:'var(--fl-on-dark)', border:'none', padding:'10px 14px', ...mono, fontSize:11, lineHeight:1.6, scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }} />
          </div>

          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0 }}>
            <div style={{ display:'flex', alignItems:'center', gap:6, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)', flexWrap:'wrap' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)', textTransform:'uppercase', letterSpacing:'0.1em', fontWeight:700 }}>Output</span>
              {output&&output!==input&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{output.length} chars</span>}
              <div style={{ flex:1 }} />
              {steps.map((s,i)=>(
                <span key={i} style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:s.error?'color-mix(in srgb, var(--fl-danger) 12%, transparent)':'color-mix(in srgb, var(--fl-ok) 12%, transparent)', color:s.error?'var(--fl-danger)':'var(--fl-ok)', border:`1px solid ${s.error?'color-mix(in srgb, var(--fl-danger) 30%, transparent)':'color-mix(in srgb, var(--fl-ok) 30%, transparent)'}` }}>
                  {i+1}. {OPS[s.opId]?.label??s.opId}{s.error?' ✗':' ✓'}
                </span>
              ))}
              <button onClick={copyOutput} disabled={!output} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:copied?'color-mix(in srgb, var(--fl-ok) 15%, transparent)':'none', border:`1px solid ${copied?'color-mix(in srgb, var(--fl-ok) 40%, transparent)':'var(--fl-border)'}`, color:copied?'var(--fl-ok)':'var(--fl-subtle)', cursor:output?'pointer':'default', ...mono, fontSize:9, transition:'all 0.2s' }}>
                <Copy size={9} /> {copied?'Copied!':'Copy'}
              </button>
            </div>
            <div style={{ flex:1, overflowY:'auto', background:'var(--fl-bg)', padding:'10px 14px', ...mono, fontSize:11, color:lastError?'var(--fl-danger)':'var(--fl-on-dark)', lineHeight:1.6, whiteSpace:'pre-wrap', wordBreak:'break-all', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
              {recipe.length===0
                ? <span style={{ color:'var(--fl-subtle)' }}>The output will appear here once the recipe is built…</span>
                : (output||<span style={{ color:'var(--fl-subtle)' }}>(sortie vide)</span>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
