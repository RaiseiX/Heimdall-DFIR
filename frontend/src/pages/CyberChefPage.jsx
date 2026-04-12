
import { useState, useEffect, useCallback } from 'react';
import {
  FlaskConical, Wand2, Plus, X, ChevronDown, Copy,
  AlertTriangle, Play, RotateCcw, ChevronRight,
} from 'lucide-react';

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
  for (const c of s) {
    const i = BASE32_CHARS.indexOf(c);
    if (i < 0) throw new Error(`Caractère Base32 invalide : ${c}`);
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
  for (const c of s) {
    const idx = B58.indexOf(c);
    if (idx < 0) throw new Error(`Caractère Base58 invalide : ${c}`);
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
  if (!key) throw new Error('Clé vide');
  const k = key.toUpperCase().replace(/[^A-Z]/g,'');
  if (!k) throw new Error('La clé doit contenir des lettres');
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
  if (isNaN(d)) throw new Error('FILETIME invalide');
  return [
    `UTC : ${d.toISOString()}`,
    `Local : ${d.toLocaleString()}`,
    `Unix : ${Math.floor(Number(ms)/1000)}`,
    `Valeur brute : ${ft.toString()} (100ns intervals depuis 1601-01-01)`,
  ].join('\n');
}

function unixToDate(input) {
  const s = input.trim();
  let ts = parseInt(s);
  if (isNaN(ts)) throw new Error('Timestamp invalide');
  if (s.length === 13) ts = ts;
  else ts = ts * 1000;
  const d = new Date(ts);
  const ft = (BigInt(ts) + 11644473600000n) * 10000n;
  return [
    `UTC : ${d.toISOString()}`,
    `Local : ${d.toLocaleString()}`,
    `FILETIME : ${ft.toString()}`,
  ].join('\n');
}

function prettifyJson(input) {
  try { return JSON.stringify(JSON.parse(input), null, 2); }
  catch (e) { throw new Error('JSON invalide — ' + e.message); }
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

// ─── Operations ──────────────────────────────────────────────────────────────

const OPS = {
  psCommandDecode: {
    label: 'PowerShell -EncodedCommand', category: 'Spécialisé',
    desc: 'Base64 → UTF-16LE (commandes PS obfusquées)',
    params: [],
    fn: (input) => {
      const s = input.trim().replace(/\s/g,''), raw = atob(s), bytes = Array.from(raw).map(c=>c.charCodeAt(0)), out=[];
      for(let i=0;i+1<bytes.length;i+=2){const code=bytes[i]|(bytes[i+1]<<8);if(code>0)out.push(String.fromCharCode(code));}
      return out.join('');
    },
  },
  fromBase64: {
    label: 'Depuis Base64', category: 'Encodage',
    desc: 'Décode une chaîne Base64 standard ou URL-safe',
    params: [{ id:'alphabet', label:'Alphabet', type:'select', options:['Standard (+/)','URL-safe (-_)'], default:'Standard (+/)' }],
    fn: (input, {alphabet='Standard (+/)'}={}) => {
      let s = input.trim().replace(/\s/g,'');
      if (alphabet==='URL-safe (-_)') s=s.replace(/-/g,'+').replace(/_/g,'/');
      try { return atob(s); } catch(e) { throw new Error('Base64 invalide — '+e.message); }
    },
  },
  toBase64: {
    label: 'Vers Base64', category: 'Encodage', desc: 'Encode en Base64', params: [],
    fn: (input) => { try{return btoa(input);}catch{return btoa(unescape(encodeURIComponent(input)));} },
  },
  fromBase32: {
    label: 'Depuis Base32', category: 'Encodage', desc: 'Décode une chaîne Base32 (RFC 4648)', params: [],
    fn: (input) => fromBase32(input),
  },
  toBase32: {
    label: 'Vers Base32', category: 'Encodage', desc: 'Encode en Base32 (RFC 4648)', params: [],
    fn: (input) => toBase32(input),
  },
  fromBase58: {
    label: 'Depuis Base58', category: 'Encodage', desc: 'Décode Base58 (adresses Bitcoin, clés)', params: [],
    fn: (input) => fromBase58(input),
  },
  fromHex: {
    label: 'Depuis Hex', category: 'Encodage', desc: 'Hex (4142, \\x41, 0x41) → texte brut', params: [],
    fn: (input) => {
      let s=input.trim().replace(/0x/gi,'').replace(/\\x/gi,'').replace(/[,\s]+/g,'');
      if(!/^[0-9a-fA-F]+$/.test(s)) throw new Error('Hex invalide');
      if(s.length%2!==0) s='0'+s;
      let r=''; for(let i=0;i<s.length;i+=2) r+=String.fromCharCode(parseInt(s.substr(i,2),16)); return r;
    },
  },
  toHex: {
    label: 'Vers Hex', category: 'Encodage', desc: 'Texte → hexadécimal',
    params: [{ id:'sep', label:'Séparateur', type:'select', options:['Espace','Aucun','\\x','0x'], default:'Espace' }],
    fn: (input, {sep='Espace'}={}) => Array.from(input).map(c=>{const h=c.charCodeAt(0).toString(16).padStart(2,'0');return sep==='\\x'?'\\x'+h:sep==='0x'?'0x'+h:h;}).join(sep==='Espace'?' ':''),
  },
  fromBinary: {
    label: 'Depuis Binaire', category: 'Encodage', desc: '01000001 01000010 → texte', params: [],
    fn: (input) => {
      const chunks = input.trim().replace(/\s+/g,' ').split(' ');
      if(chunks.some(c=>!/^[01]{8}$/.test(c))) throw new Error('Format attendu : octets 8 bits séparés par espace');
      return chunks.map(c=>String.fromCharCode(parseInt(c,2))).join('');
    },
  },
  toBinary: {
    label: 'Vers Binaire', category: 'Encodage', desc: 'Texte → représentation binaire 8 bits', params: [],
    fn: (input) => Array.from(input).map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '),
  },
  fromUnicodeEscape: {
    label: 'Depuis Unicode Escape', category: 'Encodage', desc: '\\u0041 \\u0042 → AB (JS/Python obfuscation)', params: [],
    fn: (input) => input.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  },
  toUnicodeEscape: {
    label: 'Vers Unicode Escape', category: 'Encodage', desc: 'Encode en \\uXXXX', params: [],
    fn: (input) => Array.from(input).map(c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join(''),
  },
  urlDecode: {
    label: 'Décodage URL', category: 'Encodage', desc: 'Décode %XX et + → espace', params: [],
    fn: (input) => { try{return decodeURIComponent(input.replace(/\+/g,' '));}catch{return unescape(input);} },
  },
  urlEncode: {
    label: 'Encodage URL', category: 'Encodage', desc: 'Encode en %XX', params: [],
    fn: (input) => encodeURIComponent(input),
  },
  fromHtmlEntity: {
    label: 'Depuis Entités HTML', category: 'Encodage', desc: 'Décode &amp; &#65; &#x41; etc.', params: [],
    fn: (input) => decodeHtmlEntities(input),
  },
  fromCharcode: {
    label: 'Depuis Codes Char', category: 'Encodage', desc: 'Codes décimaux/hex/octal → texte',
    params: [{ id:'base', label:'Base', type:'select', options:['Décimal','Hexadécimal','Octal'], default:'Décimal' }],
    fn: (input, {base='Décimal'}={}) => {
      const radix=base==='Hexadécimal'?16:base==='Octal'?8:10;
      const codes=input.trim().split(/[\s,]+/).map(s=>parseInt(s,radix));
      if(codes.some(isNaN)) throw new Error('Codes invalides pour la base '+base);
      return codes.map(c=>String.fromCharCode(c)).join('');
    },
  },
  decodeUtf16le: {
    label: 'UTF-16LE → Texte', category: 'Encodage', desc: 'Interprète les octets comme UTF-16 Little Endian', params: [],
    fn: (input) => {
      const bytes=Array.from(input).map(c=>c.charCodeAt(0)), out=[];
      for(let i=0;i+1<bytes.length;i+=2){const code=bytes[i]|(bytes[i+1]<<8);if(code>0)out.push(String.fromCharCode(code));}
      return out.join('');
    },
  },
  md5Hash: {
    label: 'MD5', category: 'Hash', desc: 'Calcule le hash MD5 (32 hex)', params: [],
    fn: (input) => md5(input),
  },
  sha1Hash: {
    label: 'SHA-1', category: 'Hash', desc: 'Calcule le hash SHA-1 (40 hex)', params: [],
    async: true,
    fn: async (input) => sha('SHA-1', input),
  },
  sha256Hash: {
    label: 'SHA-256', category: 'Hash', desc: 'Calcule le hash SHA-256 (64 hex)', params: [],
    async: true,
    fn: async (input) => sha('SHA-256', input),
  },
  sha512Hash: {
    label: 'SHA-512', category: 'Hash', desc: 'Calcule le hash SHA-512 (128 hex)', params: [],
    async: true,
    fn: async (input) => sha('SHA-512', input),
  },
  ntlmHash: {
    label: 'NTLM (MD4)', category: 'Hash', desc: 'Hash NTLM d\'un mot de passe (MD4 de UTF-16LE)', params: [],
    fn: (input) => ntlm(input),
  },
  rot13: {
    label: 'ROT13 / César', category: 'Chiffrement', desc: 'Décalage alphabétique (ROT13 par défaut)',
    params: [{ id:'amount', label:'Décalage', type:'number', default:13, min:1, max:25 }],
    fn: (input, {amount=13}={}) => input.replace(/[a-zA-Z]/g, c=>{const base=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-base+Number(amount))%26+base);}),
  },
  atbash: {
    label: 'Atbash', category: 'Chiffrement', desc: 'Chiffrement miroir alphabétique (A↔Z, B↔Y…)', params: [],
    fn: (input) => input.replace(/[a-zA-Z]/g, c=>{const base=c<='Z'?65:97;return String.fromCharCode(base+25-(c.charCodeAt(0)-base));}),
  },
  vigenereDecode: {
    label: 'Vigenère (déchiffrer)', category: 'Chiffrement', desc: 'Déchiffre avec clé alphabétique',
    params: [{ id:'key', label:'Clé', type:'text', default:'SECRET' }],
    fn: (input, {key='SECRET'}={}) => vigenere(input, key, true),
  },
  vigenereEncode: {
    label: 'Vigenère (chiffrer)', category: 'Chiffrement', desc: 'Chiffre avec clé alphabétique',
    params: [{ id:'key', label:'Clé', type:'text', default:'SECRET' }],
    fn: (input, {key='SECRET'}={}) => vigenere(input, key, false),
  },
  xorDecode: {
    label: 'XOR (1 octet)', category: 'Chiffrement', desc: 'XOR avec une clé sur un octet (ex: 0x41)',
    params: [{ id:'key', label:'Clé hex', type:'text', default:'0x41' }],
    fn: (input, {key='0x41'}={}) => {
      const k=parseInt(key,16); if(isNaN(k)) throw new Error('Clé invalide (0x41)');
      return Array.from(input).map(c=>String.fromCharCode(c.charCodeAt(0)^k)).join('');
    },
  },
  xorMultibyte: {
    label: 'XOR (multi-octets)', category: 'Chiffrement', desc: 'XOR avec clé de plusieurs octets (ex: deadbeef)',
    params: [{ id:'key', label:'Clé hex', type:'text', default:'deadbeef' }],
    fn: (input, {key='deadbeef'}={}) => {
      const k=key.replace(/0x|\\x|\s/gi,'');
      if(!/^[0-9a-fA-F]+$/.test(k)||k.length%2!==0) throw new Error('Clé hex invalide (ex: deadbeef)');
      const keyBytes=Array.from({length:k.length/2},(_,i)=>parseInt(k.slice(i*2,i*2+2),16));
      return Array.from(input).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^keyBytes[i%keyBytes.length])).join('');
    },
  },
  rc4Decode: {
    label: 'RC4', category: 'Chiffrement', desc: 'Chiffrement/déchiffrement RC4 (symétrique)',
    params: [{ id:'key', label:'Clé (texte)', type:'text', default:'secret' }],
    fn: (input, {key='secret'}={}) => { if(!key) throw new Error('Clé vide'); return rc4(input, key); },
  },
  reverseString: {
    label: 'Inverser', category: 'Formatage', desc: 'Inverse la chaîne (par caractère, ligne ou mot)',
    params: [{ id:'by', label:'Inverser par', type:'select', options:['Caractère','Ligne','Mot'], default:'Caractère' }],
    fn: (input, {by='Caractère'}={}) => by==='Ligne'?input.split('\n').reverse().join('\n'):by==='Mot'?input.split(/\s+/).reverse().join(' '):[...input].reverse().join(''),
  },
  stripNulls: {
    label: 'Supprimer Null Bytes', category: 'Formatage', desc: 'Supprime tous les octets nuls (\\x00)', params: [],
    fn: (input) => input.replace(/\x00/g,''),
  },
  jsonPrettify: {
    label: 'JSON Prettify', category: 'Formatage', desc: 'Formate un JSON compressé en lisible', params: [],
    fn: (input) => prettifyJson(input),
  },
  jsonMinify: {
    label: 'JSON Minify', category: 'Formatage', desc: 'Compresse un JSON en une seule ligne', params: [],
    fn: (input) => { try{return JSON.stringify(JSON.parse(input));}catch(e){throw new Error('JSON invalide — '+e.message);} },
  },
  xmlPrettify: {
    label: 'XML Prettify', category: 'Formatage', desc: 'Indente le XML/HTML', params: [],
    fn: (input) => prettifyXml(input),
  },
  toUpper: {
    label: 'MAJUSCULES', category: 'Formatage', desc: 'Convertit en majuscules', params: [],
    fn: (input) => input.toUpperCase(),
  },
  toLower: {
    label: 'minuscules', category: 'Formatage', desc: 'Convertit en minuscules', params: [],
    fn: (input) => input.toLowerCase(),
  },
  sortLines: {
    label: 'Trier les lignes', category: 'Formatage', desc: 'Trie les lignes alphabétiquement',
    params: [{ id:'order', label:'Ordre', type:'select', options:['Croissant','Décroissant'], default:'Croissant' }],
    fn: (input, {order='Croissant'}={}) => { const l=input.split('\n').sort(); return order==='Décroissant'?l.reverse().join('\n'):l.join('\n'); },
  },
  removeDuplicates: {
    label: 'Supprimer doublons', category: 'Formatage', desc: 'Supprime les lignes dupliquées', params: [],
    fn: (input) => [...new Set(input.split('\n'))].join('\n'),
  },
  removeBlankLines: {
    label: 'Supprimer lignes vides', category: 'Formatage', desc: 'Supprime toutes les lignes vides', params: [],
    fn: (input) => input.split('\n').filter(l=>l.trim()).join('\n'),
  },
  extractStrings: {
    label: 'Extraire Chaînes', category: 'Extraction', desc: 'Extrait les chaînes imprimables (comme strings)',
    params: [{ id:'minLen', label:'Longueur min', type:'number', default:4, min:1, max:100 }],
    fn: (input, {minLen=4}={}) => { const re=new RegExp(`[\\x20-\\x7e]{${minLen},}`,'g'); return(input.match(re)||[]).join('\n')||'(aucune chaîne trouvée)'; },
  },
  extractUrls: {
    label: 'Extraire URLs', category: 'Extraction', desc: 'Extrait toutes les URLs http(s)://', params: [],
    fn: (input) => (input.match(/https?:\/\/[^\s"'<>)\]]+/g)||[]).join('\n')||'(aucune URL)',
  },
  extractIps: {
    label: 'Extraire IPs', category: 'Extraction', desc: 'Extrait toutes les adresses IPv4 (et IPv6)', params: [],
    fn: (input) => {
      const v4=(input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]);
      const v6=(input.match(/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g)||[]);
      return [...new Set([...v4,...v6])].join('\n')||'(aucune IP)';
    },
  },
  extractEmails: {
    label: 'Extraire Emails', category: 'Extraction', desc: 'Extrait toutes les adresses email', params: [],
    fn: (input) => (input.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[]).join('\n')||'(aucun email)',
  },
  extractDomains: {
    label: 'Extraire Domaines', category: 'Extraction', desc: 'Extrait les noms de domaine (FQDN)', params: [],
    fn: (input) => {
      const re=/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|fr|de|uk|ru|cn|info|biz|xyz|onion|local|internal|corp)\b/gi;
      return [...new Set(input.match(re)||[])].join('\n')||'(aucun domaine)';
    },
  },
  extractHashes: {
    label: 'Extraire Hashes', category: 'Extraction', desc: 'Extrait les hashes MD5/SHA1/SHA256 (32/40/64 hex)', params: [],
    fn: (input) => {
      const md5m=(input.match(/\b[0-9a-fA-F]{32}\b/g)||[]);
      const sha1m=(input.match(/\b[0-9a-fA-F]{40}\b/g)||[]);
      const sha256m=(input.match(/\b[0-9a-fA-F]{64}\b/g)||[]);
      const lines=[];
      if(md5m.length) lines.push(`MD5 (${md5m.length}):\n`+[...new Set(md5m)].join('\n'));
      if(sha1m.length) lines.push(`SHA-1 (${sha1m.length}):\n`+[...new Set(sha1m)].join('\n'));
      if(sha256m.length) lines.push(`SHA-256 (${sha256m.length}):\n`+[...new Set(sha256m)].join('\n'));
      return lines.join('\n\n')||'(aucun hash trouvé)';
    },
  },
  extractWinPaths: {
    label: 'Extraire Chemins Windows', category: 'Extraction', desc: 'Extrait C:\\... HKLM\\... UNC paths', params: [],
    fn: (input) => {
      const re=/(?:[A-Za-z]:\\|\\\\)[^\s"'<>|*?\x00-\x1f]+/g;
      return [...new Set(input.match(re)||[])].join('\n')||'(aucun chemin Windows)';
    },
  },
  extractLinuxPaths: {
    label: 'Extraire Chemins Linux', category: 'Extraction', desc: 'Extrait /etc/ /tmp/ /var/ /home/ /proc/ etc.', params: [],
    fn: (input) => {
      const re=/(?:\/(?:etc|tmp|var|home|usr|opt|proc|sys|dev|run|lib|bin|sbin|boot|root|srv)(?:\/[^\s"'<>|*?\x00-\x1f]*)?)/g;
      return [...new Set(input.match(re)||[])].join('\n')||'(aucun chemin Linux)';
    },
  },
  extractGuids: {
    label: 'Extraire GUIDs / CLSIDs', category: 'Extraction', desc: 'Extrait les GUIDs au format {xxxxxxxx-xxxx-…}', params: [],
    fn: (input) => {
      const re=/\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?/g;
      return [...new Set(input.match(re)||[])].join('\n')||'(aucun GUID)';
    },
  },
  regexExtract: {
    label: 'Extraction Regex', category: 'Extraction', desc: 'Extrait les correspondances d\'un pattern regex',
    params: [
      { id:'pattern', label:'Pattern', type:'text', default:'[A-Za-z0-9+/=]{20,}' },
      { id:'flags', label:'Flags', type:'text', default:'g' },
    ],
    fn: (input, {pattern='[A-Za-z0-9+/=]{20,}',flags='g'}={}) => {
      try{return(input.match(new RegExp(pattern,flags))||[]).join('\n')||'(aucun résultat)';}
      catch(e){throw new Error('Regex invalide — '+e.message);}
    },
  },
  filetimeConvert: {
    label: 'FILETIME → Date', category: 'Timestamps', desc: 'Convertit un FILETIME Windows (100ns depuis 1601) en date lisible',
    params: [],
    fn: (input) => filetimeToDate(input),
  },
  unixConvert: {
    label: 'Unix Timestamp → Date', category: 'Timestamps', desc: 'Convertit un timestamp Unix (s ou ms) en date lisible',
    params: [],
    fn: (input) => unixToDate(input),
  },
  dateToUnix: {
    label: 'Date → Unix Timestamp', category: 'Timestamps', desc: 'Convertit une date ISO 8601 en timestamp Unix',
    params: [],
    fn: (input) => {
      const d=new Date(input.trim()); if(isNaN(d)) throw new Error('Date invalide (format ISO 8601 attendu)');
      return `Unix (s) : ${Math.floor(d.getTime()/1000)}\nUnix (ms) : ${d.getTime()}\nISO : ${d.toISOString()}`;
    },
  },
  countChars: {
    label: 'Statistiques', category: 'Info', desc: 'Longueur, entropie, bytes fréquents', params: [],
    fn: (input) => {
      const e=shannonEntropy(input);
      const printable=(input.match(/[\x20-\x7e]/g)||[]).length;
      const freq={};
      for(const c of input){const h=c.charCodeAt(0).toString(16).padStart(2,'0');freq[h]=(freq[h]||0)+1;}
      const top=Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([h,n])=>`\\x${h}×${n}`).join('  ');
      return [`Longueur : ${input.length} chars`,`Entropie : ${e.toFixed(4)} bits/byte${e>5.5?'  ⚠ élevée':''}`,`Imprimable : ${printable}/${input.length} (${((printable/Math.max(input.length,1))*100).toFixed(1)}%)`,`Top bytes : ${top}`].join('\n');
    },
  },
};

const CATEGORIES = ['Spécialisé', 'Encodage', 'Hash', 'Chiffrement', 'Extraction', 'Timestamps', 'Formatage', 'Info'];
const CAT_COLOR = {
  Spécialisé: 'var(--fl-danger)', Encodage: 'var(--fl-accent)', Hash: '#f59e0b',
  Chiffrement: 'var(--fl-gold)', Extraction: '#22c55e', Timestamps: '#06b6d4',
  Formatage: 'var(--fl-purple)', Info: 'var(--fl-dim)',
};

// ─── Auto-detect ──────────────────────────────────────────────────────────────

function detectObfuscation(input) {
  if (!input || input.trim().length < 4) return [];
  const s = input.trim();
  const results = [];
  const b64 = s.replace(/\s/g,'');
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(b64)) {
    try {
      const raw = atob(b64);
      const isUtf16 = raw.length>=4 && raw.charCodeAt(1)===0 && raw.charCodeAt(3)===0;
      if (isUtf16) results.push({ confidence:97, ops:['psCommandDecode'], label:'PowerShell -EncodedCommand (Base64+UTF-16LE)', color:'var(--fl-danger)' });
      else results.push({ confidence:87, ops:['fromBase64'], label:'Base64 encodé', color:'var(--fl-warn)' });
    } catch {}
  }
  if (/^[A-Z2-7]+=*$/.test(b64) && b64.length >= 8) results.push({ confidence:75, ops:['fromBase32'], label:'Base32 encodé', color:'var(--fl-accent)' });
  if (/(?:\\x[0-9a-fA-F]{2}){3,}/.test(s)) results.push({ confidence:93, ops:['fromHex'], label:'Séquences \\xAB hex', color:'var(--fl-gold)' });
  const hexOnly=s.replace(/[\s,]/g,'');
  if (/^[0-9a-fA-F]+$/.test(hexOnly) && hexOnly.length%2===0 && hexOnly.length>=10) results.push({ confidence:72, ops:['fromHex'], label:'Chaîne hex pure', color:'var(--fl-purple)' });
  const urlCount=(s.match(/%[0-9A-Fa-f]{2}/g)||[]).length;
  if (urlCount>3||(urlCount>0&&urlCount/s.length>0.05)) results.push({ confidence:90, ops:['urlDecode'], label:'URL encodé (%XX)', color:'var(--fl-accent)' });
  if (/^\d+(?:\s*[,\s]\s*\d+){5,}$/.test(s.trim())) results.push({ confidence:82, ops:['fromCharcode'], label:'Codes de caractères', color:'#22c55e' });
  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(s)) results.push({ confidence:88, ops:['fromHtmlEntity'], label:'Entités HTML', color:'#06b6d4' });
  if (/\\u[0-9a-fA-F]{4}/.test(s)) results.push({ confidence:85, ops:['fromUnicodeEscape'], label:'Unicode escapes \\uXXXX', color:'var(--fl-accent)' });
  if (/^[01]{8}(\s[01]{8})+$/.test(s.trim())) results.push({ confidence:90, ops:['fromBinary'], label:'Binaire (octets 8 bits)', color:'var(--fl-gold)' });
  const e = shannonEntropy(s);
  if (e > 5.5 && results.length === 0) results.push({ confidence:45, ops:['extractStrings'], label:`Entropie élevée (${e.toFixed(2)} bits) — extraction recommandée`, color:'var(--fl-dim)' });
  return results.sort((a,b)=>b.confidence-a.confidence);
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

async function applyRecipe(input, recipe) {
  let current = input;
  const steps = [];
  for (const step of recipe) {
    const op = OPS[step.opId];
    if (!op) { steps.push({ opId:step.opId, output:current, error:'Opération inconnue' }); continue; }
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

const mono = { fontFamily:'monospace' };

function OpBadge({ category }) {
  return (
    <span style={{
      fontSize:8, padding:'0 5px', borderRadius:3,
      background:`${CAT_COLOR[category]||'var(--fl-dim)'}20`,
      color:CAT_COLOR[category]||'var(--fl-dim)',
      border:`1px solid ${CAT_COLOR[category]||'var(--fl-dim)'}40`,
      ...mono, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.05em',
    }}>
      {category}
    </span>
  );
}

function RecipeStep({ step, index, onRemove, onChange }) {
  const op = OPS[step.opId];
  if (!op) return null;
  const [open, setOpen] = useState(false);
  return (
    <div style={{ border:'1px solid var(--fl-border)', borderRadius:5, marginBottom:4, background:'var(--fl-bg)', overflow:'hidden' }}>
      <div
        style={{ display:'flex', alignItems:'center', gap:6, padding:'5px 8px', cursor:op.params.length>0?'pointer':'default', borderBottom:open&&op.params.length>0?'1px solid var(--fl-border)':'none' }}
        onClick={() => op.params.length>0 && setOpen(o=>!o)}
      >
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0, minWidth:14 }}>{index+1}.</span>
        <span style={{ ...mono, fontSize:10, color:'var(--fl-on-dark)', flex:1 }}>{op.label}</span>
        <OpBadge category={op.category} />
        {op.params.length>0 && <ChevronDown size={10} style={{ color:'var(--fl-subtle)', transform:open?'rotate(180deg)':'none', transition:'transform 0.15s' }} />}
        <button onClick={e=>{e.stopPropagation();onRemove(index);}} style={{ background:'none', border:'none', cursor:'pointer', padding:0, color:'var(--fl-subtle)', display:'flex' }}>
          <X size={10} />
        </button>
      </div>
      {open && op.params.length>0 && (
        <div style={{ padding:'6px 8px', display:'flex', flexDirection:'column', gap:5 }}>
          {op.params.map(p => (
            <div key={p.id} style={{ display:'flex', alignItems:'center', gap:6 }}>
              <label style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', minWidth:70 }}>{p.label}</label>
              {p.type==='select'?(
                <select value={step.params?.[p.id]??p.default} onChange={e=>onChange(index,p.id,e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 4px', flex:1 }}>
                  {p.options.map(o=><option key={o} value={o}>{o}</option>)}
                </select>
              ):(
                <input type={p.type==='number'?'number':'text'} value={step.params?.[p.id]??p.default} min={p.min} max={p.max}
                  onChange={e=>onChange(index,p.id,p.type==='number'?Number(e.target.value):e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 6px', flex:1, outline:'none' }} />
              )}
            </div>
          ))}
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
  const [pickerCat, setPickerCat] = useState('Spécialisé');
  const [pickerSearch, setPickerSearch] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [copied, setCopied] = useState(false);

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
    const s = detectObfuscation(input);
    setSuggestions(s.length>0 ? s : [{ confidence:0, label:'Aucune obfuscation connue détectée', color:'var(--fl-ok)', ops:[] }]);
  }, [input]);

  const applySuggestion = useCallback((ops) => {
    if (!ops.length) return;
    setRecipe(ops.map(opId => ({ opId, params:Object.fromEntries((OPS[opId]?.params||[]).map(p=>[p.id,p.default])) })));
    setSuggestions([]);
  }, []);

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
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)' }}>— {Object.keys(OPS).length} opérations</span>
        <div style={{ flex:1 }} />
        {running && <span style={{ ...mono, fontSize:9, color:'var(--fl-warn)' }}>⟳ calcul…</span>}
        <button onClick={handleDetect} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:10 }}>
          <Wand2 size={10} /> Détecter auto
        </button>
        <button onClick={()=>{setRecipe([]);setInput('');setSuggestions([]);}} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'none', border:'1px solid var(--fl-border)', color:'var(--fl-subtle)', cursor:'pointer', ...mono, fontSize:10 }}>
          <RotateCcw size={10} /> Reset
        </button>
      </div>

      {suggestions.length>0 && (
        <div style={{ padding:'5px 14px', background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
          <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0 }}>DÉTECTION :</span>
          {suggestions.map((s,i)=>(
            <button key={i} onClick={()=>s.ops.length>0&&applySuggestion(s.ops)}
              style={{ display:'flex', alignItems:'center', gap:5, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:`${s.color}15`, border:`1px solid ${s.color}40`, color:s.color, cursor:s.ops.length>0?'pointer':'default', ...mono, fontSize:9 }}>
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
              Recette · {recipe.length} étape{recipe.length!==1?'s':''}
            </span>
            <button onClick={()=>setShowPicker(p=>!p)} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 7px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:9 }}>
              <Plus size={9} /> Ajouter
            </button>
          </div>

          {showPicker && (
            <div style={{ background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', flexShrink:0 }}>
              <div style={{ padding:'4px 8px', borderBottom:'1px solid var(--fl-border)' }}>
                <input value={pickerSearch} onChange={e=>setPickerSearch(e.target.value)} placeholder="Rechercher une opération…"
                  style={{ width:'100%', boxSizing:'border-box', ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:'var(--fl-radius-sm)', padding:'3px 6px', outline:'none' }} />
              </div>
              {!pickerSearch && (
                <div style={{ display:'flex', overflowX:'auto', scrollbarWidth:'none', padding:'4px 6px', gap:3, borderBottom:'1px solid var(--fl-border)' }}>
                  {CATEGORIES.map(cat=>(
                    <button key={cat} onClick={()=>setPickerCat(cat)} style={{ flexShrink:0, padding:'2px 6px', borderRadius:'var(--fl-radius-sm)', cursor:'pointer', ...mono, fontSize:8, background:pickerCat===cat?`${CAT_COLOR[cat]}20`:'none', border:`1px solid ${pickerCat===cat?CAT_COLOR[cat]+'60':'transparent'}`, color:pickerCat===cat?CAT_COLOR[cat]:'var(--fl-subtle)' }}>
                      {cat}
                    </button>
                  ))}
                </div>
              )}
              <div style={{ maxHeight:220, overflowY:'auto', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
                {filteredOps.length===0
                  ? <div style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', padding:'10px', textAlign:'center' }}>Aucune opération trouvée</div>
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
                Cliquez "Ajouter" pour<br />construire une recette<br /><br />— ou —<br /><br />Collez un payload et<br />utilisez "Détecter auto"
              </div>
            ):(
              recipe.map((step,i)=>(
                <RecipeStep key={i} step={step} index={i} onRemove={removeOp} onChange={changeParam} />
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
                  <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)' }}>Exécution automatique</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0, overflow:'hidden' }}>
          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0, borderBottom:'2px solid var(--fl-border)' }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-accent)', textTransform:'uppercase', letterSpacing:'0.1em', fontWeight:700 }}>Entrée</span>
              {input&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{input.length} chars · entropie {entropy} bits{parseFloat(entropy)>5.5?' ⚠':''}</span>}
              {input&&parseFloat(entropy)>5.5&&<span style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-danger) 12%, transparent)', color:'var(--fl-danger)', border:'1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)' }}>Entropie élevée</span>}
            </div>
            <textarea value={input} onChange={e=>setInput(e.target.value)}
              placeholder={'Collez le payload à analyser…\n\nLa recette s\'applique automatiquement.\nUtilisez "Détecter auto" pour une suggestion.'}
              spellCheck={false}
              style={{ flex:1, resize:'none', outline:'none', background:'var(--fl-bg)', color:'var(--fl-on-dark)', border:'none', padding:'10px 14px', ...mono, fontSize:11, lineHeight:1.6, scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }} />
          </div>

          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0 }}>
            <div style={{ display:'flex', alignItems:'center', gap:6, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)', flexWrap:'wrap' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)', textTransform:'uppercase', letterSpacing:'0.1em', fontWeight:700 }}>Sortie</span>
              {output&&output!==input&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{output.length} chars</span>}
              <div style={{ flex:1 }} />
              {steps.map((s,i)=>(
                <span key={i} style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:s.error?'color-mix(in srgb, var(--fl-danger) 12%, transparent)':'color-mix(in srgb, var(--fl-ok) 12%, transparent)', color:s.error?'var(--fl-danger)':'var(--fl-ok)', border:`1px solid ${s.error?'color-mix(in srgb, var(--fl-danger) 30%, transparent)':'color-mix(in srgb, var(--fl-ok) 30%, transparent)'}` }}>
                  {i+1}. {OPS[s.opId]?.label??s.opId}{s.error?' ✗':' ✓'}
                </span>
              ))}
              <button onClick={copyOutput} disabled={!output} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:copied?'color-mix(in srgb, var(--fl-ok) 15%, transparent)':'none', border:`1px solid ${copied?'color-mix(in srgb, var(--fl-ok) 40%, transparent)':'var(--fl-border)'}`, color:copied?'var(--fl-ok)':'var(--fl-subtle)', cursor:output?'pointer':'default', ...mono, fontSize:9, transition:'all 0.2s' }}>
                <Copy size={9} /> {copied?'Copié !':'Copier'}
              </button>
            </div>
            <div style={{ flex:1, overflowY:'auto', background:'var(--fl-bg)', padding:'10px 14px', ...mono, fontSize:11, color:lastError?'var(--fl-danger)':'var(--fl-on-dark)', lineHeight:1.6, whiteSpace:'pre-wrap', wordBreak:'break-all', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
              {recipe.length===0
                ? <span style={{ color:'var(--fl-subtle)' }}>La sortie apparaîtra ici une fois la recette construite…</span>
                : (output||<span style={{ color:'var(--fl-subtle)' }}>(sortie vide)</span>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
