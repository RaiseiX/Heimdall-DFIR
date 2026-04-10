
import { useState, useMemo, useCallback } from 'react';
import {
  FlaskConical, Wand2, Plus, X, ChevronDown, Copy,
  AlertTriangle, Play, RotateCcw, ChevronRight,
} from 'lucide-react';

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function decodeHtmlEntities(input) {
  return input
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, '\u00a0')
    .replace(/&#x([0-9A-Fa-f]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
}

const OPS = {
  psCommandDecode: {
    label: 'PowerShell -EncodedCommand',
    category: 'Spécialisé',
    desc: 'Base64 → UTF-16LE (commandes PS obfusquées)',
    params: [],
    fn: (input) => {
      const s = input.trim().replace(/\s/g, '');
      const raw = atob(s);
      const bytes = Array.from(raw).map(c => c.charCodeAt(0));
      const out = [];
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const code = bytes[i] | (bytes[i + 1] << 8);
        if (code > 0) out.push(String.fromCharCode(code));
      }
      return out.join('');
    },
  },
  fromBase64: {
    label: 'Depuis Base64',
    category: 'Encodage',
    desc: 'Décode une chaîne Base64 standard ou URL-safe',
    params: [{ id: 'alphabet', label: 'Alphabet', type: 'select', options: ['Standard (+/)', 'URL-safe (-_)'], default: 'Standard (+/)' }],
    fn: (input, { alphabet = 'Standard (+/)' } = {}) => {
      let s = input.trim().replace(/\s/g, '');
      if (alphabet === 'URL-safe (-_)') s = s.replace(/-/g, '+').replace(/_/g, '/');
      try { return atob(s); } catch (e) { throw new Error('Base64 invalide — ' + e.message); }
    },
  },
  toBase64: {
    label: 'Vers Base64',
    category: 'Encodage',
    desc: 'Encode en Base64',
    params: [],
    fn: (input) => {
      try { return btoa(input); }
      catch { return btoa(unescape(encodeURIComponent(input))); }
    },
  },
  fromHex: {
    label: 'Depuis Hex',
    category: 'Encodage',
    desc: 'Hex (4142, \\x41\\x42, 0x41 0x42) → texte brut',
    params: [],
    fn: (input) => {
      let s = input.trim();
      s = s.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[,\s]+/g, '');
      if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error('Hex invalide');
      if (s.length % 2 !== 0) s = '0' + s;
      let result = '';
      for (let i = 0; i < s.length; i += 2)
        result += String.fromCharCode(parseInt(s.substr(i, 2), 16));
      return result;
    },
  },
  toHex: {
    label: 'Vers Hex',
    category: 'Encodage',
    desc: 'Texte → représentation hexadécimale',
    params: [{ id: 'sep', label: 'Séparateur', type: 'select', options: ['Espace', 'Aucun', '\\x', '0x'], default: 'Espace' }],
    fn: (input, { sep = 'Espace' } = {}) =>
      Array.from(input).map(c => {
        const h = c.charCodeAt(0).toString(16).padStart(2, '0');
        if (sep === '\\x') return '\\x' + h;
        if (sep === '0x') return '0x' + h;
        return h;
      }).join(sep === 'Espace' ? ' ' : ''),
  },
  urlDecode: {
    label: 'Décodage URL',
    category: 'Encodage',
    desc: 'Décode %XX et + → espace',
    params: [],
    fn: (input) => {
      try { return decodeURIComponent(input.replace(/\+/g, ' ')); }
      catch { return unescape(input); }
    },
  },
  urlEncode: {
    label: 'Encodage URL',
    category: 'Encodage',
    desc: 'Encode les caractères spéciaux en %XX',
    params: [],
    fn: (input) => encodeURIComponent(input),
  },
  fromHtmlEntity: {
    label: 'Depuis Entités HTML',
    category: 'Encodage',
    desc: 'Décode &amp; &#65; &#x41; etc. (sans DOM)',
    params: [],
    fn: (input) => decodeHtmlEntities(input),
  },
  fromCharcode: {
    label: 'Depuis Codes Char',
    category: 'Encodage',
    desc: 'Codes décimaux/hex séparés → texte',
    params: [{ id: 'base', label: 'Base', type: 'select', options: ['Décimal', 'Hexadécimal', 'Octal'], default: 'Décimal' }],
    fn: (input, { base = 'Décimal' } = {}) => {
      const radix = base === 'Hexadécimal' ? 16 : base === 'Octal' ? 8 : 10;
      const codes = input.trim().split(/[\s,]+/).map(s => parseInt(s, radix));
      if (codes.some(isNaN)) throw new Error('Codes invalides pour la base ' + base);
      return codes.map(c => String.fromCharCode(c)).join('');
    },
  },
  decodeUtf16le: {
    label: 'UTF-16LE → Texte',
    category: 'Encodage',
    desc: 'Interprète une chaîne brute comme UTF-16 Little Endian',
    params: [],
    fn: (input) => {
      const bytes = Array.from(input).map(c => c.charCodeAt(0));
      const out = [];
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const code = bytes[i] | (bytes[i + 1] << 8);
        if (code > 0) out.push(String.fromCharCode(code));
      }
      return out.join('');
    },
  },
  rot13: {
    label: 'ROT13 / César',
    category: 'Chiffrement',
    desc: 'Décalage de lettres (ROT13 par défaut)',
    params: [{ id: 'amount', label: 'Décalage', type: 'number', default: 13, min: 1, max: 25 }],
    fn: (input, { amount = 13 } = {}) =>
      input.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - base + Number(amount)) % 26 + base);
      }),
  },
  xorDecode: {
    label: 'XOR',
    category: 'Chiffrement',
    desc: 'XOR avec une clé sur un octet (ex: 0x41)',
    params: [{ id: 'key', label: 'Clé hex', type: 'text', default: '0x41' }],
    fn: (input, { key = '0x41' } = {}) => {
      const k = parseInt(key, 16);
      if (isNaN(k)) throw new Error('Clé invalide (format: 0x41)');
      return Array.from(input).map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join('');
    },
  },
  reverseString: {
    label: 'Inverser',
    category: 'Formatage',
    desc: 'Inverse la chaîne (par caractère, ligne ou mot)',
    params: [{ id: 'by', label: 'Inverser par', type: 'select', options: ['Caractère', 'Ligne', 'Mot'], default: 'Caractère' }],
    fn: (input, { by = 'Caractère' } = {}) => {
      if (by === 'Ligne') return input.split('\n').reverse().join('\n');
      if (by === 'Mot') return input.split(/\s+/).reverse().join(' ');
      return [...input].reverse().join('');
    },
  },
  stripNulls: {
    label: 'Supprimer Null Bytes',
    category: 'Formatage',
    desc: 'Supprime tous les octets nuls (\\x00)',
    params: [],
    fn: (input) => input.replace(/\x00/g, ''),
  },
  extractStrings: {
    label: 'Extraire Chaînes',
    category: 'Extraction',
    desc: 'Extrait toutes les chaînes imprimables (comme strings)',
    params: [{ id: 'minLen', label: 'Longueur min', type: 'number', default: 4, min: 1, max: 100 }],
    fn: (input, { minLen = 4 } = {}) => {
      const re = new RegExp(`[\\x20-\\x7e]{${minLen},}`, 'g');
      return (input.match(re) || []).join('\n') || '(aucune chaîne trouvée)';
    },
  },
  extractUrls: {
    label: 'Extraire URLs',
    category: 'Extraction',
    desc: 'Extrait toutes les URLs http(s)://',
    params: [],
    fn: (input) =>
      (input.match(/https?:\/\/[^\s"'<>)\]]+/g) || []).join('\n') || '(aucune URL)',
  },
  extractIps: {
    label: 'Extraire IPs',
    category: 'Extraction',
    desc: 'Extrait toutes les adresses IPv4',
    params: [],
    fn: (input) =>
      (input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).join('\n') || '(aucune IP)',
  },
  regexExtract: {
    label: 'Extraction Regex',
    category: 'Extraction',
    desc: 'Extrait les correspondances d\'un pattern regex',
    params: [
      { id: 'pattern', label: 'Pattern', type: 'text', default: '[A-Za-z0-9+/=]{20,}' },
      { id: 'flags', label: 'Flags', type: 'text', default: 'g' },
    ],
    fn: (input, { pattern = '[A-Za-z0-9+/=]{20,}', flags = 'g' } = {}) => {
      try {
        return (input.match(new RegExp(pattern, flags)) || []).join('\n') || '(aucun résultat)';
      } catch (e) { throw new Error('Regex invalide — ' + e.message); }
    },
  },
  countChars: {
    label: 'Statistiques',
    category: 'Info',
    desc: 'Affiche longueur, entropie, bytes les plus fréquents',
    params: [],
    fn: (input) => {
      const e = shannonEntropy(input);
      const printable = (input.match(/[\x20-\x7e]/g) || []).length;
      const freq = {};
      for (const c of input) {
        const h = c.charCodeAt(0).toString(16).padStart(2, '0');
        freq[h] = (freq[h] || 0) + 1;
      }
      const top = Object.entries(freq)
        .sort((a, b) => b[1] - a[1]).slice(0, 5)
        .map(([h, n]) => `\\x${h}×${n}`)
        .join('  ');
      return [
        `Longueur : ${input.length} caractères`,
        `Entropie : ${e.toFixed(4)} bits/byte${e > 5.5 ? '  ⚠ élevée' : ''}`,
        `Imprimable : ${printable}/${input.length} (${((printable / Math.max(input.length, 1)) * 100).toFixed(1)}%)`,
        `Top bytes : ${top}`,
      ].join('\n');
    },
  },
};

const CATEGORIES = ['Spécialisé', 'Encodage', 'Chiffrement', 'Extraction', 'Formatage', 'Info'];
const CAT_COLOR = {
  Spécialisé: '#da3633', Encodage: '#4d82c0', Chiffrement: '#c89d1d',
  Extraction: '#22c55e', Formatage: '#8b72d6', Info: '#7d8590',
};

function detectObfuscation(input) {
  if (!input || input.trim().length < 4) return [];
  const s = input.trim();
  const results = [];

  const b64clean = s.replace(/\s/g, '');
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(b64clean)) {
    try {
      const raw = atob(b64clean);
      const isUtf16 = raw.length >= 4 && raw.charCodeAt(1) === 0 && raw.charCodeAt(3) === 0;
      if (isUtf16) {
        results.push({ confidence: 97, ops: ['psCommandDecode'], label: 'PowerShell -EncodedCommand (Base64+UTF-16LE)', color: '#da3633' });
      } else {
        results.push({ confidence: 87, ops: ['fromBase64'], label: 'Base64 encodé', color: '#d97c20' });
      }
    } catch { /* not valid base64 */ }
  }

  if (/(?:\\x[0-9a-fA-F]{2}){3,}/.test(s)) {
    results.push({ confidence: 93, ops: ['fromHex'], label: 'Séquences \\xAB hexadécimales', color: '#c89d1d' });
  }

  const hexOnly = s.replace(/[\s,]/g, '');
  if (/^[0-9a-fA-F]+$/.test(hexOnly) && hexOnly.length % 2 === 0 && hexOnly.length >= 10) {
    results.push({ confidence: 72, ops: ['fromHex'], label: 'Chaîne hexadécimale pure', color: '#8b72d6' });
  }

  const urlCount = (s.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (urlCount > 3 || (urlCount > 0 && urlCount / s.length > 0.05)) {
    results.push({ confidence: 90, ops: ['urlDecode'], label: 'URL encodé (%XX)', color: '#4d82c0' });
  }

  if (/^\d+(?:\s*[,\s]\s*\d+){5,}$/.test(s.trim())) {
    results.push({ confidence: 82, ops: ['fromCharcode'], label: 'Codes de caractères décimaux', color: '#22c55e' });
  }

  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(s)) {
    results.push({ confidence: 88, ops: ['fromHtmlEntity'], label: 'Entités HTML', color: '#06b6d4' });
  }

  const e = shannonEntropy(s);
  if (e > 5.5 && results.length === 0) {
    results.push({
      confidence: 45,
      ops: ['extractStrings'],
      label: `Entropie très élevée (${e.toFixed(2)} bits) — extraction recommandée`,
      color: '#7d8590',
    });
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}

function applyRecipe(input, recipe) {
  let current = input;
  const steps = [];
  for (const step of recipe) {
    const op = OPS[step.opId];
    if (!op) { steps.push({ opId: step.opId, output: current, error: 'Opération inconnue' }); continue; }
    try {
      const out = op.fn(current, step.params || {});
      steps.push({ opId: step.opId, output: out, error: null });
      current = out;
    } catch (e) {
      steps.push({ opId: step.opId, output: current, error: e.message });
      break;
    }
  }
  return { final: current, steps };
}

const mono = { fontFamily: 'monospace' };

function OpBadge({ category }) {
  return (
    <span style={{
      fontSize: 8, padding: '0 5px', borderRadius: 3,
      background: `${CAT_COLOR[category] || '#7d8590'}20`,
      color: CAT_COLOR[category] || '#7d8590',
      border: `1px solid ${CAT_COLOR[category] || '#7d8590'}40`,
      ...mono, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
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
    <div style={{ border: '1px solid #1a2535', borderRadius: 5, marginBottom: 4, background: '#0a1525', overflow: 'hidden' }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px',
          cursor: op.params.length > 0 ? 'pointer' : 'default',
          borderBottom: open && op.params.length > 0 ? '1px solid #1a2535' : 'none',
        }}
        onClick={() => op.params.length > 0 && setOpen(o => !o)}
      >
        <span style={{ ...mono, fontSize: 9, color: '#3d5070', flexShrink: 0, minWidth: 14 }}>{index + 1}.</span>
        <span style={{ ...mono, fontSize: 10, color: '#b0ccec', flex: 1 }}>{op.label}</span>
        <OpBadge category={op.category} />
        {op.params.length > 0 && (
          <ChevronDown size={10} style={{ color: '#3d5070', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
        )}
        <button
          onClick={e => { e.stopPropagation(); onRemove(index); }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#3d5070', display: 'flex' }}
        >
          <X size={10} />
        </button>
      </div>

      {open && op.params.length > 0 && (
        <div style={{ padding: '6px 8px', display: 'flex', flexDirection: 'column', gap: 5 }}>
          {op.params.map(p => (
            <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <label style={{ ...mono, fontSize: 9, color: '#3d5070', minWidth: 70 }}>{p.label}</label>
              {p.type === 'select' ? (
                <select
                  value={step.params?.[p.id] ?? p.default}
                  onChange={e => onChange(index, p.id, e.target.value)}
                  style={{ ...mono, fontSize: 9, background: '#07101f', color: '#7abfff', border: '1px solid #1a2535', borderRadius: 3, padding: '1px 4px', flex: 1 }}
                >
                  {p.options.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input
                  type={p.type === 'number' ? 'number' : 'text'}
                  value={step.params?.[p.id] ?? p.default}
                  min={p.min} max={p.max}
                  onChange={e => onChange(index, p.id, p.type === 'number' ? Number(e.target.value) : e.target.value)}
                  style={{ ...mono, fontSize: 9, background: '#07101f', color: '#7abfff', border: '1px solid #1a2535', borderRadius: 3, padding: '1px 6px', flex: 1, outline: 'none' }}
                />
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
  const [showPicker, setShowPicker] = useState(false);
  const [pickerCat, setPickerCat] = useState('Spécialisé');
  const [suggestions, setSuggestions] = useState([]);
  const [copied, setCopied] = useState(false);

  const { final: output, steps } = useMemo(() => {
    if (!input || recipe.length === 0) return { final: input, steps: [] };
    return applyRecipe(input, recipe);
  }, [input, recipe]);

  const lastError = steps.find(s => s.error);

  const entropy = useMemo(() => (input ? shannonEntropy(input).toFixed(2) : null), [input]);

  const handleDetect = useCallback(() => {
    const s = detectObfuscation(input);
    setSuggestions(s.length > 0
      ? s
      : [{ confidence: 0, label: 'Aucune obfuscation connue détectée', color: '#3fb950', ops: [] }],
    );
  }, [input]);

  const applySuggestion = useCallback((ops) => {
    if (!ops.length) return;
    setRecipe(ops.map(opId => ({
      opId,
      params: Object.fromEntries((OPS[opId]?.params || []).map(p => [p.id, p.default])),
    })));
    setSuggestions([]);
  }, []);

  const addOp = useCallback((opId) => {
    const op = OPS[opId];
    setRecipe(r => [...r, { opId, params: Object.fromEntries((op.params || []).map(p => [p.id, p.default])) }]);
    setShowPicker(false);
  }, []);

  const removeOp = useCallback((i) => setRecipe(r => r.filter((_, idx) => idx !== i)), []);

  const changeParam = useCallback((stepIdx, paramId, value) => {
    setRecipe(r => r.map((s, i) => i === stepIdx ? { ...s, params: { ...s.params, [paramId]: value } } : s));
  }, []);

  const copyOutput = useCallback(() => {
    if (!output) return;
    navigator.clipboard.writeText(output).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [output]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#060b14', overflow: 'hidden' }}>

      
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '0 14px', height: 36, flexShrink: 0,
        background: '#07101f', borderBottom: '1px solid #1a2035',
      }}>
        <FlaskConical size={13} style={{ color: '#4d82c0' }} />
        <span style={{ ...mono, fontSize: 11, color: '#b0ccec', fontWeight: 700 }}>CyberChef Forensic</span>
        <span style={{ ...mono, fontSize: 9, color: '#2a4060' }}>— Décodeur / Désobfuscateur</span>
        <div style={{ flex: 1 }} />
        <button
          onClick={handleDetect}
          style={{
            display: 'flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 4,
            background: '#1a3a5c', border: '1px solid #2a5a8c', color: '#7abfff',
            cursor: 'pointer', ...mono, fontSize: 10,
          }}
        >
          <Wand2 size={10} />
          Détecter auto
        </button>
        <button
          onClick={() => { setRecipe([]); setInput(''); setSuggestions([]); }}
          style={{
            display: 'flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 4,
            background: 'none', border: '1px solid #1a2535', color: '#3d5070',
            cursor: 'pointer', ...mono, fontSize: 10,
          }}
        >
          <RotateCcw size={10} />
          Reset
        </button>
      </div>

      
      {suggestions.length > 0 && (
        <div style={{
          padding: '5px 14px', background: '#07101f', borderBottom: '1px solid #1a2035',
          display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center',
        }}>
          <span style={{ ...mono, fontSize: 9, color: '#3d5070', flexShrink: 0 }}>DÉTECTION :</span>
          {suggestions.map((s, i) => (
            <button
              key={i}
              onClick={() => s.ops.length > 0 && applySuggestion(s.ops)}
              style={{
                display: 'flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 4,
                background: `${s.color}15`, border: `1px solid ${s.color}40`, color: s.color,
                cursor: s.ops.length > 0 ? 'pointer' : 'default', ...mono, fontSize: 9,
              }}
            >
              {s.confidence > 0 && <span style={{ opacity: 0.55 }}>{s.confidence}%</span>}
              {s.label}
              {s.ops.length > 0 && <ChevronRight size={9} />}
            </button>
          ))}
          <button onClick={() => setSuggestions([])} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3d5070', marginLeft: 'auto', display: 'flex' }}>
            <X size={10} />
          </button>
        </div>
      )}

      
      <div style={{ display: 'flex', flex: 1, minHeight: 0, overflow: 'hidden' }}>

        
        <div style={{
          width: 240, flexShrink: 0, display: 'flex', flexDirection: 'column',
          borderRight: '1px solid #1a2035', background: '#07101f', overflow: 'hidden',
        }}>
          
          <div style={{
            padding: '6px 10px', borderBottom: '1px solid #1a2035',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
          }}>
            <span style={{ ...mono, fontSize: 9, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Recette · {recipe.length} étape{recipe.length !== 1 ? 's' : ''}
            </span>
            <button
              onClick={() => setShowPicker(p => !p)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 3,
                background: '#1a3a5c', border: '1px solid #2a5a8c', color: '#7abfff',
                cursor: 'pointer', ...mono, fontSize: 9,
              }}
            >
              <Plus size={9} />
              Ajouter
            </button>
          </div>

          
          {showPicker && (
            <div style={{ background: '#060b14', borderBottom: '1px solid #1a2035', flexShrink: 0 }}>
              <div style={{ display: 'flex', overflowX: 'auto', scrollbarWidth: 'none', padding: '4px 6px', gap: 3, borderBottom: '1px solid #0d1525' }}>
                {CATEGORIES.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setPickerCat(cat)}
                    style={{
                      flexShrink: 0, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                      ...mono, fontSize: 8,
                      background: pickerCat === cat ? `${CAT_COLOR[cat]}20` : 'none',
                      border: `1px solid ${pickerCat === cat ? CAT_COLOR[cat] + '60' : 'transparent'}`,
                      color: pickerCat === cat ? CAT_COLOR[cat] : '#3d5070',
                    }}
                  >
                    {cat}
                  </button>
                ))}
              </div>
              <div style={{ maxHeight: 200, overflowY: 'auto', scrollbarWidth: 'thin', scrollbarColor: '#1a2535 #060b14' }}>
                {Object.entries(OPS)
                  .filter(([, op]) => op.category === pickerCat)
                  .map(([id, op]) => (
                    <button
                      key={id}
                      onClick={() => addOp(id)}
                      style={{
                        display: 'block', width: '100%', textAlign: 'left', padding: '5px 10px',
                        background: 'none', border: 'none', borderBottom: '1px solid #0d1525',
                        cursor: 'pointer', ...mono, fontSize: 9, color: '#7abfff',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.background = '#0d1f30'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
                    >
                      <div style={{ fontWeight: 700 }}>{op.label}</div>
                      <div style={{ fontSize: 8, color: '#3d5070', marginTop: 1 }}>{op.desc}</div>
                    </button>
                  ))}
              </div>
            </div>
          )}

          
          <div style={{ flex: 1, overflowY: 'auto', padding: '6px 8px', scrollbarWidth: 'thin', scrollbarColor: '#1a2535 #07101f' }}>
            {recipe.length === 0 ? (
              <div style={{ ...mono, fontSize: 9, color: '#1e2d40', textAlign: 'center', marginTop: 28, lineHeight: 1.9 }}>
                Cliquez "Ajouter" pour<br />construire une recette<br /><br />— ou —<br /><br />Collez un payload et<br />utilisez "Détecter auto"
              </div>
            ) : (
              recipe.map((step, i) => (
                <RecipeStep key={i} step={step} index={i} onRemove={removeOp} onChange={changeParam} />
              ))
            )}
          </div>

          
          {recipe.length > 0 && (
            <div style={{ padding: '5px 8px', borderTop: '1px solid #1a2035', flexShrink: 0 }}>
              {lastError ? (
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 4 }}>
                  <AlertTriangle size={9} style={{ color: '#da3633', flexShrink: 0, marginTop: 1 }} />
                  <span style={{ ...mono, fontSize: 8, color: '#da3633', wordBreak: 'break-all' }}>{lastError.error}</span>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <Play size={9} style={{ color: '#22c55e' }} />
                  <span style={{ ...mono, fontSize: 9, color: '#22c55e' }}>Exécution automatique</span>
                </div>
              )}
            </div>
          )}
        </div>

        
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>

          
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, borderBottom: '1px solid #1a2035' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '4px 12px', flexShrink: 0,
              background: '#07101f', borderBottom: '1px solid #0d1525',
            }}>
              <span style={{ ...mono, fontSize: 9, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Entrée</span>
              {input && (
                <span style={{ ...mono, fontSize: 8, color: '#2a4060' }}>
                  {input.length} chars · entropie {entropy} bits{parseFloat(entropy) > 5.5 ? ' ⚠' : ''}
                </span>
              )}
              {input && parseFloat(entropy) > 5.5 && (
                <span style={{ ...mono, fontSize: 8, padding: '1px 6px', borderRadius: 3, background: '#da363318', color: '#da3633', border: '1px solid #da363330' }}>
                  Entropie élevée
                </span>
              )}
            </div>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={'Collez le payload à analyser…\n\nLa recette s\'applique automatiquement.\nUtilisez "Détecter auto" pour une suggestion.'}
              spellCheck={false}
              style={{
                flex: 1, resize: 'none', outline: 'none', background: '#060b14',
                color: '#7abfff', border: 'none', padding: '10px 14px',
                ...mono, fontSize: 11, lineHeight: 1.6,
                scrollbarWidth: 'thin', scrollbarColor: '#1a2535 #060b14',
              }}
            />
          </div>

          
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '4px 12px', flexShrink: 0,
              background: '#07101f', borderBottom: '1px solid #0d1525',
            }}>
              <span style={{ ...mono, fontSize: 9, color: '#3d5070', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Sortie</span>
              {output && output !== input && (
                <span style={{ ...mono, fontSize: 8, color: '#2a4060' }}>{output.length} chars</span>
              )}
              <div style={{ flex: 1 }} />
              
              {steps.map((s, i) => (
                <span key={i} style={{
                  ...mono, fontSize: 8, padding: '1px 6px', borderRadius: 3,
                  background: s.error ? '#da363318' : '#22c55e15',
                  color: s.error ? '#da3633' : '#22c55e',
                  border: `1px solid ${s.error ? '#da363330' : '#22c55e30'}`,
                }}>
                  {i + 1}. {OPS[s.opId]?.label ?? s.opId}{s.error ? ' ✗' : ' ✓'}
                </span>
              ))}
              <button
                onClick={copyOutput}
                disabled={!output}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 3,
                  background: copied ? '#22c55e20' : 'none',
                  border: `1px solid ${copied ? '#22c55e40' : '#1a2535'}`,
                  color: copied ? '#22c55e' : '#3d5070',
                  cursor: output ? 'pointer' : 'default',
                  ...mono, fontSize: 9, transition: 'all 0.2s',
                }}
              >
                <Copy size={9} />
                {copied ? 'Copié !' : 'Copier'}
              </button>
            </div>
            <div style={{
              flex: 1, overflowY: 'auto', background: '#060b14', padding: '10px 14px',
              ...mono, fontSize: 11, color: lastError ? '#da3633' : '#b8d4f0',
              lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              scrollbarWidth: 'thin', scrollbarColor: '#1a2535 #060b14',
            }}>
              {recipe.length === 0
                ? <span style={{ color: '#1e2d40' }}>La sortie apparaîtra ici une fois la recette construite…</span>
                : (output || <span style={{ color: '#1e2d40' }}>(sortie vide)</span>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
