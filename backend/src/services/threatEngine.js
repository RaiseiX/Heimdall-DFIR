// Threat Engine (v2.26) — compiles YAML rules into an artifact/eventId-bucketed
// match engine. Evaluates in the ingest hot path; targets ≤ 5 µs/record on the
// built-in rule packs (RMM, Anti-Forensics, LOLBIN, CredAccess, Persistence).
//
// Rule schema documented in tasks/threat_engine_architecture.md §1.1.

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('../config/logger').default;

const RULES_DIR = path.join(__dirname, '..', '..', 'config', 'threat_rules');

const SEVERITY_RANK = { greyware: 1, low: 1, medium: 2, high: 3, critical: 4 };

let _cache = { mtimeMs: 0, rules: [], byArtifact: new Map(), wildcardRules: [], fieldGates: new Map() };

function compileLeaf(leaf) {
  const field = leaf.field;
  const value = leaf.value;
  switch (leaf.op) {
    case 'eq':         return (rec) => rec?.[field] === value;
    case 'neq':        return (rec) => rec?.[field] !== value;
    case 'in': {
      const set = new Set(Array.isArray(value) ? value : [value]);
      return (rec) => set.has(rec?.[field]);
    }
    case 'gte':        return (rec) => Number(rec?.[field]) >= Number(value);
    case 'lte':        return (rec) => Number(rec?.[field]) <= Number(value);
    case 'contains':   return (rec) => String(rec?.[field] ?? '').includes(String(value));
    case 'icontains': {
      const needle = String(value).toLowerCase();
      return (rec) => String(rec?.[field] ?? '').toLowerCase().includes(needle);
    }
    case 'regex':      { const re = new RegExp(value); return (rec) => re.test(String(rec?.[field] ?? '')); }
    case 'iregex':     { const re = new RegExp(value, 'i'); return (rec) => re.test(String(rec?.[field] ?? '')); }
    default: throw new Error(`unknown op: ${leaf.op}`);
  }
}

function compileAst(node) {
  if (!node) return () => true;
  if (node.all) {
    const fns = node.all.map(compileAst);
    return (rec) => { for (const f of fns) if (!f(rec)) return false; return true; };
  }
  if (node.any) {
    const fns = node.any.map(compileAst);
    return (rec) => { for (const f of fns) if (f(rec)) return true; return false; };
  }
  if (node.none) {
    const fns = node.none.map(compileAst);
    return (rec) => { for (const f of fns) if (f(rec)) return false; return true; };
  }
  if (node.field && node.op) return compileLeaf(node);
  throw new Error('invalid AST node');
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Walks a rule's match AST collecting the regex leaves that can be combined
// into a per-field gate. Returns true when the rule is "gateable" — i.e. its
// match is built only from positive iregex/icontains leaves (no eq/in/neq/
// gte/lte, no `none`, no case-sensitive regex/contains). Such a rule can be
// skipped wholesale when none of its fields match the gate.
function collectGateLeaves(node, out) {
  if (!node || typeof node !== 'object') return true;
  if (node.field && node.op) {
    if (node.op === 'iregex') { out.push({ field: node.field, re: String(node.value) }); return true; }
    if (node.op === 'icontains') { out.push({ field: node.field, re: escapeRegExp(node.value) }); return true; }
    return false;
  }
  if (node.none) return false;
  const children = node.all || node.any || [];
  let ok = true;
  for (const c of children) if (!collectGateLeaves(c, out)) ok = false;
  return ok;
}

function compileRule(raw) {
  if (!raw || raw.enabled === false) return null;
  if (!raw.id || !raw.name || !raw.match || !Array.isArray(raw.tags)) return null;
  const targets = raw.target_artifact == null
    ? ['*']
    : Array.isArray(raw.target_artifact) ? raw.target_artifact : [raw.target_artifact];
  const gateLeaves = [];
  const gateable = collectGateLeaves(raw.match, gateLeaves);
  return {
    id: String(raw.id),
    name: String(raw.name),
    severity: String(raw.severity || 'medium'),
    category: String(raw.category || 'generic'),
    target_artifact: targets.map(String),
    mitre: Array.isArray(raw.mitre) ? raw.mitre : (raw.mitre ? [raw.mitre] : []),
    references: Array.isArray(raw.references) ? raw.references : [],
    tags: raw.tags.map(String),
    _match: compileAst(raw.match),
    _gateable: gateable,
    _fields: new Set(gateLeaves.map(l => l.field)),
    _gateLeaves: gateLeaves,
  };
}

function walkYaml(dir) {
  const files = [];
  let latestMtime = 0;
  if (!fs.existsSync(dir)) return { files, latestMtime };
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.isDirectory()) {
      const sub = walkYaml(path.join(dir, e.name));
      files.push(...sub.files);
      if (sub.latestMtime > latestMtime) latestMtime = sub.latestMtime;
    } else if (e.isFile() && /\.(ya?ml)$/i.test(e.name)) {
      const full = path.join(dir, e.name);
      try {
        const st = fs.statSync(full);
        if (st.mtimeMs > latestMtime) latestMtime = st.mtimeMs;
        files.push(full);
      } catch (_e) {}
    }
  }
  return { files, latestMtime };
}

function load() {
  const { files, latestMtime } = walkYaml(RULES_DIR);
  if (latestMtime && latestMtime === _cache.mtimeMs) return _cache;
  const all = [];
  for (const f of files) {
    try {
      const doc = yaml.load(fs.readFileSync(f, 'utf-8'));
      const rules = Array.isArray(doc?.rules) ? doc.rules : (Array.isArray(doc) ? doc : [doc]);
      for (const raw of rules) {
        try {
          const r = compileRule(raw);
          if (r) all.push(r);
        } catch (e) {
          logger.warn(`[threat-engine] invalid rule ${raw?.id || '?'} in ${path.basename(f)}: ${e.message}`);
        }
      }
    } catch (e) {
      logger.warn(`[threat-engine] failed to load ${path.basename(f)}: ${e.message}`);
    }
  }
  const byArtifact = new Map();
  const wildcardRules = [];
  for (const r of all) {
    if (r.target_artifact.includes('*')) wildcardRules.push(r);
    for (const a of r.target_artifact) {
      if (a === '*') continue;
      if (!byArtifact.has(a)) byArtifact.set(a, []);
      byArtifact.get(a).push(r);
    }
  }
  // Per-field combined gate over every gateable rule's regex leaf. Lets
  // evaluate() skip a rule when none of the fields it touches can possibly
  // match — the common case on high-volume artifacts (MFT/USN/EVTX) where most
  // rules target description/source/process_name and can't fire on file metadata.
  const fieldGates = new Map();
  {
    const byField = new Map();
    for (const r of all) {
      if (!r._gateable) continue;
      for (const l of r._gateLeaves) {
        if (!byField.has(l.field)) byField.set(l.field, []);
        byField.get(l.field).push(l.re);
      }
    }
    for (const [field, pats] of byField) {
      try {
        fieldGates.set(field, new RegExp(pats.map(p => `(?:${p})`).join('|'), 'i'));
      } catch (e) {
        logger.warn(`[threat-engine] field gate for "${field}" failed: ${e.message}`);
      }
    }
  }
  _cache = { mtimeMs: latestMtime, rules: all, byArtifact, wildcardRules, fieldGates };
  if (all.length) logger.info(`[threat-engine] loaded ${all.length} rules from ${files.length} file(s)`);
  return _cache;
}

// Evaluate a record (pre-extracted row with artifact_type/event_id/description/source/etc.)
// Returns { detections: [...], tags: [...], severity: 'highest|null' } or null if no hits.
function evaluate(record) {
  const cache = load();
  const artifact = record?.artifact_type || '';
  const candidates = cache.byArtifact.get(artifact);
  const pool = candidates
    ? (cache.wildcardRules.length ? candidates.concat(cache.wildcardRules) : candidates)
    : cache.wildcardRules;
  if (!pool || pool.length === 0) return null;

  // Lazy per-field gate results. A gateable rule is skipped when none of the
  // fields it references match their combined regex gate (superset-safe: it may
  // over-match and fall through to the precise _match, but never skips a hit).
  // Huge fields (EVTX payloads can exceed 100KB) would make the combined
  // per-field gate — dozens of `.*`-heavy alternatives in one case-insensitive
  // regex — catastrophically slow and stall the event loop for minutes. For
  // them we skip the gate shortcut entirely and fall through to the precise
  // per-rule matchers: same result, no false negatives, bounded cost.
  const MAX_GATE_FIELD_LEN = 100000;
  const gateHit = {};
  const gateMatch = (field) => {
    if (field in gateHit) return gateHit[field];
    const re = cache.fieldGates.get(field);
    const raw = String(record?.[field] ?? '');
    gateHit[field] = re ? (raw.length <= MAX_GATE_FIELD_LEN ? re.test(raw) : true) : true;
    return gateHit[field];
  };

  const hits = [];
  const tags = new Set();
  let topSev = 0;
  let topSevLabel = null;
  for (const r of pool) {
    if (r._gateable) {
      let anyFieldHit = false;
      for (const f of r._fields) {
        if (gateMatch(f)) { anyFieldHit = true; break; }
      }
      if (!anyFieldHit) continue;
    }
    let matched = false;
    try { matched = r._match(record); } catch (_e) { matched = false; }
    if (!matched) continue;
    hits.push({
      id: r.id,
      name: r.name,
      severity: r.severity,
      category: r.category,
      mitre: r.mitre,
    });
    for (const t of r.tags) tags.add(t);
    const rank = SEVERITY_RANK[r.severity] || 0;
    if (rank > topSev) { topSev = rank; topSevLabel = r.severity; }
  }
  if (hits.length === 0) return null;
  return { detections: hits, tags: Array.from(tags).sort(), severity: topSevLabel };
}

module.exports = { evaluate, load, RULES_DIR };
