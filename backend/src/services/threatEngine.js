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

let _cache = { mtimeMs: 0, rules: [], byArtifact: new Map(), wildcardRules: [] };

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

function compileRule(raw) {
  if (!raw || raw.enabled === false) return null;
  if (!raw.id || !raw.name || !raw.match || !Array.isArray(raw.tags)) return null;
  const targets = raw.target_artifact == null
    ? ['*']
    : Array.isArray(raw.target_artifact) ? raw.target_artifact : [raw.target_artifact];
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
  _cache = { mtimeMs: latestMtime, rules: all, byArtifact, wildcardRules };
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

  const hits = [];
  const tags = new Set();
  let topSev = 0;
  let topSevLabel = null;
  for (const r of pool) {
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
