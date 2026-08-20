// Timeline keyword enrichment (v2.23). Loads MITRE-categorised regex rules
// from backend/config/timeline_keywords.yaml and returns matched tags for a
// given CSV record. Designed to be called inside the ingest hot path — rules
// are compiled once at load and cached until the file mtime changes.
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('../config/logger').default;

const KEYWORDS_PATH = path.join(__dirname, '..', '..', 'config', 'timeline_keywords.yaml');

let _cache = { mtimeMs: 0, rules: [], gateRe: null };

function compile(raw) {
  const rules = Array.isArray(raw?.rules) ? raw.rules : [];
  const out = [];
  for (const r of rules) {
    if (!r || !r.name || !r.pattern || !Array.isArray(r.tags)) continue;
    try {
      out.push({
        name: String(r.name),
        pattern: String(r.pattern),
        re: new RegExp(r.pattern, r.flags || 'i'),
        fields: Array.isArray(r.fields) && r.fields.length ? r.fields : null, // null = scan all
        types: Array.isArray(r.types) && r.types.length ? r.types.map(String) : null, // null = any artifact type
        tags: r.tags.map(String),
        // Lookaround forces the regex engine's backtracking path, so those are
        // excluded from the combined gate and tested individually instead.
        lookaround: /\(\?[=!<]/.test(String(r.pattern)),
      });
    } catch (e) {
      logger.warn(`[keywords] invalid regex for rule "${r.name}": ${e.message}`);
    }
  }
  // Combined gate over the plain scan-all rules (no `fields`, no lookaround):
  // one test answers "did ANY of them match?" in a single pass, so non-matching
  // rows — the overwhelming majority on high-volume artifacts (MFT/USN/EVTX) —
  // skip the per-rule loop. Lookaround rules are left out so the combined
  // regex stays on the engine's fast automaton path, and are re-checked
  // individually in the fast path. Superset-safe: over-matching only falls
  // through to the precise loop, never skips a real hit.
  let gateRe = null;
  const gatePatterns = out.filter(r => !r.fields && !r.lookaround).map(r => r.pattern);
  if (gatePatterns.length) {
    try {
      gateRe = new RegExp(gatePatterns.map(p => `(?:${p})`).join('|'), 'i');
    } catch (e) {
      logger.warn(`[keywords] combined gate regex failed: ${e.message}`);
    }
  }
  return { rules: out, gateRe };
}

function load() {
  try {
    const st = fs.statSync(KEYWORDS_PATH);
    if (st.mtimeMs === _cache.mtimeMs) return _cache.rules;
    const raw = yaml.load(fs.readFileSync(KEYWORDS_PATH, 'utf-8'));
    const compiled = compile(raw);
    _cache = { mtimeMs: st.mtimeMs, rules: compiled.rules, gateRe: compiled.gateRe };
    logger.info(`[keywords] loaded ${_cache.rules.length} rules from ${path.basename(KEYWORDS_PATH)}`);
    return _cache.rules;
  } catch (e) {
    if (_cache.rules.length === 0) {
      logger.warn(`[keywords] could not load ${KEYWORDS_PATH}: ${e.message}`);
    }
    return _cache.rules;
  }
}

// Run all rules against a record; return a deduped sorted list of matched tags.
// `artifactType` may come from the explicit argument or from record.artifact_type
// (the tagger re-run path injects it into the record). Rules with a `types` list
// only match when the artifact type is in that list.
// Regex guards: the keyword gate combines every plain rule into one big
// case-insensitive alternation, and the per-rule loop re-tests the same
// haystack. EVTX rows can carry 100KB+ payloads; testing an unbounded joined
// record against 200+ `.*`-heavy patterns can stall the event loop for minutes
// (observed: parse-progress polls unresponsive for 300-400s). Every real
// keyword pattern targets short fields (command lines, process names, paths),
// so a 100KB window is far beyond anything that can legitimately match — the
// cap bounds worst-case regex cost without losing real hits.
const MAX_SUBJECT_LEN = 100000;

function matchTags(record, descriptionFallback = '', artifactType = '') {
  const rules = load();
  if (rules.length === 0) return [];
  const at = artifactType || (record && record.artifact_type) || '';
  const hay = {};
  const scanAll = () => {
    let all = descriptionFallback ? String(descriptionFallback) : '';
    for (const v of Object.values(record || {})) {
      if (v == null) continue;
      const s = typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : '');
      if (s) all += ' ' + s;
      if (all.length >= MAX_SUBJECT_LEN) break;
    }
    return all.slice(0, MAX_SUBJECT_LEN);
  };
  const matched = new Set();

  // Fast path: if the combined scan-all gate doesn't match the record's full
  // haystack, no plain scan-all rule can match — evaluate only the lookaround
  // scan-all rules and the field-targeted rules.
  const gateRe = _cache.gateRe;
  if (gateRe && rules.some(r => !r.fields && !r.lookaround && (!r.types || r.types.includes(at)))) {
    const subject = hay.all || (hay.all = scanAll());
    if (subject && !gateRe.test(subject)) {
      for (const r of rules) {
        if (r.types && !r.types.includes(at)) continue;
        if (r.fields) {
          const s = r.fields.map(f => record?.[f] ?? '').join(' ').slice(0, MAX_SUBJECT_LEN);
          if (s && r.re.test(s)) for (const t of r.tags) matched.add(t);
        } else if (r.lookaround) {
          if (r.re.test(subject)) for (const t of r.tags) matched.add(t);
        }
      }
      return Array.from(matched).sort();
    }
  }

  for (const r of rules) {
    if (r.types && !r.types.includes(at)) continue;
    let subject;
    if (r.fields) {
      subject = r.fields.map(f => record?.[f] ?? '').join(' ').slice(0, MAX_SUBJECT_LEN);
    } else {
      subject = hay.all || (hay.all = scanAll());
    }
    if (!subject) continue;
    if (r.re.test(subject)) {
      for (const t of r.tags) matched.add(t);
    }
  }
  return Array.from(matched).sort();
}

module.exports = { matchTags, load };
