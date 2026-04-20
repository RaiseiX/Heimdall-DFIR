// Timeline keyword enrichment (v2.23). Loads MITRE-categorised regex rules
// from backend/config/timeline_keywords.yaml and returns matched tags for a
// given CSV record. Designed to be called inside the ingest hot path — rules
// are compiled once at load and cached until the file mtime changes.
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('../config/logger').default;

const KEYWORDS_PATH = path.join(__dirname, '..', '..', 'config', 'timeline_keywords.yaml');

let _cache = { mtimeMs: 0, rules: [] };

function compile(raw) {
  const rules = Array.isArray(raw?.rules) ? raw.rules : [];
  const out = [];
  for (const r of rules) {
    if (!r || !r.name || !r.pattern || !Array.isArray(r.tags)) continue;
    try {
      out.push({
        name: String(r.name),
        re: new RegExp(r.pattern, r.flags || 'i'),
        fields: Array.isArray(r.fields) && r.fields.length ? r.fields : null, // null = scan all
        tags: r.tags.map(String),
      });
    } catch (e) {
      logger.warn(`[keywords] invalid regex for rule "${r.name}": ${e.message}`);
    }
  }
  return out;
}

function load() {
  try {
    const st = fs.statSync(KEYWORDS_PATH);
    if (st.mtimeMs === _cache.mtimeMs) return _cache.rules;
    const raw = yaml.load(fs.readFileSync(KEYWORDS_PATH, 'utf-8'));
    _cache = { mtimeMs: st.mtimeMs, rules: compile(raw) };
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
function matchTags(record, descriptionFallback = '') {
  const rules = load();
  if (rules.length === 0) return [];
  const hay = {};
  const scanAll = () => {
    let all = descriptionFallback ? String(descriptionFallback) : '';
    for (const v of Object.values(record || {})) {
      if (v == null) continue;
      const s = typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : '');
      if (s) all += ' ' + s;
    }
    return all;
  };
  const matched = new Set();
  for (const r of rules) {
    let subject;
    if (r.fields) {
      subject = r.fields.map(f => record?.[f] ?? '').join(' ');
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
