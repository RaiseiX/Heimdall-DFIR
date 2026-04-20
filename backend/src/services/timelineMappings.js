// Tool-agnostic CSV mapping registry (v2.23). Loads per-tool YAML mapping
// files from backend/config/timeline_mappings/*.yaml and picks the right
// mapping for an incoming CSV via three strategies (filename pattern, folder
// hint, header signature). Used by the CSV meta-import endpoint.
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('../config/logger').default;

const MAPPINGS_DIR = path.join(__dirname, '..', '..', 'config', 'timeline_mappings');

let _cache = { loadedAt: 0, mappings: [] };
const RELOAD_MS = 30_000;

function loadMappings() {
  if (Date.now() - _cache.loadedAt < RELOAD_MS && _cache.mappings.length) return _cache.mappings;
  const out = [];
  try {
    for (const f of fs.readdirSync(MAPPINGS_DIR)) {
      if (!/\.(ya?ml)$/i.test(f)) continue;
      try {
        const raw = yaml.load(fs.readFileSync(path.join(MAPPINGS_DIR, f), 'utf-8'));
        if (!raw || !raw.tool || !raw.artifact_type || !raw.columns) {
          logger.warn(`[mappings] ${f}: missing required fields (tool, artifact_type, columns)`);
          continue;
        }
        out.push({
          id: f.replace(/\.ya?ml$/i, ''),
          tool: String(raw.tool),
          artifact_type: String(raw.artifact_type),
          artifact_name: String(raw.artifact_name || raw.tool),
          filename_patterns: (raw.filename_patterns || []).map(p => new RegExp(p, 'i')),
          folder_patterns: (raw.folder_patterns || []).map(p => new RegExp(p, 'i')),
          header_signatures: (raw.header_signatures || []).map(sig => (sig || []).map(String)),
          timestamp_columns: raw.timestamp_columns || [],
          description_columns: raw.description_columns || [],
          source_column: raw.source_column || null,
          columns: raw.columns || {},
        });
      } catch (e) {
        logger.warn(`[mappings] failed to load ${f}: ${e.message}`);
      }
    }
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn(`[mappings] dir read error: ${e.message}`);
  }
  _cache = { loadedAt: Date.now(), mappings: out };
  logger.info(`[mappings] ${out.length} CSV mapping(s) loaded`);
  return out;
}

// Detect the right mapping for a CSV file. Returns null if nothing matches.
// ctx = { filename, folderPath, headers }
function detectMapping(ctx) {
  const mappings = loadMappings();
  const filename = (ctx.filename || '').toLowerCase();
  const folder = (ctx.folderPath || '').toLowerCase();
  const headers = Array.isArray(ctx.headers) ? ctx.headers.map(h => String(h)) : [];

  // Strategy 1 — filename pattern
  for (const m of mappings) {
    if (m.filename_patterns.some(re => re.test(filename))) return { mapping: m, via: 'filename' };
  }
  // Strategy 2 — folder hint
  for (const m of mappings) {
    if (m.folder_patterns.some(re => re.test(folder))) return { mapping: m, via: 'folder' };
  }
  // Strategy 3 — header signature (every column in signature must be present)
  for (const m of mappings) {
    for (const sig of m.header_signatures) {
      if (sig.length && sig.every(c => headers.includes(c))) return { mapping: m, via: 'headers' };
    }
  }
  return null;
}

// Apply a mapping to one CSV record: returns a normalized record compatible
// with streamNormalizeToDB's batch shape — or null if the timestamp is invalid.
function applyMapping(mapping, record) {
  const col = mapping.columns || {};
  const pick = (spec) => {
    if (!spec) return null;
    if (Array.isArray(spec)) {
      for (const k of spec) {
        const v = record[k];
        if (v !== undefined && v !== null && String(v).trim() !== '') return v;
      }
      return null;
    }
    const v = record[spec];
    return v === undefined ? null : v;
  };
  return {
    raw_timestamp: pick(mapping.timestamp_columns) || pick(col.timestamp),
    source: pick(col.source) || pick(mapping.source_column) || '',
    description: pick(col.description) || pick(mapping.description_columns) || '',
    tool: mapping.tool,
    artifact_type: mapping.artifact_type,
    artifact_name: mapping.artifact_name,
    event_id: pick(col.event_id),
    ext: pick(col.ext),
    path: pick(col.path),
    file_size: pick(col.file_size),
    sha1: pick(col.sha1),
    src_ip: pick(col.src_ip),
    dst_ip: pick(col.dst_ip),
    details: pick(col.details),
    host_name: pick(col.host_name),
    user_name: pick(col.user_name),
    process_name: pick(col.process_name),
  };
}

module.exports = { loadMappings, detectMapping, applyMapping };
