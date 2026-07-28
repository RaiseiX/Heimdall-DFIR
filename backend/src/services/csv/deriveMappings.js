// Build CSV mappings from the same tables that drive native parsing.
//
// Hand-written YAML mappings drift: one wrong column name and the CSV path
// computes a different dedupe_hash than the native path, so the unique
// (case_id, dedupe_hash) index stops catching duplicates. Deriving them makes
// that class of bug impossible without also breaking native parsing.

/**
 * Pull the '--csvf <name>' output filename a parser declares.
 *
 * Read the builder's SOURCE rather than invoking it: several argsBuilders call
 * fs.statSync(input) to branch on file-vs-directory, which throws on a placeholder
 * path. Invoking them to discover a literal would silently cost those types their
 * filename pattern — a side effect has no business in a lookup.
 *
 * COUPLING WARNING: the regex expects the call to be written literally as
 * `'--csvf', '<name>'` with single quotes, matching how every argsBuilder in
 * artifactPatterns.js is formatted today. Reformatting that call (double quotes,
 * a variable instead of a literal, line-broken differently) makes this silently
 * return null — indistinguishable from "this type declares no --csvf". A guard
 * that counts matches against the real tables is planned for a later task; this
 * function does not self-check today.
 */
function declaredCsvName(config) {
  if (typeof config.argsBuilder !== 'function') return null;
  const m = /'--csvf',\s*'([^']+)'/.exec(config.argsBuilder.toString());
  return m ? m[1] : null;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Types whose native parser does NOT write to collection_timeline. pcap flows go
 * to network_connections and rdpcache produces bitmap images, so a CSV mapping
 * would create timeline rows the native path never creates — the exact divergence
 * this module exists to prevent.
 */
const NOT_TIMELINE_ARTIFACTS = new Set(['pcap', 'rdpcache']);

function deriveMappings(artifactPatterns, ecsColumns = {}) {
  const out = [];
  for (const [artifactType, config] of Object.entries(artifactPatterns || {})) {
    if (NOT_TIMELINE_ARTIFACTS.has(artifactType)) continue;

    const tsCols = config.timestampColumns || [];
    if (!tsCols.length) continue; // nothing to anchor a timeline row on

    const csvName = declaredCsvName(config);
    const ecs = ecsColumns[artifactType] || {};

    // Header signature: the match requires every listed column to be present, so
    // this is just the first declared timestamp column plus the source column —
    // no ranking or selection happens here.
    const signature = [tsCols[0], config.sourceColumn].filter(Boolean);

    out.push({
      id: `derived:${artifactType}`,
      tool: String(config.tool || artifactType).replace(/\.[^.]+$/, '').slice(0, 32),
      artifact_type: artifactType,
      artifact_name: config.name || artifactType,
      filename_patterns: csvName ? [new RegExp(`${escapeRegExp(csvName)}$`, 'i')] : [],
      folder_patterns: [],
      header_signatures: signature.length === 2 ? [signature] : [],
      fallback: false,
      timestamp_columns: tsCols,
      description_columns: config.descriptionColumns || [],
      source_column: config.sourceColumn || null,
      columns: {
        host_name: ecs.host || [],
        user_name: ecs.user || [],
        process_name: ecs.process || [],
      },
    });
  }
  return out;
}

module.exports = { deriveMappings, declaredCsvName };
