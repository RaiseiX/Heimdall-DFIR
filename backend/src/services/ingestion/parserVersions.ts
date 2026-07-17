// backend/src/services/ingestion/parserVersions.ts
// Single source of truth for dedup: bumping a value invalidates the cache and forces re-parse.
// Keep aligned with the version runParser writes to parser_results.parser_version.
export const PARSER_VERSIONS: Record<string, string> = {
  mft: '1', evtx: '1', prefetch: '1', pcap: '1', webcache: '1',
  sqle: '1', bash_history: '1', syslog: '1',
};
