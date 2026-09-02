// Scan a collection directory for loose CSVs the native per-type parsers never
// claim (no ARTIFACT_PATTERNS entry matches *.csv), classify each one against
// the native parse outcome, and import whatever the plan accepts.
//
// Extracted out of routes/collection.js so this — the highest-risk new logic
// in the CSV-ingestion feature — is unit-testable without spinning the whole
// /:caseId/parse route (external tool spawns, live case/evidence rows, etc.).
// `detect` / `importFile` are injected, defaulting to the real header-sniffing
// detector and the real importCsvFile service, the same DI pattern
// workers/huntTrigger.ts's maybeTriggerHunt already uses in this codebase so
// tests can substitute stubs.
const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const logger = require('../../config/logger').default;
const { findCsvFilesRecursive } = require('./findCsvFiles');
const { planCsvIngestion } = require('./csvIngestionPlan');
const { detectMapping } = require('../timelineMappings');
const { importCsvFile } = require('./importCsvFile');

// Peek only the first 8KB of each file for its header row — collections
// routinely contain multi-gigabyte CSVs, so this must never read the whole
// file into memory. A header row longer than this (or an unreadable file)
// degrades gracefully to filename/folder-only detection rather than erroring;
// no real-world CSV header approaches this size, so the cap is left as-is.
const HEADER_PEEK_BYTES = 8192;

function defaultDetect(file) {
  let headers = [];
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(HEADER_PEEK_BYTES);
    const n = fs.readSync(fd, buf, 0, HEADER_PEEK_BYTES, 0);
    const firstLine = buf.slice(0, n).toString('utf8').replace(/^﻿/, '').split(/\r?\n/)[0] || '';
    // relax_quotes here too, so header detection cannot reject a file the importer
    // below would have read. A header column carrying a quote is rare, but the two
    // parsers disagreeing about the same file is the kind of split that ends with
    // "no mapping found" standing in for "we refused to look".
    headers = parse(firstLine + '\n', {
      columns: false, skip_empty_lines: true, relax_column_count: true, relax_quotes: true,
    })[0] || [];
  } catch (_e) {
    /* unreadable header — filename/folder detection strategies still apply */
  } finally {
    // fs.readSync throwing must not leak the descriptor — closeSync has to run
    // whether or not the read above succeeded.
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_e) { /* already gone */ } }
  }
  return detectMapping({ filename: path.basename(file), folderPath: path.dirname(file), headers })?.mapping ?? null;
}

const EMPTY_RESULT = Object.freeze({
  imported: 0, imported_fallback: 0, skipped_redundant: 0, skipped_no_mapping: 0, error: 0, files: [],
});

/**
 * @param {import('pg').Pool} pool
 * @param {{ collDir: string, caseId: string, evidenceId: string|null, resultId: string,
 *           nativeResults: object, detect?: (file: string) => object|null,
 *           importFile?: typeof importCsvFile }} ctx
 * @returns {Promise<{ imported: number, imported_fallback: number, skipped_redundant: number,
 *                      skipped_no_mapping: number, error: number, files: object[] }>}
 *
 * Never rejects: an unreadable directory, a bad file, or an unexpected
 * exception anywhere in this scan degrades to the empty result rather than
 * costing a collection parse that already succeeded for every raw artifact.
 */
async function scanCollectionCsvs(pool, { collDir, caseId, evidenceId, resultId, nativeResults, detect = defaultDetect, importFile = importCsvFile }) {
  try {
    const collectionCsvs = findCsvFilesRecursive(collDir);
    if (!collectionCsvs.length) return { ...EMPTY_RESULT };

    // Memoized per file path: planCsvIngestion calls detect() once to classify
    // each file, and the import loop below needs the same mapping object
    // again for the same file. Without this every CSV would have its header
    // read and parsed twice, and — worse — a transient failure on only the
    // second read would silently yield headers: [] and insert 0 rows instead
    // of surfacing as an error.
    const detectCache = new Map();
    const cachedDetect = (file) => {
      if (!detectCache.has(file)) detectCache.set(file, detect(file));
      return detectCache.get(file);
    };

    const decisions = planCsvIngestion({ csvFiles: collectionCsvs, nativeResults, detect: cachedDetect });

    // Import everything the plan accepted, reusing the same per-file service
    // the manual /import-csv route uses. One bad file must not sink the rest.
    for (const d of decisions) {
      if (!d.decision.startsWith('imported')) continue;
      const mapping = cachedDetect(d.file);
      try {
        const r = await importFile(pool, {
          caseId, resultId, evidenceId,
          filePath: d.file, filename: path.basename(d.file), mapping,
        });
        d.inserted = r.inserted;
      } catch (err) {
        d.decision = 'error';
        d.reason = err.message;
        logger.warn(`[csv] import failed for ${path.basename(d.file)}: ${err.message}`);
      }
    }

    // Tallied after the import loop (not before) so a file that failed to
    // import is counted as 'error', not left double-booked under whichever
    // decision the plan gave it before the attempt.
    const counts = { imported: 0, imported_fallback: 0, skipped_redundant: 0, skipped_no_mapping: 0, error: 0 };
    for (const d of decisions) counts[d.decision] = (counts[d.decision] || 0) + 1;
    logger.info(`[csv] ${collectionCsvs.length} CSV: ${JSON.stringify(counts)}`);
    return { ...counts, files: decisions };
  } catch (e) {
    logger.warn('[csv] collection scan error:', e.message);
    return { ...EMPTY_RESULT };
  }
}

module.exports = { scanCollectionCsvs, defaultDetect, HEADER_PEEK_BYTES };
