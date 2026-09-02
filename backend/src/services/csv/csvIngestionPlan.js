// Decide, per CSV found in a collection, whether to ingest it.
//
// Precedence is per ARTIFACT TYPE, not per file: inferring that a given CSV was
// produced from a given raw file would need fragile heuristics, and the type is
// all the decision actually depends on.

/**
 * Row count, whichever field this artifact type's parse path used.
 *
 * collection.js has two shapes: most types (evtx, mft, prefetch, lnk, jumplist,
 * registry, srum, ...) write { status: 'success'|'degraded'|'error', normalized_records }
 * (collection.js:1522-1537); pcap and rdpcache write { status: 'ok'|'empty', records }
 * (collection.js:1308, :1323) and never reach this planner (excluded from derived
 * mappings). The status vocabulary differs across both and may grow further, so the
 * count — not the status string — is what the predicates below key on.
 */
function rowCount(entry) {
  const n = entry.normalized_records ?? entry.records ?? 0;
  const v = Number(n);
  return Number.isFinite(v) ? v : 0;
}

/**
 * A native result that produced rows. 'skipped' means the raw parse for this type
 * never ran at all — see the caveat on nativeTriedAndFailed below for why that is
 * NOT the same as "no raw files existed".
 */
function nativeProducedRows(entry) {
  return !!entry && entry.status !== 'skipped' && rowCount(entry) > 0;
}

/**
 * Raw parsing for this type was attempted but yielded nothing usable.
 *
 * 'skipped' is excluded here, but it is not a clean "raw files were absent" signal:
 * collection.js emits status 'skipped' from three sites with different reasons —
 * :1196 "unsupported OS", :1205 "tool not installed", and only :1213 "No files found".
 * The first two can fire even when raw files WERE present but never got a chance to
 * parse. Treating all of them as "absent" is a deliberate simplification (a CSV should
 * still import when the native tool couldn't run), not a claim that files were absent.
 */
function nativeTriedAndFailed(entry) {
  return !!entry && entry.status !== 'skipped' && rowCount(entry) === 0;
}

// CSVs a native parser already consumes, matched on the filename suffix because
// Cat-Scale prefixes every output with `<host>-<DTG>-`.
//
// Precedence by artifact type cannot cover these. `full-timeline.csv` detects to no
// artifact type at all, so `results[undefined]` is undefined and the planner fell
// through to "no raw parse attempted for this type" — import. That stayed invisible
// only because the CSV parser rejected the file over a quote in a filename; with
// relax_quotes the import would succeed and write up to 8,587,252 raw rows on top of
// the 332,108 that catscaleService.ts:1114 already produced from the same file, after
// deliberately filtering 8,255,144 entries (containers, rebuildable, packages, not
// relevant). The same evidence counted twice, once curated and once not.
//
// Skipped as redundant rather than dropped from the plan: `skipped_redundant` is
// tallied into the `[csv] N CSV: {...}` line, so a file we chose not to import stays
// visible and counted.
const CLAIMED_BY_NATIVE = [
  { suffix: 'full-timeline.csv', by: 'the CatScale filesystem-timeline parser' },
];

function claimedByNative(file) {
  const name = String(file || '').toLowerCase();
  return CLAIMED_BY_NATIVE.find(c => name.endsWith(c.suffix)) || null;
}

function planCsvIngestion({ csvFiles, nativeResults, detect }) {
  const files = csvFiles || [];
  const results = nativeResults || {};
  return files.map((file) => {
    const claim = claimedByNative(file);
    if (claim) {
      return { file, artifactType: null, decision: 'skipped_redundant', reason: `claimed by ${claim.by}` };
    }

    const mapping = detect(file);
    if (!mapping) {
      return { file, artifactType: null, decision: 'skipped_no_mapping', reason: 'no mapping matched' };
    }

    const artifactType = mapping.artifact_type;
    const native = results[artifactType];

    if (nativeProducedRows(native)) {
      return { file, artifactType, decision: 'skipped_redundant', reason: 'raw artifact already parsed' };
    }
    if (nativeTriedAndFailed(native)) {
      return { file, artifactType, decision: 'imported_fallback', reason: `raw parse status: ${native.status}, 0 rows` };
    }
    return { file, artifactType, decision: 'imported', reason: 'no raw parse attempted for this type' };
  });
}

module.exports = { planCsvIngestion, CLAIMED_BY_NATIVE };
