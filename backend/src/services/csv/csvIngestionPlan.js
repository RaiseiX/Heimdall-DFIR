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

function planCsvIngestion({ csvFiles, nativeResults, detect }) {
  const files = csvFiles || [];
  const results = nativeResults || {};
  return files.map((file) => {
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

module.exports = { planCsvIngestion };
