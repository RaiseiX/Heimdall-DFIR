// Unified forensic-field extraction (v2.23, inspired by forensic-timeliner).
// Kept out of routes/collection.js so it can be consumed without importing the
// router (and, transitively, the router's elasticsearch/redis/multer/auth
// requires and its top-level DB auto-migration side effect) — mirrors what
// config/artifactPatterns.js already does for the static artifact tables.
//
// Promotes raw JSONB values to first-class columns (tool / timestamp_kind /
// event_id / ext / path / file_size / sha1 / src_ip / dst_ip / details) and
// computes a stable dedupe_hash for the unique (case_id, dedupe_hash) index.
// Both the native ingest path (routes/collection.js) and the CSV path
// (services/csv/importCsvFile.js) call this same function so the hash can
// never diverge between them.
const crypto = require('crypto');
const { matchTags: matchKeywordTags } = require('./timelineKeywords');
const threatEngine = require('./threatEngine');

function extractForensicFields(record, artifactType, config, tsColumn, description, source) {
  const toolRaw = (config && config.tool) || artifactType;
  const tool = String(toolRaw).replace(/\.[^.]+$/, '').slice(0, 32);

  const eventIdRaw = record['EventId'] || record['EventID'] || record['event_id'] || null;
  const eventId = eventIdRaw !== null && /^\d+$/.test(String(eventIdRaw).trim())
    ? parseInt(eventIdRaw, 10) : null;

  const nameForExt = record['FileName'] || record['ExecutableName']
    || record['TargetFilename'] || record['Path'] || record['FullPath'] || source || '';
  let extVal = (record['Extension'] || record['FileExtension'] || '').toString().toLowerCase().trim();
  if (!extVal) {
    const m = /\.([A-Za-z0-9]{1,10})$/.exec(nameForExt);
    if (m) extVal = '.' + m[1].toLowerCase();
  }
  extVal = extVal ? extVal.slice(0, 16) : null;

  const pathVal = record['FolderPath'] || record['FullPath'] || record['TargetPath']
    || record['SourceFilename'] || record['Path'] || source || null;

  const sizeRaw = record['FileSize'] || record['Size'] || record['FileSizeBytes'] || null;
  const fileSize = sizeRaw !== null && /^\d+$/.test(String(sizeRaw).trim())
    ? Math.min(parseInt(sizeRaw, 10), Number.MAX_SAFE_INTEGER) : null;

  const sha1Raw = (record['SHA1'] || record['Sha1'] || record['SHA-1'] || '').toString().trim().toLowerCase();
  const sha1 = /^[a-f0-9]{40}$/.test(sha1Raw) ? sha1Raw : null;

  const ipRe = /(\d{1,3}\.){3}\d{1,3}/;
  const srcIpCand = String(record['SourceIp'] || record['SrcIP'] || record['src_ip'] || '');
  const dstIpCand = String(record['DestinationIp'] || record['DstIP'] || record['dst_ip'] || '');
  const srcIp = (srcIpCand.match(ipRe) || [])[0] || null;
  const dstIp = (dstIpCand.match(ipRe) || [])[0] || null;

  let details = null;
  if (artifactType === 'evtx') {
    details = [record['PayloadData1'], record['PayloadData2']].filter(Boolean).join(' | ') || null;
  } else if (artifactType === 'prefetch') {
    const rc = record['RunCount'];
    details = rc ? `run_count=${rc}` : null;
  } else if (artifactType === 'mft') {
    const ads = record['HasAds'] === 'True' ? 'ADS' : null;
    details = [ads, record['ZoneIdContents']].filter(Boolean).join(' | ') || null;
  }
  if (details) details = details.slice(0, 500);

  // EVTX: EventRecordId+Computer make the record globally unique without relying on description truncation.
  // MFT: EntryNumber+SequenceNumber is the stable per-file identity in the MFT.
  // Without these, high-frequency events (same EventId+Channel+second) collide and are silently dropped.
  const extraUnique =
    artifactType === 'evtx'
      ? `|${record['EventRecordId'] || record['RecordNumber'] || ''}|${record['Computer'] || ''}`
      : artifactType === 'mft'
      ? `|${record['EntryNumber'] || ''}|${record['SequenceNumber'] || ''}`
      : '';

  const dedupeHash = crypto
    .createHash('md5')
    .update([
      tsColumn || '', source || '', artifactType || '',
      (description || '').slice(0, 200), eventId == null ? '' : String(eventId),
    ].join('|') + extraUnique)
    .digest('hex')
    .slice(0, 16);

  // v2.23 — keyword enrichment (matches backend/config/timeline_keywords.yaml)
  let tags = [];
  try { tags = matchKeywordTags(record, description); } catch (_e) {}

  // v2.26 — Threat Engine: per-row detection evaluation.
  // Builds a synthetic record shape the engine expects (artifact_type, event_id,
  // description, source, path, process_name, ext). Runs bucketed matching.
  let detections = null;
  try {
    const engineRecord = {
      ...record,
      artifact_type: artifactType,
      event_id: eventId,
      description,
      source,
      path: pathVal,
      ext: extVal,
    };
    const hit = threatEngine.evaluate(engineRecord);
    if (hit) {
      detections = hit.detections;
      if (hit.tags && hit.tags.length) {
        const seen = new Set(tags);
        for (const t of hit.tags) if (!seen.has(t)) { tags.push(t); seen.add(t); }
      }
    }
  } catch (_e) {}

  return {
    tool, timestamp_kind: tsColumn || null,
    event_id: eventId, ext: extVal, path: pathVal, file_size: fileSize,
    sha1, src_ip: srcIp, dst_ip: dstIp, details,
    tags,
    detections,
    dedupe_hash: dedupeHash,
  };
}

module.exports = { extractForensicFields };
