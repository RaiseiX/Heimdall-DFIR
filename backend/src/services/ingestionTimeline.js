const fs = require('fs');
const readline = require('readline');
const { parse: csvParseSync } = require('csv-parse/sync');
const { buildSlimRaw } = require('./timelineFieldExtract');
const { stripNullBytes, extractTimestamp, extractDescription, computeDedupeHash, TIMELINE_FIELD_CONFIG } = require('./timelineNormalizeCore');

const BATCH_SIZE = 500;

function firstNonEmpty(record, cols) {
  for (const c of cols || []) { const v = (record[c] ?? '').toString().trim(); if (v) return v; }
  return null;
}

async function importCsvToTimeline(csvPath, { pool, caseId, resultId, evidenceId, artifactType }) {
  const cfg = TIMELINE_FIELD_CONFIG[artifactType];
  if (!cfg) return 0;                          // unmapped type: no-op
  try { fs.statSync(csvPath); } catch { return 0; }

  let headers = null, first = true, inserted = 0;
  let batch = [];

  const flush = async () => {
    if (!batch.length) return;
    const seen = new Set();
    const rows = batch.filter(r => { if (r.dh && seen.has(r.dh)) return false; if (r.dh) seen.add(r.dh); return true; });
    batch = [];
    const res = await pool.query(
      `INSERT INTO collection_timeline
         (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, host_name, raw, dedupe_hash)
       SELECT $1,$2,$3, u.ts, $4, $5, u.descr, u.src, u.hn, u.rw, u.dh
         FROM UNNEST($6::timestamptz[], $7::text[], $8::text[], $9::text[], $10::jsonb[], $11::text[])
              AS u(ts, descr, src, hn, rw, dh)
       ON CONFLICT DO NOTHING`,
      [caseId, resultId, evidenceId, artifactType, artifactType,
       rows.map(r => r.ts), rows.map(r => r.descr), rows.map(r => r.src),
       rows.map(r => r.hn), rows.map(r => JSON.stringify(r.raw)), rows.map(r => r.dh)]
    );
    inserted += res.rowCount;
  };

  const rl = readline.createInterface({ input: fs.createReadStream(csvPath, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    if (first) { headers = line.split(',').map(h => h.replace(/^"|"$/g, '').trim()); first = false; continue; }
    let rawRec;
    try { [rawRec] = csvParseSync(line, { columns: headers, skip_empty_lines: true, relax_column_count: true }); }
    catch { continue; }
    if (!rawRec) continue;
    const record = stripNullBytes(rawRec);
    const ts = extractTimestamp(record, cfg.timestampColumns);
    if (!ts) continue;
    const description = cfg.describe ? cfg.describe(record) : extractDescription(record, cfg.descriptionColumns);
    const source = firstNonEmpty(record, [cfg.sourceColumn]);
    const host = firstNonEmpty(record, cfg.hostColumns);
    const eventId = cfg.eventIdColumn ? (record[cfg.eventIdColumn] || null) : null;
    const raw = buildSlimRaw(record, artifactType);
    const dh = computeDedupeHash(artifactType, { tsColumn: ts.column, source, description, eventId, record });
    batch.push({ ts: ts.timestamp, descr: description || null, src: source, hn: host, raw, dh });
    if (batch.length >= BATCH_SIZE) await flush();
  }
  await flush();
  return inserted;
}

module.exports = { importCsvToTimeline };
