// Turn one CSV into collection_timeline rows. Shared by the manual /import-csv
// route and the automatic collection scan — a second copy of this logic would
// drift, and a drifted dedupe_hash silently defeats the unique index.
//
// importCsvFile(pool, { caseId, resultId, evidenceId, filePath, filename, mapping })
//   pool     — pg Pool/client to query against.
//   mapping  — the already-detected mapping object (from
//              timelineMappings.detectMapping); mapping detection itself stays
//              with the caller.
//   filename — accepted for parity with the route's per-file bookkeeping even
//              though the row-level logic below doesn't need it.
//
// Return contract: resolves with { status: 'ok', inserted, skipped } once the
// whole file has been streamed and flushed. `status` is only ever 'ok' here —
// this function does not decide 'skipped' (that's the caller's job, before
// ever calling in: "no mapping matched" is resolved upstream) and it does not
// catch stream/parse-fatal errors into a `{ status: 'error' }` result. Such
// errors (a malformed stream, an `fs.createReadStream` failure, csv-parse's
// own 'error' event) reject the returned promise instead, exactly like the
// original /import-csv loop let them propagate to the route's own try/catch.
// Callers that want per-file error isolation (e.g. so one bad file in a batch
// doesn't abort the rest) must wrap their own call in try/catch — this
// function does not do it for them, to keep behaviour byte-identical to what
// the route did before this extraction.
const fs = require('fs');
const { parse: parseStream } = require('csv-parse');
const { applyMapping } = require('../timelineMappings');
const { stripNullBytes, normalizeTimestamp, extractTimestamp } = require('../timelineNormalizeCore');
const { extractForensicFields } = require('../timelineForensicFields');

async function importCsvFile(pool, { caseId, resultId, evidenceId, filePath, filename, mapping }) {
  let inserted = 0, skipped = 0;
  const BATCH = 2000;
  let batch = [];

  const flush = async () => {
    if (batch.length === 0) return;
    const rows = batch; batch = [];
    const cases = [], results = [], evs = [], tss = [], types = [], names = [], descs = [], srcs = [], raws = [];
    const hns = [], uns = [], pns = [], mtis = [], mtns = [], mts = [], sds = [];
    const tools = [], tks = [], dts = [], pths = [], exs = [], eids = [], fss = [], sips = [], dips = [], s1s = [], dhs = [], tgs = [];
    const seen = new Set();
    for (const rec of rows) {
      if (rec.dedupe_hash && seen.has(rec.dedupe_hash)) { skipped++; continue; }
      if (rec.dedupe_hash) seen.add(rec.dedupe_hash);
      cases.push(caseId); results.push(resultId); evs.push(evidenceId);
      tss.push(rec.timestamp); types.push(rec.artifact_type); names.push(rec.artifact_name);
      descs.push(rec.description); srcs.push(rec.source); raws.push(JSON.stringify(rec.raw));
      hns.push(rec.host_name); uns.push(rec.user_name); pns.push(rec.process_name || null);
      mtis.push(null); mtns.push(null); mts.push(null); sds.push(null);
      tools.push(rec.tool); tks.push(rec.timestamp_kind); dts.push(rec.details);
      pths.push(rec.path); exs.push(rec.ext);
      eids.push(rec.event_id == null ? null : rec.event_id);
      fss.push(rec.file_size == null ? null : rec.file_size);
      sips.push(rec.src_ip); dips.push(rec.dst_ip); s1s.push(rec.sha1); dhs.push(rec.dedupe_hash);
      tgs.push(JSON.stringify(Array.isArray(rec.tags) ? rec.tags : []));
    }
    if (cases.length === 0) return;
    const r = await pool.query(
      `INSERT INTO collection_timeline
         (case_id, result_id, evidence_id, timestamp, artifact_type, artifact_name, description, source, raw,
          host_name, user_name, process_name, mitre_technique_id, mitre_technique_name, mitre_tactic, source_device,
          tool, timestamp_kind, details, "path", ext, event_id, file_size, src_ip, dst_ip, sha1, dedupe_hash, tags)
       SELECT u.case_id, u.result_id, u.evidence_id, u.ts, u.art_type, u.art_name, u.descr, u.src, u.rw,
              u.hn, u.un, u.pn, u.mti, u.mtn, u.mt, u.sd,
              u.tl, u.tk, u.dt, u.pth, u.ex, u.eid, u.fs, u.sip, u.dip, u.s1, u.dh,
              COALESCE(ARRAY(SELECT jsonb_array_elements_text(u.tg_json)), '{}')::text[]
         FROM UNNEST(
           $1::uuid[], $2::uuid[], $3::uuid[], $4::timestamptz[], $5::text[], $6::text[], $7::text[], $8::text[], $9::jsonb[],
           $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[],
           $17::text[], $18::text[], $19::text[], $20::text[], $21::text[], $22::int[], $23::bigint[], $24::inet[], $25::inet[], $26::text[], $27::text[],
           $28::jsonb[]
         ) AS u(case_id, result_id, evidence_id, ts, art_type, art_name, descr, src, rw,
                hn, un, pn, mti, mtn, mt, sd,
                tl, tk, dt, pth, ex, eid, fs, sip, dip, s1, dh, tg_json)
       ON CONFLICT DO NOTHING`,
      [cases, results, evs, tss, types, names, descs, srcs, raws,
       hns, uns, pns, mtis, mtns, mts, sds,
       tools, tks, dts, pths, exs, eids, fss, sips, dips, s1s, dhs, tgs]
    );
    inserted += r.rowCount;
    skipped  += (cases.length - r.rowCount);
  };

  await new Promise((resolve, reject) => {
    const parser = parseStream({ columns: true, skip_empty_lines: true, relax_column_count: true, encoding: 'utf8' });
    parser.on('data', async (rec) => {
      parser.pause();
      try {
        const mapped = applyMapping(mapping, stripNullBytes(rec));
        const ts = mapped.raw_timestamp ? normalizeTimestamp(String(mapped.raw_timestamp)) : null;
        if (!ts) { skipped++; parser.resume(); return; }
        const description = String(mapped.description || '').slice(0, 2000);
        const source = String(mapped.source || '').slice(0, 500);
        // Latent gap: this resolves against mapping.timestamp_columns, the same
        // list the native path's config.timestampColumns mirrors — but that list
        // and mapping.columns.timestamp (used elsewhere by applyMapping/pick) are
        // populated independently. A future mapping YAML that adds a timestamp
        // column to columns.timestamp but not timestamp_columns would reopen the
        // native/CSV hash divergence this fix closes. No current mapping does that.
        const tsResolved = extractTimestamp(rec, mapping.timestamp_columns);
        const forensic = extractForensicFields(
          rec, mapped.artifact_type, { tool: mapping.tool },
          tsResolved ? tsResolved.column : (mapping.timestamp_columns[0] || null),
          ts, description, source,
        );
        // Override forensic fields with explicit mapping values when present
        const rowToInsert = {
          timestamp: ts,
          artifact_type: mapped.artifact_type,
          artifact_name: mapped.artifact_name,
          description, source,
          raw: Object.fromEntries(Object.entries(rec).slice(0, 20)),
          host_name: mapped.host_name || null,
          user_name: mapped.user_name || null,
          process_name: mapped.process_name || null,
          ...forensic,
          tool: mapping.tool,
          event_id: mapped.event_id != null && /^\d+$/.test(String(mapped.event_id).trim()) ? parseInt(mapped.event_id, 10) : forensic.event_id,
          ext: mapped.ext ? String(mapped.ext).toLowerCase().slice(0, 16) : forensic.ext,
          path: mapped.path || forensic.path,
          file_size: mapped.file_size != null && /^\d+$/.test(String(mapped.file_size).trim()) ? parseInt(mapped.file_size, 10) : forensic.file_size,
          src_ip: mapped.src_ip || forensic.src_ip,
          dst_ip: mapped.dst_ip || forensic.dst_ip,
          sha1:   /^[a-f0-9]{40}$/i.test(String(mapped.sha1 || '').trim()) ? String(mapped.sha1).toLowerCase() : forensic.sha1,
          details: mapped.details != null ? String(mapped.details).slice(0, 200000) : forensic.details,
        };
        batch.push(rowToInsert);
        if (batch.length >= BATCH) { await flush(); }
      } catch (e) { skipped++; }
      finally { parser.resume(); }
    });
    parser.on('end',   async () => { try { await flush(); resolve(); } catch (e) { reject(e); } });
    parser.on('error', reject);

    const src = fs.createReadStream(filePath);
    let bomChecked = false;
    src.on('data', (chunk) => {
      if (!bomChecked) {
        bomChecked = true;
        if (chunk[0] === 0xEF && chunk[1] === 0xBB && chunk[2] === 0xBF) chunk = chunk.slice(3);
      }
      if (!parser.write(chunk)) { src.pause(); parser.once('drain', () => src.resume()); }
    });
    src.on('end',   () => parser.end());
    src.on('error', reject);
  });

  return { status: 'ok', inserted, skipped };
}

module.exports = { importCsvFile };
