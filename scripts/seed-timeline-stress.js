#!/usr/bin/env node
/*
 * Dev-only timeline stress seeder. Injects N synthetic rows into collection_timeline
 * for an existing case so the Timeline Explorer can be profiled on realistic volume.
 *
 * Usage:
 *   node scripts/seed-timeline-stress.js <caseId> [rowCount=250000]
 *
 * Mix: 50% MFT, 30% Evtx, 20% Hayabusa. Each row gets a unique dedupe_hash so the
 * ON CONFLICT guard doesn't silently drop inserts.
 */

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const { Pool } = require('pg');
const crypto = require('crypto');

const caseId = parseInt(process.argv[2], 10);
const total  = parseInt(process.argv[3] || '250000', 10);

if (!Number.isFinite(caseId)) {
  console.error('usage: node seed-timeline-stress.js <caseId> [rowCount=250000]');
  process.exit(1);
}

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME     || 'forensiclab',
  user:     process.env.DB_USER     || 'forensiclab',
  password: process.env.DB_PASSWORD,
  ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

const HOSTS  = ['DC01', 'WS-ADM', 'WS-IT-03', 'WS-FIN-12', 'SRV-FILE', 'SRV-WEB'];
const USERS  = ['alice', 'bob', 'charlie', 'SYSTEM', 'admin', 'svc_backup'];
const EXTS   = ['exe', 'dll', 'ps1', 'lnk', 'docx', 'xlsx', 'zip', 'pdf'];
const EVTIDS = [4624, 4625, 4688, 1102, 7045, 4672, 4776, 5140];
const MITRES = ['T1059.001', 'T1078', 'T1110', 'T1547.001', 'T1055', null, null, null];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function buildRow(i, baseTs) {
  const roll = Math.random();
  let tool, artifact, source, eventId = null, ext = null, desc;
  if (roll < 0.5) {
    tool = 'MFTECmd'; artifact = 'mft'; source = 'MFT';
    ext = pick(EXTS);
    desc = `\\Users\\${pick(USERS)}\\AppData\\file-${i}.${ext}`;
  } else if (roll < 0.8) {
    tool = 'EvtxECmd'; artifact = 'evtx'; source = 'Security.evtx';
    eventId = pick(EVTIDS);
    desc = `Event ${eventId} on ${pick(HOSTS)}`;
  } else {
    tool = 'Hayabusa'; artifact = 'hayabusa'; source = 'hayabusa';
    eventId = pick(EVTIDS);
    desc = `Hayabusa rule hit ${eventId}`;
  }

  const ts = new Date(baseTs + i * 1000 + Math.floor(Math.random() * 500)).toISOString();
  const host = pick(HOSTS);
  const user = pick(USERS);
  const mitre = pick(MITRES);
  const dedupe = crypto.createHash('sha1')
    .update(`${ts}|${source}|${artifact}|${desc}|${eventId ?? ''}|stress${i}`)
    .digest('hex').slice(0, 16);

  return {
    ts, artifact, source, desc, tool, eventId, ext, host, user, mitre, dedupe,
    raw: { _seed: true, i, EventID: eventId, Ext: ext, Host: host, User: user },
  };
}

async function main() {
  const client = await pool.connect();
  try {
    const { rows: caseRows } = await client.query('SELECT id, title FROM cases WHERE id=$1', [caseId]);
    if (caseRows.length === 0) { console.error(`case ${caseId} not found`); process.exit(2); }
    console.log(`seeding ${total.toLocaleString()} rows into case ${caseId} (${caseRows[0].title})`);

    const baseTs = Date.now() - 1000 * total;
    const BATCH = 2000;
    const started = Date.now();

    for (let off = 0; off < total; off += BATCH) {
      const n = Math.min(BATCH, total - off);
      const values = [];
      const params = [];
      let p = 1;
      for (let i = 0; i < n; i++) {
        const r = buildRow(off + i, baseTs);
        values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
        params.push(
          caseId, r.ts, r.artifact, r.source, r.desc,
          r.tool, r.eventId, r.ext, r.host, r.user, r.mitre, r.dedupe,
          JSON.stringify(r.raw), 'stress-seed',
        );
      }
      await client.query(
        `INSERT INTO collection_timeline
          (case_id, timestamp, artifact_type, source, description,
           tool, event_id, ext, host_name, user_name, mitre_technique_id, dedupe_hash, raw, artifact_name)
         VALUES ${values.join(',')}
         ON CONFLICT (case_id, dedupe_hash) DO NOTHING`,
        params,
      );
      if ((off + n) % 20000 === 0 || off + n === total) {
        const pct = ((off + n) / total * 100).toFixed(1);
        const elapsed = ((Date.now() - started) / 1000).toFixed(1);
        console.log(`  ${off + n}/${total} (${pct}%) · ${elapsed}s`);
      }
    }

    const { rows: cnt } = await client.query(
      `SELECT COUNT(*)::int AS n FROM collection_timeline WHERE case_id=$1 AND artifact_name='stress-seed'`,
      [caseId],
    );
    console.log(`done — ${cnt[0].n.toLocaleString()} stress rows in case ${caseId}`);
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(e => { console.error(e); process.exit(1); });
