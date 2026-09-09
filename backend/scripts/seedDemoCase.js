#!/usr/bin/env node
'use strict';

// Synthetic presentation dataset. No files, credentials or collected evidence are read.
// Usage (from backend): node scripts/seedDemoCase.js --owner <existing-user> [--apply]
// The default runs all inserts inside a transaction and rolls them back.
const { createHash } = require('node:crypto');

const CASE_ID = '9de00000-0000-4000-8000-000000000001';
const CASE_NUMBER = 'DEMO-HEIMDALL-01';
const MARKER = '[heimdall-synthetic-demo:v1]';
const SEED_LOCK = 7410927;
const AUDIT_ACTION = 'seed_synthetic_demo';
const EVIDENCE_ID = '9de00000-0000-4000-8000-000000000002';
const RESULT_ID = '9de00000-0000-4000-8000-000000000003';
const epoch = Date.parse('2026-06-12T08:00:00.000Z');
const at = minutes => new Date(epoch + minutes * 60000).toISOString();
const uuid = n => `9de00000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const json = value => JSON.stringify(value);

// Same reference convention as frontend/supertimeline/utils/timelineUtils.computeRef.
function artifactRef(row) {
  const input = `${row.timestamp || ''}|${row.artifact_type || ''}|${row.source || ''}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i++) hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  return Math.abs(hash).toString(16).substring(0, 8).padStart(8, '0');
}

function parseArgs(args) {
  let owner;
  let apply = false;
  let modeSeen = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' && args.length === 1) return { help: true };
    if (args[i] === '--owner' && owner === undefined) owner = args[++i];
    else if ((args[i] === '--apply' || args[i] === '--dry-run') && !modeSeen) {
      apply = args[i] === '--apply';
      modeSeen = true;
    } else throw new Error('Use --owner <existing-user> and at most one of --apply or --dry-run.');
  }
  if (typeof owner !== 'string' || !/^[A-Za-z0-9_.@-]{1,50}$/.test(owner)) {
    throw new Error('--owner must name an existing active admin or analyst (1–50 username characters).');
  }
  return { owner, apply };
}

function buildDataset(ownerId) {
  const hosts = ['LAB-WS01', 'LAB-DC01', 'LAB-FS01'];
  const patterns = [
    ['evtx', 'Interactive sign-in', 'Synthetic successful lab sign-in', 'winlogon.exe', 4624],
    ['evtx', 'Process creation', 'Synthetic endpoint service start', 'svchost.exe', 4688],
    ['prefetch', 'Application execution', 'Synthetic document viewer execution trace', 'notepad.exe', null],
    ['amcache', 'Application inventory', 'Synthetic lab application inventory record', 'lab-agent.exe', null],
    ['evtx', 'Directory service activity', 'Synthetic routine domain authentication', 'lsass.exe', 4768],
    ['evtx', 'File access', 'Synthetic access to a training document', 'explorer.exe', 4663],
  ];
  const signals = {
    34: ['DEMO: Unusual PowerShell parent', 'high', 'powershell.exe', 'T1059.001', 'PowerShell', 'Execution', 'Observed: synthetic process ancestry diverges from baseline.'],
    57: ['DEMO: Local account discovery', 'medium', 'net.exe', 'T1087.001', 'Local Account', 'Discovery', 'Observed: synthetic account enumeration follows script execution.'],
    79: ['DEMO: Remote service creation', 'high', 'services.exe', 'T1569.002', 'Service Execution', 'Execution', 'Observed: synthetic service creation on LAB-FS01. Remote origin remains a hypothesis.'],
    102: ['DEMO: Remote logon correlation', 'high', 'winlogon.exe', 'T1021.001', 'Remote Desktop Protocol', 'Lateral Movement', 'Observed: synthetic remote logon overlaps workstation activity. Intent is not established.'],
    121: ['DEMO: Archive staging', 'medium', 'tar.exe', 'T1560.001', 'Archive via Utility', 'Collection', 'Observed: synthetic archive process. No exfiltration is demonstrated.'],
  };
  const timeline = Array.from({ length: 160 }, (_, i) => {
    const pattern = patterns[i % patterns.length];
    const signal = signals[i];
    const host = signal && i >= 79 ? 'LAB-FS01' : hosts[i % hosts.length];
    const eventId = signal ? (i === 79 ? 7045 : i === 102 ? 4624 : 4688) : pattern[4];
    const detection = signal ? [{ source: 'sigma', name: signal[0], severity: signal[1],
      rule_id: `heimdall-demo-${i}`, category: signal[5].toLowerCase().replaceAll(' ', '_'),
      synthetic: true, provenance: 'Hand-authored demonstration; no detection engine executed.' }] : [];
    return {
      id: -7410000001 - i, case_id: CASE_ID, result_id: RESULT_ID, evidence_id: EVIDENCE_ID,
      timestamp: at(i * 1.5), artifact_type: signal ? 'evtx' : pattern[0],
      artifact_name: signal ? signal[0] : pattern[1], description: signal ? signal[6] : pattern[2],
      source: 'Synthetic lab dataset / not acquired evidence',
      raw: json({ synthetic: true, generator: MARKER, record: i + 1, Computer: host,
        Channel: 'Heimdall-Demo', EventID: eventId,
        ...(i === 34 ? { ParentImage: 'WINWORD.EXE', Image: 'powershell.exe' } : {}),
        ...(i === 102 ? { LogonType: 10, TargetUserName: 'demo.analyst' } : {}) }),
      host_name: host, user_name: 'BIFROST\\demo.analyst', process_name: signal ? signal[2] : pattern[3],
      mitre_technique_id: signal ? signal[3] : null, mitre_technique_name: signal ? signal[4] : null,
      mitre_tactic: signal ? signal[5] : null, tool: 'Heimdall_Demo', timestamp_kind: 'synthetic_event',
      details: signal ? signal[6] : 'Fictional baseline activity for interface demonstration.',
      event_id: eventId, tags: ['demo', 'synthetic', ...(signal ? ['review'] : [])],
      dedupe_hash: createHash('sha256').update(`${MARKER}:${i}`).digest('hex').slice(0, 16),
      detections: json(detection),
    };
  });
  const links = [
    ['LAB-WS01', '10.77.0.21', '10.77.0.10', 53, 'UDP', 'svchost.exe', false, 'Routine synthetic DNS'],
    ['LAB-WS01', '10.77.0.21', '10.77.0.10', 88, 'TCP', 'lsass.exe', false, 'Routine synthetic Kerberos'],
    ['LAB-WS01', '10.77.0.21', '192.0.2.80', 443, 'TCP', 'powershell.exe', true, 'Documentation address; simulated unusual outbound session'],
    ['LAB-WS01', '10.77.0.21', '10.77.0.30', 445, 'TCP', 'System', true, 'Simulated SMB session; lateral movement is a hypothesis'],
    ['LAB-WS01', '10.77.0.21', '10.77.0.30', 3389, 'TCP', 'mstsc.exe', true, 'Simulated remote desktop session'],
    ['LAB-FS01', '10.77.0.30', '10.77.0.10', 389, 'TCP', 'lsass.exe', false, 'Routine synthetic LDAP'],
    ['LAB-DC01', '10.77.0.10', '198.51.100.53', 53, 'UDP', 'dns.exe', false, 'Documentation address; simulated resolver'],
    ['LAB-FS01', '10.77.0.30', '203.0.113.44', 443, 'TCP', 'lab-agent.exe', false, 'Documentation address; simulated training endpoint'],
  ];
  const findings = [34, 79, 102, 121].map((index, i) => ({
    id: uuid(100 + i), case_id: CASE_ID, artifact_ref: artifactRef(timeline[index]), event_timestamp: timeline[index].timestamp,
    title: signals[index][0], description: `${signals[index][6]} This finding is fictional and manually authored for the demo.`,
    mitre_technique: signals[index][3], mitre_tactic: signals[index][5], color: '#b68745',
    significance: 'Training observation. Validate chronology and provenance before drawing an incident conclusion.',
    confidence: i === 2 ? 'medium' : 'high', links_to: i ? uuid(99 + i) : null, author_id: ownerId,
  }));
  return {
    cases: [{ id: CASE_ID, case_number: CASE_NUMBER, title: 'DEMO — Operation Bifrost',
      description: `${MARKER}\nEntirely fictional DFIR training case. Suspicious workstation activity followed by possible lateral movement. No real incident, acquired files or engine-verified detections.`,
      status: 'active', priority: 'high', investigator_id: ownerId, created_by: ownerId, opened_at: at(0) }],
    evidence: [{ id: EVIDENCE_ID, case_id: CASE_ID, name: 'DEMO — Bifrost synthetic Windows collection',
      evidence_type: 'collection', is_highlighted: true, added_by: ownerId, scan_status: null,
      notes: 'Metadata-only synthetic fixture. No acquired file, cryptographic file hash or antivirus scan exists.',
      chain_of_custody: json([]), metadata: json({ synthetic: true, generator: MARKER, platform: 'windows',
        metadata_only: true, hosts, acquisition: 'not_performed', antivirus_scan: 'not_performed' }) }],
    parser_results: [{ id: RESULT_ID, case_id: CASE_ID, evidence_id: EVIDENCE_ID, parser_name: 'Heimdall_Demo',
      parser_version: '1.0', record_count: timeline.length, created_by: ownerId, platform: 'windows',
      output_data: json({ synthetic: true, generator: MARKER, unified_timeline_count: timeline.length,
        note: 'Hand-authored synthetic records; no parser or detection engine executed.' }) }],
    collection_timeline: timeline,
    network_connections: links.map((link, i) => ({ id: uuid(200 + i), case_id: CASE_ID, evidence_id: EVIDENCE_ID,
      src_host: link[0], src_ip: link[1], src_port: 49152 + i, dst_ip: link[2], dst_port: link[3], protocol: link[4],
      process: link[5], is_suspicious: link[6], notes: `SYNTHETIC — ${link[7]}`, socket_state: 'ESTABLISHED',
      bytes_sent: 1400 + i * 2400, bytes_received: 2800 + i * 3100, packet_count: 20 + i * 7,
      first_seen: at(20 + i * 24), last_seen: at(23 + i * 24) })),
    timeline_bookmarks: findings,
    investigation_steps: [
      ['acquisition', 'Record synthetic dataset scope and provenance', 'done'],
      ['examination', 'Compare workstation activity against the lab baseline', 'done'],
      ['analysis', 'Correlate workstation and file-server observations', 'in_progress'],
      ['analysis', 'Test the lateral movement hypothesis', 'todo'],
      ['reporting', 'Document observations, uncertainty and limitations', 'todo'],
    ].map((step, i) => ({ id: uuid(300 + i), case_id: CASE_ID, phase: step[0], title: step[1], status: step[2],
      position: i, created_by: ownerId, assignee_id: ownerId, finding_ref: i === 2 ? findings[2].id : null })),
  };
}

const TABLES = Object.freeze(Object.keys(buildDataset(null)));

async function preflight(client, dataset) {
  const result = await client.query(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = ANY($1::text[])`,
    [[...TABLES, 'users', 'audit_log']]);
  const required = { ...Object.fromEntries(TABLES.map(table => [table, Object.keys(dataset[table][0])])),
    users: ['id', 'username', 'role', 'is_active'],
    audit_log: ['user_id', 'action', 'entity_type', 'entity_id', 'details', 'ip_address', 'created_at', 'hmac', 'prev_hash', 'seq'] };
  const found = new Set(result.rows.map(row => `${row.table_name}.${row.column_name}`));
  const missing = Object.entries(required).flatMap(([table, cols]) => cols.filter(col => !found.has(`${table}.${col}`)).map(col => `${table}.${col}`));
  if (missing.length) throw new Error(`Schema is not ready; apply normal project migrations first. Missing: ${missing.join(', ')}`);
}

async function insertDataset(client, dataset) {
  // Identifiers come only from this module's closed dataset, never from CLI arguments.
  for (const table of TABLES) {
    const rows = dataset[table];
    const columns = Object.keys(rows[0]);
    const values = [];
    const tuples = rows.map(row => `(${columns.map(column => { values.push(row[column]); return `$${values.length}`; }).join(',')})`);
    await client.query(`INSERT INTO "${table}" (${columns.map(column => `"${column}"`).join(',')}) VALUES ${tuples.join(',')}`, values);
  }
}

async function runSeed({ pool, appendAuditRow, owner, apply = false }) {
  const client = await pool.connect();
  let locked = false;
  let transaction = false;
  let committed = false;
  try {
    await client.query("SET statement_timeout = '15s'");
    await client.query("SET lock_timeout = '5s'");
    // A session lock spans the data commit and the helper's independent audit transaction.
    await client.query('SELECT pg_advisory_lock($1::bigint)', [SEED_LOCK]);
    locked = true;
    await client.query('BEGIN');
    transaction = true;
    await preflight(client, buildDataset(null));
    const user = await client.query('SELECT id, role, is_active FROM users WHERE username = $1 FOR SHARE', [owner]);
    if (user.rows.length !== 1 || !user.rows[0].is_active || !['admin', 'analyst'].includes(user.rows[0].role)) {
      throw new Error('Owner must be an existing active admin or analyst. No user was created or changed.');
    }
    const ownerId = user.rows[0].id;
    const existing = await client.query('SELECT id, case_number, description, investigator_id, created_by FROM cases WHERE id = $1 OR case_number = $2 FOR UPDATE', [CASE_ID, CASE_NUMBER]);
    if (existing.rows.length && (existing.rows.length !== 1 || existing.rows[0].id !== CASE_ID
      || existing.rows[0].case_number !== CASE_NUMBER || !existing.rows[0].description?.startsWith(`${MARKER}\n`)
      || existing.rows[0].investigator_id !== ownerId || existing.rows[0].created_by !== ownerId)) {
      throw new Error('Demo identifier/owner collision. Existing data was left untouched.');
    }
    const dataset = buildDataset(ownerId);
    const created = existing.rows.length === 0;
    if (created) await insertDataset(client, dataset);
    await client.query(apply ? 'COMMIT' : 'ROLLBACK');
    transaction = false;
    committed = apply;
    const report = { caseId: CASE_ID, caseNumber: CASE_NUMBER, mode: apply ? 'apply' : 'dry-run',
      status: created ? (apply ? 'created' : 'validated-and-rolled-back') : 'already-exists-unchanged',
      fixtureCounts: Object.fromEntries(TABLES.map(table => [table, dataset[table].length])),
      audit: apply ? 'pending' : 'not-written' };
    if (!apply) return report;
    const audit = await client.query('SELECT 1 FROM audit_log WHERE entity_id = $1 AND action = $2 AND details @> $3::jsonb LIMIT 1',
      [CASE_ID, AUDIT_ACTION, json({ generator: MARKER })]);
    if (audit.rows.length) report.audit = 'already-recorded';
    else {
      try {
        // Reuse the bounded connection; appendAuditRow owns BEGIN/COMMIT and its chain lock.
        await appendAuditRow({ connect: async () => ({ query: client.query.bind(client), release() {} }) },
          { userId: ownerId, action: AUDIT_ACTION, entityType: 'case', entityId: CASE_ID,
            details: { generator: MARKER, synthetic: true, fixtureCounts: report.fixtureCounts,
              operation: created ? 'created' : 'recovered-missing-audit', noFilesAcquired: true } });
        report.audit = created ? 'recorded' : 'recovered';
      } catch {
        report.audit = 'failed';
        report.followUp = 'Case remains committed. Rerun the same --owner and --apply after resolving audit configuration; no dataset is reset.';
      }
    }
    return report;
  } catch (error) {
    if (transaction) await client.query('ROLLBACK').catch(() => {});
    if (committed) throw new Error('Demo data is committed, but follow-up verification failed. Rerun the same owner and --apply to repair audit.');
    throw error;
  } finally {
    if (locked) await client.query('SELECT pg_advisory_unlock($1::bigint)', [SEED_LOCK]).catch(() => {});
    // This CLI owns its pool, and discards the connection rather than leaking session settings.
    client.release(true);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('Usage: node scripts/seedDemoCase.js --owner <existing-active-admin-or-analyst> [--apply | --dry-run]\nDefault: transaction rollback. No files, credentials, migrations or existing cases are changed.');
    return;
  }
  // Source checkouts have a TS logger; production builds may already supply logger.js.
  try { require.resolve('../src/config/logger'); }
  catch { require('ts-node').register({ transpileOnly: true, compilerOptions: { module: 'CommonJS', moduleResolution: 'node' } }); }
  const { pool, readPool } = require('../src/config/database');
  const { appendAuditRow } = require('../src/services/auditChain');
  try {
    const report = await runSeed({ pool, appendAuditRow, ...args });
    console.log(JSON.stringify(report, null, 2));
    if (report.audit === 'failed') process.exitCode = 2;
  } finally { await Promise.all([pool.end(), readPool.end()]); }
}

if (require.main === module) main().catch(error => {
  // Database errors may contain query values: report their code, not their message.
  console.error(error.code ? `Demo seed failed (database code ${error.code}); transaction rolled back unless a committed-state warning was shown.` : error.message);
  process.exitCode = 1;
});

module.exports = { CASE_ID, CASE_NUMBER, MARKER, parseArgs, buildDataset, runSeed, preflight };
