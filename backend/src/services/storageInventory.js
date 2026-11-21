const fs = require('fs');
const path = require('path');

const UUID_SOURCE = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const UUID_RE = new RegExp(`^${UUID_SOURCE}$`, 'i');
const COLLECTION_NAME_RE = new RegExp(`^case-(${UUID_SOURCE})(?:-|$)`, 'i');
const RDP_CACHE = 'rdp-cache';
const RDP_CACHE_NAME_RE = new RegExp(`^${RDP_CACHE}/(${UUID_SOURCE})$`, 'i');
const IMPORT_PARSER = 'MagnetRESPONSE_Import';
const ANY_UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const TEMP_CASE_OUTPUT_RE = new RegExp(`^(?:parse|hayabusa)-(${ANY_UUID})-`, 'i');
const TEMP_MEMORY_RE = new RegExp(`^memory-(${ANY_UUID})$`, 'i');
const TEMP_RUN_OUTPUT_RE = /^parse-\d+-[a-z0-9]+$/i;

function isAbsent(err) {
  return err && (err.code === 'ENOENT' || err.code === 'ENOTDIR');
}

async function readdirOrEmpty(dir) {
  try {
    return await fs.promises.readdir(dir);
  } catch (err) {
    if (isAbsent(err)) return [];
    throw err;
  }
}

async function lstatOrNull(target) {
  try {
    return await fs.promises.lstat(target);
  } catch (err) {
    if (isAbsent(err)) return null;
    throw err;
  }
}

async function treeSize(dir) {
  let total = 0;
  for (const name of await readdirOrEmpty(dir)) {
    const child = path.join(dir, name);
    const st = await lstatOrNull(child);
    if (!st) continue;
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) total += await treeSize(child);
    else if (st.isFile()) total += st.size;
  }
  return total;
}

function describe(root, target, name, kind, size, st) {
  return { root, path: target, name, kind, size, mtime: st.mtime.toISOString() };
}

async function describeCollection(target, name) {
  const st = await lstatOrNull(target);
  if (!st) return null;
  if (st.isSymbolicLink()) return describe('collections', target, name, 'other', 0, st);
  if (st.isDirectory()) return describe('collections', target, name, 'dir', await treeSize(target), st);
  if (st.isFile()) return describe('collections', target, name, 'file', st.size, st);
  return describe('collections', target, name, 'other', 0, st);
}

async function listCollections(collectionsRoot) {
  const entries = [];
  for (const name of await readdirOrEmpty(collectionsRoot)) {
    const target = path.join(collectionsRoot, name);
    if (name === RDP_CACHE) {
      const st = await lstatOrNull(target);
      if (st && !st.isSymbolicLink() && st.isDirectory()) {
        for (const child of await readdirOrEmpty(target)) {
          const entry = await describeCollection(path.join(target, child), `${RDP_CACHE}/${child}`);
          if (entry) entries.push(entry);
        }
        continue;
      }
    }
    const entry = await describeCollection(target, name);
    if (entry) entries.push(entry);
  }
  return entries;
}

function isCaseCollectionName(name, caseId) {
  if (typeof name !== 'string' || typeof caseId !== 'string' || caseId === '') return false;
  return name.toLowerCase().startsWith(`case-${caseId.toLowerCase()}-`);
}

async function walkUploads(uploadRoot, dir, entries) {
  for (const name of await readdirOrEmpty(dir)) {
    const target = path.join(dir, name);
    const st = await lstatOrNull(target);
    if (!st) continue;
    const relative = path.relative(uploadRoot, target);
    if (st.isSymbolicLink()) entries.push(describe('uploads', target, relative, 'other', 0, st));
    else if (st.isDirectory()) await walkUploads(uploadRoot, target, entries);
    else if (st.isFile()) entries.push(describe('uploads', target, relative, 'file', st.size, st));
    else entries.push(describe('uploads', target, relative, 'other', 0, st));
  }
}

async function listTemp(tempRoot, entries) {
  for (const name of await readdirOrEmpty(tempRoot)) {
    const target = path.join(tempRoot, name);
    const st = await lstatOrNull(target);
    if (!st) continue;
    if (st.isSymbolicLink()) entries.push(describe('temp', target, name, 'other', 0, st));
    else if (st.isDirectory()) entries.push(describe('temp', target, name, 'dir', await treeSize(target), st));
    else if (st.isFile()) entries.push(describe('temp', target, name, 'file', st.size, st));
    else entries.push(describe('temp', target, name, 'other', 0, st));
  }
}

async function listStorageEntries({ collectionsRoot, uploadRoot, tempRoot }) {
  const entries = await listCollections(collectionsRoot);
  await walkUploads(uploadRoot, uploadRoot, entries);
  if (tempRoot) await listTemp(tempRoot, entries);
  return entries;
}

function classifyTempName(name) {
  let match = TEMP_CASE_OUTPUT_RE.exec(name);
  if (match) return { kind: 'case_output', id: match[1].toLowerCase() };
  match = TEMP_MEMORY_RE.exec(name);
  if (match) return { kind: 'memory_upload', id: match[1].toLowerCase() };
  if (TEMP_RUN_OUTPUT_RE.test(name)) return { kind: 'run_output', id: null };
  return null;
}

function classifyTempEntry(entry, caseById, uploadById) {
  const known = classifyTempName(entry.name || '');
  if (!known) return { ...entry, status: 'orphan_unattributed', case_id: null, evidence_id: null, legal_hold: null };
  if (known.kind === 'run_output') return { ...entry, status: 'temp_output', case_id: null, evidence_id: null, legal_hold: null };
  const caseId = known.kind === 'case_output' ? known.id : uploadById.get(known.id);
  if (!caseId) return { ...entry, status: 'orphan_unattributed', case_id: null, evidence_id: null, legal_hold: null };
  const owner = caseById.get(caseId);
  if (!owner) return { ...entry, status: 'orphan_deleted_case', case_id: caseId, evidence_id: null, legal_hold: null };
  return { ...entry, status: 'temp_output', case_id: caseId, evidence_id: null, legal_hold: owner.legal_hold };
}

function additionalList(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function isLocalPath(value) {
  return typeof value === 'string' && value !== '' && !value.startsWith('minio://');
}

function evidenceTargets(row) {
  const targets = [];
  if (!isLocalPath(row.file_path)) return targets;
  targets.push(path.resolve(row.file_path));
  for (const item of additionalList(row.additional_files)) {
    if (item && typeof item.name === 'string' && item.name) {
      targets.push(path.resolve(path.dirname(row.file_path), item.name));
    }
  }
  return targets;
}

function caseIdFromEntry(entry) {
  if (entry.root === 'collections') {
    const name = entry.name || '';
    const match = COLLECTION_NAME_RE.exec(name) || RDP_CACHE_NAME_RE.exec(name);
    return match ? match[1].toLowerCase() : null;
  }
  for (const segment of String(entry.name || '').split(/[\\/]/)) {
    if (UUID_RE.test(segment)) return segment.toLowerCase();
  }
  return null;
}

function classifyEntries(entries, refs) {
  const { evidence = [], importDirs = [], cases = [], memoryUploads = [] } = refs || {};
  const uploadById = new Map(memoryUploads.map((row) => [String(row.id).toLowerCase(), String(row.case_id).toLowerCase()]));
  const evidenceByPath = new Map();
  for (const row of evidence) {
    for (const target of evidenceTargets(row)) {
      if (!evidenceByPath.has(target)) evidenceByPath.set(target, row);
    }
  }
  const importByPath = new Map();
  for (const item of importDirs) {
    if (!isLocalPath(item.dir)) continue;
    const target = path.resolve(item.dir);
    if (!importByPath.has(target)) importByPath.set(target, item);
  }
  const caseById = new Map(cases.map((row) => [String(row.id).toLowerCase(), row]));
  const present = new Set();

  const classified = entries.map((entry) => {
    const key = path.resolve(entry.path);
    present.add(key);
    if (entry.root === 'temp') return classifyTempEntry(entry, caseById, uploadById);
    const proof = evidenceByPath.get(key);
    if (proof) {
      const known = caseById.get(String(proof.case_id).toLowerCase());
      return {
        ...entry, status: 'evidence', case_id: proof.case_id, evidence_id: proof.id, legal_hold: known ? known.legal_hold : null,
      };
    }
    const imported = importByPath.get(key);
    if (imported) {
      const known = caseById.get(String(imported.case_id).toLowerCase());
      return {
        ...entry, status: 'import_dir', case_id: imported.case_id, evidence_id: null, legal_hold: known ? known.legal_hold : null,
      };
    }
    const caseId = caseIdFromEntry(entry);
    if (!caseId) return { ...entry, status: 'orphan_unattributed', case_id: null, evidence_id: null, legal_hold: null };
    const known = caseById.get(caseId);
    if (!known) return { ...entry, status: 'orphan_deleted_case', case_id: caseId, evidence_id: null, legal_hold: null };
    return {
      ...entry, status: 'orphan_active_case', case_id: caseId, evidence_id: null, legal_hold: known.legal_hold,
    };
  });

  const missing = [];
  const reported = new Set();
  for (const row of evidence) {
    for (const target of evidenceTargets(row)) {
      if (present.has(target) || reported.has(target)) continue;
      reported.add(target);
      missing.push({ source: 'evidence', case_id: row.case_id, evidence_id: row.id, path: target });
    }
  }
  for (const [target, item] of importByPath) {
    if (present.has(target) || reported.has(target)) continue;
    reported.add(target);
    missing.push({ source: 'import_dir', case_id: item.case_id, evidence_id: null, path: target });
  }
  return { entries: classified, missing };
}

async function collectRefs(db) {
  const evidenceRes = await db.query('SELECT id, case_id, file_path, additional_files FROM evidence');
  const importRes = await db.query(
    `SELECT COALESCE(NULLIF(output_data->>'collection_dir', ''), input_file) AS dir, case_id
       FROM parser_results WHERE parser_name = $1`,
    [IMPORT_PARSER],
  );
  const casesRes = await db.query('SELECT id, legal_hold FROM cases');
  return {
    evidence: evidenceRes.rows,
    importDirs: importRes.rows
      .filter((row) => typeof row.dir === 'string' && row.dir !== '')
      .map((row) => ({ case_id: row.case_id, dir: row.dir })),
    cases: casesRes.rows,
  };
}

async function collectTempRefs(db) {
  const res = await db.query('SELECT id, case_id FROM memory_uploads');
  return { memoryUploads: res.rows };
}

module.exports = {
  listStorageEntries, classifyEntries, collectRefs, collectTempRefs, isCaseCollectionName, classifyTempName,
};
