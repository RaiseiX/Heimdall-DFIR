const fs = require('fs');
const path = require('path');
const logger = require('../config/logger').default;
const { auditCritical } = require('../middleware/auth');
const { destroyStorageTarget } = require('./storageDeletionService');
const { classifyTempName } = require('./storageInventory');

const IN_FLIGHT_UPLOAD = ['hashing', 'forwarding'];
const HOUR = 60 * 60 * 1000;

function tempRoot() {
  return path.resolve(process.env.TEMP_DIR || '/app/temp');
}

function hours(name, fallback) {
  const value = Number(process.env[name]);
  return (Number.isFinite(value) && value > 0 ? value : fallback) * HOUR;
}

function sweepSettings() {
  return {
    graceMs: hours('TEMP_SWEEP_GRACE_HOURS', 24),
    uploadTtlMs: hours('MEMORY_UPLOAD_TTL_HOURS', 24),
    intervalMs: hours('TEMP_SWEEP_INTERVAL_HOURS', 6),
  };
}

async function readNames(root) {
  try {
    return (await fs.promises.readdir(root)).sort();
  } catch (error) {
    if (error && (error.code === 'ENOENT' || error.code === 'ENOTDIR')) return [];
    throw error;
  }
}

async function newestMtime(target) {
  const stat = await fs.promises.lstat(target);
  let newest = stat.mtimeMs;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const name of await fs.promises.readdir(target)) {
      newest = Math.max(newest, await newestMtime(path.join(target, name)));
    }
  }
  return newest;
}

async function footprint(target) {
  const stat = await fs.promises.lstat(target);
  if (stat.isSymbolicLink()) return { size: 0, allocated: 0 };
  if (!stat.isDirectory()) return { size: stat.size, allocated: (stat.blocks || 0) * 512 };
  let size = 0;
  let allocated = 0;
  for (const name of await fs.promises.readdir(target)) {
    const child = await footprint(path.join(target, name));
    size += child.size;
    allocated += child.allocated;
  }
  return { size, allocated };
}

async function planCaseTempTargets(db, caseId, listedNames) {
  const root = tempRoot();
  const names = Array.isArray(listedNames) ? [...listedNames].sort() : await readNames(root);
  if (names.length === 0) return [];
  const id = String(caseId).toLowerCase();
  const uploads = await db.query('SELECT id FROM memory_uploads WHERE case_id = $1', [caseId]);
  const uploadIds = new Set(uploads.rows.map(row => String(row.id).toLowerCase()));
  return names
    .filter((name) => {
      const entry = classifyTempName(name);
      if (!entry) return false;
      if (entry.kind === 'case_output') return entry.id === id;
      if (entry.kind === 'memory_upload') return uploadIds.has(entry.id);
      return false;
    })
    .map(name => ({ kind: 'disk', locator: path.join(root, name) }));
}

async function expireUpload(db, id, cutoff) {
  const res = await db.query(
    `UPDATE memory_uploads SET status = 'error', error_message = 'upload_expired', updated_at = NOW()
      WHERE id = $1 AND status = 'uploading' AND updated_at < $2
      RETURNING id`,
    [id, new Date(cutoff).toISOString()],
  );
  return res.rows.length > 0;
}

async function decide(db, entry, target, context) {
  const { now, graceMs, uploadTtlMs, cases, uploads } = context;
  if (entry.kind === 'case_output') {
    const ids = { case_id: entry.id };
    if (!cases.has(entry.id)) return { reason: 'deleted_case', entityType: 'case', entityId: entry.id, ids };
    if (now - await newestMtime(target) > graceMs) return { reason: 'stale_output', entityType: 'case', entityId: entry.id, ids };
    return null;
  }
  if (entry.kind === 'run_output') {
    if (now - await newestMtime(target) > graceMs) return { reason: 'stale_output', entityType: 'temp_entry', entityId: null, ids: {} };
    return null;
  }
  const row = uploads.get(entry.id);
  if (!row) {
    if (now - await newestMtime(target) > graceMs) {
      return { reason: 'orphan_upload', entityType: 'memory_upload', entityId: entry.id, ids: { upload_id: entry.id } };
    }
    return null;
  }
  const ids = { upload_id: entry.id, case_id: row.case_id ? String(row.case_id).toLowerCase() : null };
  const updatedAt = Date.parse(row.updated_at);
  if (!Number.isFinite(updatedAt) || now - updatedAt <= uploadTtlMs) return null;
  if (row.status === 'uploading') {
    if (!(await expireUpload(db, entry.id, now - uploadTtlMs))) return null;
    return { reason: 'upload_expired', entityType: 'memory_upload', entityId: entry.id, ids };
  }
  if (IN_FLIGHT_UPLOAD.includes(row.status)) return { reason: 'upload_stalled', entityType: 'memory_upload', entityId: entry.id, ids };
  return { reason: `upload_${row.status}`, entityType: 'memory_upload', entityId: entry.id, ids };
}

async function sweepTempStorage(db, options = {}) {
  const settings = sweepSettings();
  const now = options.now ?? Date.now();
  const graceMs = options.graceMs ?? settings.graceMs;
  const uploadTtlMs = options.uploadTtlMs ?? settings.uploadTtlMs;
  const summary = { removed: [], failed: [], kept: 0, auditFailures: 0 };
  const root = tempRoot();
  const names = await readNames(root);
  if (names.length === 0) return summary;

  const cases = new Set((await db.query('SELECT id FROM cases')).rows.map(row => String(row.id).toLowerCase()));
  const uploads = new Map(
    (await db.query('SELECT id, case_id, status, updated_at FROM memory_uploads')).rows
      .map(row => [String(row.id).toLowerCase(), row]),
  );
  const context = { now, graceMs, uploadTtlMs, cases, uploads };

  for (const name of names) {
    const entry = classifyTempName(name);
    if (!entry) {
      summary.kept += 1;
      continue;
    }
    const target = path.join(root, name);
    let decision;
    let measured;
    let result;
    try {
      decision = await decide(db, entry, target, context);
      if (!decision) {
        summary.kept += 1;
        continue;
      }
      measured = await footprint(target);
      await auditCritical(db, null, 'temp_storage_purge_started', decision.entityType, decision.entityId, {
        name,
        reason: decision.reason,
        ...decision.ids,
        size: measured.size,
        allocated: measured.allocated,
      });
      result = await destroyStorageTarget(target, root);
    } catch (error) {
      const code = error && error.code ? String(error.code) : 'UNKNOWN';
      summary.failed.push({ name, code });
      logger.error('[temp-sweep] entry not removed', { name, code });
      continue;
    }
    summary.removed.push({ name, reason: decision.reason, size: measured.size, allocated: measured.allocated });
    try {
      await auditCritical(db, null, 'temp_storage_purged', decision.entityType, decision.entityId, {
        name,
        reason: decision.reason,
        ...decision.ids,
        size: measured.size,
        allocated: measured.allocated,
        method: result.method,
        result: result.status,
      });
    } catch (error) {
      summary.auditFailures += 1;
      logger.error('[temp-sweep] audit failed after removal', { name, code: error && error.code ? String(error.code) : 'UNKNOWN' });
    }
  }
  return summary;
}

module.exports = { planCaseTempTargets, sweepTempStorage, sweepSettings, tempRoot };
