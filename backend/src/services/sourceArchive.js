const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { estSousUneRacine } = require('./storagePathGuard');

const DOUBLE_SUFFIXES = ['.tar.gz', '.tar.bz2', '.tar.xz'];
const HEX64_RE = /^[0-9a-f]{64}$/;
const SAFE_EXT_RE = /^\.[a-z0-9]{1,10}$/;
const PROBLEM_STATUSES = new Set(['mismatch', 'missing', 'no_stored_file', 'source_not_preserved', 'no_reference_hash', 'outside_roots', 'invalid_manifest', 'unreadable']);

function sourceArchiveName(collectionDir, originalName) {
  const lower = String(originalName || '').toLowerCase();
  let suffix = DOUBLE_SUFFIXES.find((s) => lower.endsWith(s));
  if (!suffix) {
    const ext = path.extname(lower);
    suffix = SAFE_EXT_RE.test(ext) ? ext : '';
  }
  return `${path.basename(collectionDir)}.source${suffix}`;
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    let size = 0;
    const stream = fs.createReadStream(file);
    stream.on('data', (chunk) => { size += chunk.length; hash.update(chunk); });
    stream.on('end', () => resolve({ sha256: hash.digest('hex'), size }));
    stream.on('error', reject);
  });
}

async function preserveSourceArchive(uploadedPath, collectionDir, originalName, expectedSha256) {
  if (!HEX64_RE.test(expectedSha256 || '')) {
    throw new Error('Empreinte scellée indisponible : l archive d origine ne peut pas être conservée');
  }
  const name = sourceArchiveName(collectionDir, originalName);
  const dest = path.join(path.dirname(collectionDir), name);
  try {
    await fs.promises.copyFile(uploadedPath, dest, fs.constants.COPYFILE_EXCL);
  } catch (err) {
    if (err.code !== 'EEXIST') await fs.promises.rm(dest, { force: true });
    throw err;
  }
  try {
    const { sha256, size } = await sha256File(dest);
    if (sha256 !== expectedSha256) {
      throw new Error('La copie conservée ne correspond pas à l empreinte scellée');
    }
    await fs.promises.chmod(dest, 0o444);
    return { name, path: dest, sha256, size };
  } catch (err) {
    await fs.promises.rm(dest, { force: true });
    throw err;
  }
}

function sourceArchiveEntry(preserved) {
  return { name: preserved.name, role: 'source_archive', sha256: preserved.sha256, size: preserved.size };
}

function declaredSourceArchive(row) {
  let items = row.additional_files;
  if (typeof items === 'string') items = JSON.parse(items || '[]');
  if (items == null) return null;
  if (!Array.isArray(items)) throw new Error('invalid manifest');
  const entry = items.find((item) => item && item.role === 'source_archive');
  if (!entry) return null;
  if (typeof entry.name !== 'string' || !entry.name || path.basename(entry.name) !== entry.name || /[\0\r\n]/.test(entry.name)) {
    throw new Error('invalid manifest');
  }
  return path.join(path.dirname(row.file_path), entry.name);
}

async function verifyEvidence(row, { racines }) {
  const base = {
    evidence_id: row.id,
    case_id: row.case_id,
    expected_sha256: row.hash_sha256 || null,
    computed_sha256: null,
    target: null,
  };
  const done = (status, extra = {}) => ({ ...base, status, ...extra });

  if (typeof row.file_path !== 'string' || !row.file_path) return done('no_stored_file');
  if (row.file_path.startsWith('minio://')) return done('skipped');
  if (!HEX64_RE.test(row.hash_sha256 || '')) return done('no_reference_hash');

  let target;
  let declared;
  try {
    declared = declaredSourceArchive(row);
  } catch {
    return done('invalid_manifest');
  }
  target = declared || row.file_path;
  base.target = target;
  if (!estSousUneRacine(racines, target)) return done('outside_roots');

  let stat;
  try {
    stat = await fs.promises.lstat(target);
  } catch (err) {
    if (err.code === 'ENOENT') return done('missing');
    return done('unreadable');
  }
  if (stat.isDirectory() && !declared) return done('source_not_preserved');
  if (!stat.isFile()) return done('unreadable');
  try {
    const realRoots = (await Promise.all(racines.map((r) => fs.promises.realpath(r).catch(() => null)))).filter(Boolean);
    const realTarget = path.join(await fs.promises.realpath(path.dirname(target)), path.basename(target));
    if (!estSousUneRacine(realRoots, realTarget)) return done('outside_roots');
  } catch {
    return done('unreadable');
  }

  try {
    const { sha256 } = await sha256File(target);
    return done(sha256 === row.hash_sha256 ? 'ok' : 'mismatch', { computed_sha256: sha256 });
  } catch {
    return done('unreadable');
  }
}

function isProblem(status) {
  return PROBLEM_STATUSES.has(status);
}

module.exports = {
  sourceArchiveName, sha256File, preserveSourceArchive, sourceArchiveEntry, verifyEvidence, isProblem,
};
