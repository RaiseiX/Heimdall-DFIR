const path = require('path');
const logger = require('../config/logger').default;
const { destroyStorageTarget } = require('./storageDeletionService');
const { deleteMinioLocator } = require('./deletionStorage');
const { racinesDeStockage, estSousUneRacine } = require('./storagePathGuard');

function logOrphan(kind, relativePath, sha256, error) {
  logger.error(`[orphan-upload] ${kind} left in storage after audit failure`, {
    relative_path: relativePath,
    sha256: sha256 || null,
    code: error && error.code ? String(error.code) : 'UNKNOWN',
  });
}

async function removeOrphanFile(target, { sha256 = null } = {}) {
  const resolved = typeof target === 'string' && target ? path.resolve(target) : null;
  const root = resolved ? estSousUneRacine(racinesDeStockage(), resolved) : null;
  const relativePath = root ? path.relative(path.resolve(root), resolved) : (resolved ? path.basename(resolved) : null);
  try {
    if (!root) {
      throw Object.assign(new Error('Storage target outside configured roots'), { code: 'STORAGE_PATH_REJECTED' });
    }
    await destroyStorageTarget(resolved, root);
    return true;
  } catch (error) {
    logOrphan('file', relativePath, sha256, error);
    return false;
  }
}

async function removeOrphanObject(locator, { sha256 = null, objectKey = null } = {}) {
  try {
    await deleteMinioLocator(locator);
    return true;
  } catch (error) {
    logOrphan('object', objectKey, sha256, error);
    return false;
  }
}

module.exports = { removeOrphanFile, removeOrphanObject };
