// Extraction argv, lifted out of the collection route so the permission flags are
// testable. Cat-Scale stores its tree 0600/0700 owned by root; GNU tar run as root
// restores both by default, which left the backend unable to read what it had just
// extracted. Evidence integrity is carried by the hashes, not by these mode bits.
const TAR_EXT = new Set(['.tar', '.gz', '.tgz']);

function extractArgs(ext, archivePath, destDir) {
  if (TAR_EXT.has(ext)) {
    return ['tar', 'xf', archivePath, '--no-same-owner', '--no-same-permissions', '-C', destDir];
  }
  if (ext === '.zip') return ['unzip', '-o', '-q', archivePath, '-d', destDir];
  return ['7z', 'x', archivePath, `-o${destDir}`, '-y'];
}

// unzip and 7z have their own handling of stored modes, and a directory without
// its traversal bit is unreadable even by its owner.
function permissionArgs(destDir) {
  return ['chmod', '-R', 'u+rwX,go-w', destDir];
}

module.exports = { extractArgs, permissionArgs };
