// Extraction argv, lifted out of the collection route so the permission flags are
// testable. Cat-Scale stores its tree 0600/0700 owned by root; GNU tar run as root
// restores both by default, which left the backend unable to read what it had just
// extracted. Evidence integrity is carried by the hashes, not by these mode bits.
const TAR_EXT = new Set(['.tar', '.gz', '.tgz']);

// `password` decrypts password-protected .zip / .7z archives. Passed as a command
// line argument (unzip -P / 7z -p) — the password is momentarily visible in the
// process list on the server, an accepted trade-off for a local forensic tool.
function extractArgs(ext, archivePath, destDir, password) {
  if (TAR_EXT.has(ext)) {
    // `.tar` is a plain (uncompressed) tarball — the `z` flag would make GNU tar
    // try to gunzip it and fail with "not in gzip format". Only .gz/.tgz are gzipped.
    const zFlag = ext === '.tar' ? '' : 'z';
    return ['tar', `x${zFlag}f`, archivePath, '--no-same-owner', '--no-same-permissions', '-C', destDir];
  }
  if (ext === '.zip') {
    const args = ['unzip', '-o', '-q'];
    if (password) { args.push('-P', password); }
    args.push(archivePath, '-d', destDir);
    return args;
  }
  const args = ['7z', 'x', archivePath, `-o${destDir}`, '-y'];
  if (password) { args.push(`-p${password}`); }
  return args;
}

// unzip and 7z have their own handling of stored modes, and a directory without
// its traversal bit is unreadable even by its owner.
function permissionArgs(destDir) {
  return ['chmod', '-R', 'u+rwX,go-w', destDir];
}

module.exports = { extractArgs, permissionArgs };
