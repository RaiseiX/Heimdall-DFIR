const fs = require('fs');
const path = require('path');

function rejected() {
  return Object.assign(new Error('Storage target outside configured root'), { code: 'STORAGE_PATH_REJECTED' });
}

function resolvedPair(root, target) {
  const resolvedRoot = path.resolve(root);
  const resolvedTarget = path.resolve(target);
  if (!resolvedTarget.startsWith(`${resolvedRoot}${path.sep}`)) throw rejected();
  return { resolvedRoot, resolvedTarget };
}

function within(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function assertConfinedPathSync(root, target) {
  const { resolvedRoot, resolvedTarget } = resolvedPair(root, target);
  const realRoot = fs.realpathSync(resolvedRoot);
  const realParent = fs.realpathSync(path.dirname(resolvedTarget));
  if (!within(realRoot, realParent)) throw rejected();
  return resolvedTarget;
}

async function assertConfinedPath(root, target) {
  const { resolvedRoot, resolvedTarget } = resolvedPair(root, target);
  const [realRoot, realParent] = await Promise.all([
    fs.promises.realpath(resolvedRoot),
    fs.promises.realpath(path.dirname(resolvedTarget)),
  ]);
  if (!within(realRoot, realParent)) throw rejected();
  return resolvedTarget;
}

function racinesDeStockage() {
  const brutes = [
    process.env.UPLOAD_DIR || '/app/uploads',
    process.env.COLLECTIONS_DIR || '/app/collections',
  ];
  return [...new Set(brutes.map((r) => path.resolve(r)))];
}

function estSousUneRacine(racines, cible) {
  if (!Array.isArray(racines) || racines.length === 0) return null;
  if (typeof cible !== 'string' || !cible) return null;
  const resolue = path.resolve(cible);
  for (const brute of racines) {
    const racine = path.resolve(brute);
    if (resolue !== racine && resolue.startsWith(racine + path.sep)) return brute;
  }
  return null;
}

module.exports = { assertConfinedPath, assertConfinedPathSync, racinesDeStockage, estSousUneRacine };
