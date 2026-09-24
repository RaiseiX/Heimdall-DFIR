import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
const { assertConfinedPath } = require('./storagePathGuard');

const CHUNK_SIZE = 4 * 1024 * 1024;
const NODE_PASSES: Array<'random' | 'zeros'> = [
  'random', 'random', 'random', 'random', 'random', 'random', 'random', 'zeros',
];

export type StorageDeletionMethod = 'node' | 'rmdir' | 'none';
export type StorageDeletionResult = {
  status: 'deleted' | 'already_absent';
  method: StorageDeletionMethod;
};

function unsupportedStorageTarget(): Error {
  return Object.assign(new Error('Unsupported storage target'), { code: 'UNSUPPORTED_STORAGE_TARGET' });
}

async function nodeWipe(filePath: fs.PathLike): Promise<void> {
  const before = await fs.promises.lstat(filePath);
  if (!before.isFile() || before.isSymbolicLink()) throw unsupportedStorageTarget();
  const fd = await fs.promises.open(filePath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
  let opened;
  try {
    opened = await fd.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) throw unsupportedStorageTarget();
    const fileSize = opened.size;
    for (const pass of NODE_PASSES) {
      let offset = 0;
      while (offset < fileSize) {
        const chunkLen = Math.min(CHUNK_SIZE, fileSize - offset);
        const buffer = pass === 'zeros' ? Buffer.alloc(chunkLen, 0x00) : crypto.randomBytes(chunkLen);
        await fd.write(buffer, 0, chunkLen, offset);
        offset += chunkLen;
      }
      await fd.datasync();
    }
    const current = await fs.promises.lstat(filePath);
    if (!current.isFile() || current.isSymbolicLink() || current.dev !== opened.dev || current.ino !== opened.ino) {
      throw unsupportedStorageTarget();
    }
  } finally {
    await fd.close();
  }
  const current = await fs.promises.lstat(filePath);
  if (!current.isFile() || current.isSymbolicLink() || current.dev !== opened.dev || current.ino !== opened.ino) {
    throw unsupportedStorageTarget();
  }
  await fs.promises.unlink(filePath);
}

async function wipeRegularFile(filePath: string, storageRoot: string): Promise<'node'> {
  await assertConfinedPath(storageRoot, filePath);
  const stat = await fs.promises.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw unsupportedStorageTarget();
  await nodeWipe(filePath);
  return 'node';
}

const SEPARATEUR = Buffer.from(path.sep);

function storagePathRejected(): Error {
  return Object.assign(new Error('Storage target outside configured root'), { code: 'STORAGE_PATH_REJECTED' });
}

async function realStorageRoot(storageRoot: string): Promise<Buffer> {
  return fs.promises.realpath(path.resolve(storageRoot), { encoding: 'buffer' });
}

async function assertStrictlyInside(realRoot: Buffer, directory: Buffer): Promise<void> {
  const real = await fs.promises.realpath(directory, { encoding: 'buffer' });
  const prefix = Buffer.concat([realRoot, SEPARATEUR]);
  if (real.length <= prefix.length || !real.subarray(0, prefix.length).equals(prefix)) throw storagePathRejected();
}

function parentOf(target: Buffer): Buffer {
  return target.subarray(0, target.lastIndexOf(SEPARATEUR[0]));
}

function depthOf(target: Buffer): number {
  let depth = 0;
  for (const byte of target) if (byte === SEPARATEUR[0]) depth += 1;
  return depth;
}

async function directoryPlan(directoryPath: string, realRoot: Buffer): Promise<{ files: Buffer[]; directories: Buffer[] }> {
  const files: Buffer[] = [];
  const directories: Buffer[] = [];
  const pending = [Buffer.from(directoryPath)];
  while (pending.length > 0) {
    const current = pending.pop() as Buffer;
    await assertStrictlyInside(realRoot, current);
    const currentStat = await fs.promises.lstat(current);
    if (!currentStat.isDirectory() || currentStat.isSymbolicLink()) throw unsupportedStorageTarget();
    directories.push(current);
    const entries = await fs.promises.readdir(current, { encoding: 'buffer' });
    for (const entry of entries) {
      const child = Buffer.concat([current, SEPARATEUR, entry]);
      const childStat = await fs.promises.lstat(child);
      if (childStat.isSymbolicLink()) throw unsupportedStorageTarget();
      if (childStat.isDirectory()) pending.push(child);
      else if (childStat.isFile()) files.push(child);
      else throw unsupportedStorageTarget();
    }
  }
  directories.sort((left, right) => depthOf(right) - depthOf(left));
  return { files, directories };
}

async function wipePlannedFile(target: Buffer, realRoot: Buffer): Promise<void> {
  await assertStrictlyInside(realRoot, parentOf(target));
  const stat = await fs.promises.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw unsupportedStorageTarget();
  await nodeWipe(target);
}

export async function destroyStorageTarget(filePath: string, storageRoot: string): Promise<StorageDeletionResult> {
  await assertConfinedPath(storageRoot, filePath);
  let stat;
  try {
    stat = await fs.promises.lstat(filePath);
  } catch (error: any) {
    if (error?.code === 'ENOENT') return { status: 'already_absent', method: 'none' };
    throw error;
  }
  if (stat.isSymbolicLink()) throw unsupportedStorageTarget();
  if (stat.isFile()) {
    const method = await wipeRegularFile(filePath, storageRoot);
    return { status: 'deleted', method };
  }
  if (!stat.isDirectory()) throw unsupportedStorageTarget();
  const realRoot = await realStorageRoot(storageRoot);
  const plan = await directoryPlan(filePath, realRoot);
  for (const target of plan.files) await wipePlannedFile(target, realRoot);
  for (const target of plan.directories) {
    await assertStrictlyInside(realRoot, target);
    const current = await fs.promises.lstat(target);
    if (!current.isDirectory() || current.isSymbolicLink()) throw unsupportedStorageTarget();
    await fs.promises.rmdir(target);
  }
  return { status: 'deleted', method: 'rmdir' };
}
