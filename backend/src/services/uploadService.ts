import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import type { Readable } from 'stream';
import type {
  UploadSession,
  UploadStatus,
  InitUploadResponse,
  ChunkAckResponse,
  CompleteUploadResponse,
  DiskSpace,
  SafePathResult,
} from '../types/index';

const CHUNK_SIZE = 50 * 1024 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_RETRIES_PER_CHUNK = 3;
const DEFAULT_MAX_TOTAL_SIZE = 256 * 1024 * 1024 * 1024;
const DEFAULT_MAX_ACTIVE_SESSIONS = 8;
const FORGET_DELAY_MS = 5000;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RECEIVING: ReadonlySet<UploadStatus> = new Set<UploadStatus>(['pending', 'uploading']);
const ACTIVE: ReadonlySet<UploadStatus> = new Set<UploadStatus>(['pending', 'uploading', 'assembling', 'finalizing', 'hashing']);

export type UploadErrorKind =
  | 'not_found'
  | 'forbidden'
  | 'conflict'
  | 'too_large'
  | 'invalid'
  | 'bad_request'
  | 'quota'
  | 'insufficient_storage';

const HTTP_STATUS: Record<UploadErrorKind, number> = {
  not_found: 404,
  forbidden: 404,
  conflict: 409,
  too_large: 413,
  invalid: 422,
  bad_request: 400,
  quota: 429,
  insufficient_storage: 507,
};

export class UploadError extends Error {
  kind: UploadErrorKind;
  status: number;
  constructor(kind: UploadErrorKind, message: string) {
    super(message);
    this.name = 'UploadError';
    this.kind = kind;
    this.status = HTTP_STATUS[kind];
  }
}

export function isUploadError(err: unknown): err is UploadError {
  return err instanceof UploadError;
}

interface Runtime {
  writers: Set<Promise<void>>;
  tails: Map<number, Promise<void>>;
  cancelers: Set<() => void>;
}

const sessions = new Map<string, UploadSession>();
const runtimes = new WeakMap<UploadSession, Runtime>();
const recoveredDirs = new Set<string>();

function runtimeOf(session: UploadSession): Runtime {
  let rt = runtimes.get(session);
  if (!rt) {
    rt = { writers: new Set(), tails: new Map(), cancelers: new Set() };
    runtimes.set(session, rt);
  }
  return rt;
}

function envPositiveInt(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function defaultUploadDir(): string {
  return process.env.UPLOAD_DIR || '/app/uploads';
}

function chunksDirOf(uploadDir: string): string {
  return path.join(path.resolve(uploadDir), 'chunks');
}

function tempPathOf(uploadDir: string, uploadId: string): string {
  return path.join(chunksDirOf(uploadDir), `${uploadId}.tmp`);
}

function metaPathOf(uploadDir: string, uploadId: string): string {
  return path.join(chunksDirOf(uploadDir), `${uploadId}.json`);
}

function stagingPathOf(uploadDir: string, caseId: string, uploadId: string): string {
  return path.join(path.resolve(uploadDir), caseId, `${uploadId}.part`);
}

function expectedChunkSize(session: UploadSession, chunkIndex: number): number {
  return Math.min(session.chunkSize, session.totalSize - chunkIndex * session.chunkSize);
}

function persist(session: UploadSession): void {
  const target = metaPathOf(session.uploadDir, session.uploadId);
  const staging = `${target}.new`;
  const meta = {
    version: 1,
    uploadId: session.uploadId,
    originalName: session.originalName,
    totalSize: session.totalSize,
    chunkSize: session.chunkSize,
    totalChunks: session.totalChunks,
    receivedChunks: Array.from(session.receivedChunks).sort((a, b) => a - b),
    caseId: session.caseId,
    userId: session.userId,
    createdAt: session.createdAt,
    status: session.status,
    checksumSha256: session.checksumSha256,
  };
  fs.writeFileSync(staging, JSON.stringify(meta), { mode: 0o600 });
  fs.renameSync(staging, target);
}

async function removeQuietly(file: string): Promise<void> {
  try {
    await fs.promises.rm(file, { force: true });
  } catch (e) {
    logger.warn(`[Upload] cleanup failed: ${(e as Error).message}`);
  }
}

async function removeSessionFiles(session: UploadSession): Promise<void> {
  const metaPath = metaPathOf(session.uploadDir, session.uploadId);
  await removeQuietly(session.tempPath);
  await removeQuietly(metaPath);
  await removeQuietly(`${metaPath}.new`);
  await removeQuietly(stagingPathOf(session.uploadDir, session.caseId, session.uploadId));
}

function forgetLater(uploadId: string): void {
  setTimeout(() => sessions.delete(uploadId), FORGET_DELAY_MS).unref();
}

function parseSession(raw: unknown, uploadId: string, uploadDir: string): UploadSession | null {
  if (!raw || typeof raw !== 'object') return null;
  const m = raw as Record<string, unknown>;
  if (m.uploadId !== uploadId) return null;
  if (typeof m.originalName !== 'string' || typeof m.userId !== 'string') return null;
  if (typeof m.caseId !== 'string' || !UUID_RE.test(m.caseId)) return null;
  if (!Number.isSafeInteger(m.totalSize) || (m.totalSize as number) < 1) return null;
  if (m.chunkSize !== CHUNK_SIZE) return null;
  const totalSize = m.totalSize as number;
  const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);
  if (m.totalChunks !== totalChunks) return null;
  if (typeof m.createdAt !== 'number' || !Number.isFinite(m.createdAt)) return null;
  if (typeof m.status !== 'string') return null;
  if (!Array.isArray(m.receivedChunks)) return null;
  const received = new Set<number>();
  for (const idx of m.receivedChunks) {
    if (!Number.isInteger(idx) || (idx as number) < 0 || (idx as number) >= totalChunks) return null;
    received.add(idx as number);
  }
  let checksum: string | null = null;
  if (m.checksumSha256 !== null && m.checksumSha256 !== undefined) {
    if (typeof m.checksumSha256 !== 'string' || !SHA256_RE.test(m.checksumSha256)) return null;
    checksum = m.checksumSha256.toLowerCase();
  }
  return {
    uploadId,
    originalName: m.originalName,
    totalSize,
    chunkSize: CHUNK_SIZE,
    totalChunks,
    receivedChunks: received,
    tempPath: tempPathOf(uploadDir, uploadId),
    caseId: m.caseId,
    userId: m.userId,
    createdAt: m.createdAt,
    status: m.status as UploadStatus,
    uploadDir,
    checksumSha256: checksum,
  };
}

function recoverDirectory(uploadDir: string): void {
  const chunksDir = chunksDirOf(uploadDir);
  let names: string[];
  try {
    names = fs.readdirSync(chunksDir);
  } catch {
    return;
  }
  const ids = new Set<string>();
  for (const name of names) {
    const match = /^([0-9a-f-]{36})\.(tmp|json|json\.new)$/i.exec(name);
    if (match && UUID_RE.test(match[1])) ids.add(match[1]);
  }
  const now = Date.now();
  for (const id of ids) {
    const tempPath = tempPathOf(uploadDir, id);
    const metaPath = metaPathOf(uploadDir, id);
    let session: UploadSession | null = null;
    let caseId: string | null = null;
    try {
      const raw = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      if (raw && typeof raw.caseId === 'string' && UUID_RE.test(raw.caseId)) caseId = raw.caseId;
      session = parseSession(raw, id, uploadDir);
    } catch {
      session = null;
    }
    let keep = false;
    if (session && RECEIVING.has(session.status) && now - session.createdAt <= SESSION_TTL_MS && !sessions.has(id)) {
      try {
        const st = fs.statSync(tempPath);
        keep = st.isFile() && st.size === session.totalSize;
      } catch {
        keep = false;
      }
    }
    if (keep && session) {
      sessions.set(id, session);
      continue;
    }
    for (const file of [tempPath, metaPath, `${metaPath}.new`]) fs.rmSync(file, { force: true });
    if (caseId) fs.rmSync(stagingPathOf(uploadDir, caseId, id), { force: true });
  }
}

function ensureRecovered(uploadDir: string): string {
  const dir = path.resolve(uploadDir);
  if (!recoveredDirs.has(dir)) {
    recoveredDirs.add(dir);
    recoverDirectory(dir);
  }
  return dir;
}

function lookup(uploadId: unknown, userId: string, uploadDir: string): UploadSession | null {
  const dir = ensureRecovered(uploadDir);
  const session = typeof uploadId === 'string' ? sessions.get(uploadId) : undefined;
  if (!session || session.uploadDir !== dir) return null;
  if (session.userId !== userId) {
    throw new UploadError('forbidden', 'Session appartenant à un autre propriétaire');
  }
  return session;
}

function requireSession(uploadId: unknown, userId: string, uploadDir: string): UploadSession {
  const session = lookup(uploadId, userId, uploadDir);
  if (!session) throw new UploadError('not_found', 'Session invalide ou expirée');
  return session;
}

async function purgeExpired(): Promise<void> {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt <= SESSION_TTL_MS) continue;
    const rt = runtimeOf(session);
    if (rt.writers.size > 0) continue;
    if (session.status === 'finalizing' || session.status === 'hashing') continue;
    session.status = 'aborting';
    sessions.delete(id);
    await removeSessionFiles(session);
  }
}

// .unref() so this hourly cleanup timer never keeps the process alive on its own
// (the HTTP server keeps prod alive; in tests it lets Node/jest exit cleanly).
setInterval(() => {
  purgeExpired().catch(e => logger.warn(`[Upload] cleanup failed: ${(e as Error).message}`));
}, 60 * 60 * 1000).unref();

export function safePath(untrusted: string, allowedBase: string): SafePathResult {
  const base = path.resolve(allowedBase);

  const resolved = path.resolve(base, path.basename(untrusted));

  if (!resolved.startsWith(base + path.sep) && resolved !== base) {
    return { safe: false, resolvedPath: resolved, reason: 'Path traversal detected' };
  }
  return { safe: true, resolvedPath: resolved };
}

export function safeBasename(name: string): string {
  const b = path.basename(String(name ?? ''));
  return (b === '' || b === '.' || b === '..') ? '_' : b;
}

async function getDiskSpace(filePath: string): Promise<DiskSpace> {
  try {

    const { statfs } = fs.promises as unknown as {
      statfs?: (path: string) => Promise<{ bfree: number; bsize: number; blocks: number }>;
    };
    if (statfs) {
      const stats = await statfs(path.dirname(filePath));
      return {
        free: stats.bfree * stats.bsize,
        size: stats.blocks * stats.bsize,
      };
    }
  } catch {

  }

  return new Promise((resolve, reject) => {
    const { exec } = require('child_process') as typeof import('child_process');
    exec(`df -k "${path.dirname(filePath)}"`, (err, stdout) => {
      if (err) return reject(err);
      const lines = stdout.trim().split('\n');
      const parts = lines[lines.length - 1].split(/\s+/);

      const free = parseInt(parts[3], 10) * 1024;
      const total = parseInt(parts[1], 10) * 1024;
      resolve({ free, size: total });
    });
  });
}

function normalizeChecksum(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    throw new UploadError('invalid', 'checksum SHA-256 invalide');
  }
  return value.toLowerCase();
}

export function initUpload(params: {
  originalName: string;
  totalSize: number;
  checksumSha256?: string | null;
  caseId: string;
  userId: string;
  uploadDir: string;
}): InitUploadResponse {
  const { originalName, totalSize, caseId, userId, uploadDir } = params;

  const checksumSha256 = normalizeChecksum(params.checksumSha256);
  if (!Number.isSafeInteger(totalSize) || totalSize < 1) {
    throw new UploadError('invalid', 'Taille totale invalide');
  }
  const maxTotal = envPositiveInt('UPLOAD_MAX_TOTAL_SIZE_BYTES', DEFAULT_MAX_TOTAL_SIZE);
  if (totalSize > maxTotal) {
    throw new UploadError('too_large', 'Taille totale au-dessus du plafond autorisé');
  }

  const dir = path.resolve(uploadDir);
  const tempDir = chunksDirOf(dir);
  fs.mkdirSync(tempDir, { recursive: true });
  ensureRecovered(dir);

  const maxSessions = envPositiveInt('UPLOAD_MAX_ACTIVE_SESSIONS_PER_USER', DEFAULT_MAX_ACTIVE_SESSIONS);
  let active = 0;
  for (const s of sessions.values()) {
    if (s.userId === userId && ACTIVE.has(s.status)) active++;
  }
  if (active >= maxSessions) {
    throw new UploadError('quota', 'Nombre maximal de sessions actives atteint');
  }

  const uploadId = uuidv4();
  const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);
  const tempPath = tempPathOf(dir, uploadId);

  const session: UploadSession = {
    uploadId,
    originalName: String(originalName),
    totalSize,
    chunkSize: CHUNK_SIZE,
    totalChunks,
    receivedChunks: new Set(),
    tempPath,
    caseId,
    userId,
    createdAt: Date.now(),
    status: 'pending',
    uploadDir: dir,
    checksumSha256,
  };

  const fd = fs.openSync(tempPath, 'wx', 0o600);
  try {
    fs.ftruncateSync(fd, totalSize);
  } catch (e) {
    fs.closeSync(fd);
    fs.rmSync(tempPath, { force: true });
    throw e;
  }
  fs.closeSync(fd);
  try {
    persist(session);
  } catch (e) {
    fs.rmSync(tempPath, { force: true });
    fs.rmSync(`${metaPathOf(dir, uploadId)}.new`, { force: true });
    throw e;
  }

  sessions.set(uploadId, session);

  return { uploadId, chunkSize: CHUNK_SIZE, totalChunks };
}

function ackFor(session: UploadSession, chunkIndex: number): ChunkAckResponse {
  const progress = Math.round((session.receivedChunks.size / session.totalChunks) * 100);
  return {
    uploadId: session.uploadId,
    chunkIndex,
    received: session.receivedChunks.size,
    total: session.totalChunks,
    progress,
  };
}

async function writeFully(fh: fs.promises.FileHandle, buf: Buffer, position: number): Promise<void> {
  let done = 0;
  while (done < buf.length) {
    const { bytesWritten } = await fh.write(buf, done, buf.length - done, position + done);
    if (bytesWritten <= 0) throw new Error('Écriture interrompue');
    done += bytesWritten;
  }
}

async function pump(req: Readable, fh: fs.promises.FileHandle, offset: number, expected: number, rt: Runtime): Promise<void> {
  let received = 0;
  let inflight: Promise<void> = Promise.resolve();
  let outcome: Error | null | undefined;

  await new Promise<void>((resolve) => {
    const cancel = () => end(new UploadError('conflict', 'Session en cours d\'annulation'));

    const end = (err: Error | null) => {
      if (outcome !== undefined) return;
      outcome = err;
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('close', onClose);
      req.on('error', () => {});
      rt.cancelers.delete(cancel);
      resolve();
    };

    const onData = (buf: Buffer) => {
      if (outcome !== undefined) return;
      if (received + buf.length > expected) {
        req.pause();
        end(new UploadError('too_large', 'Taille de chunk dépassée'));
        return;
      }
      const position = offset + received;
      received += buf.length;
      req.pause();
      inflight = writeFully(fh, buf, position).then(
        () => { if (outcome === undefined) req.resume(); },
        (e) => end(e as Error),
      );
    };

    const onEnd = () => {
      inflight.then(() => {
        end(received === expected
          ? null
          : new UploadError('invalid', `Taille de chunk invalide: ${received} octets reçus, ${expected} attendus`));
      });
    };

    const onError = (e: Error) => end(e);

    const onClose = () => {
      if (!req.readableEnded) end(new UploadError('invalid', 'Connexion interrompue par le client'));
    };

    rt.cancelers.add(cancel);
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);
  });

  await inflight.catch(() => {});
  if (outcome) throw outcome;
}

export async function receiveChunk(params: {
  uploadId: string;
  chunkIndex: number;
  req: Readable;
  userId: string;
  uploadDir: string;
  declaredLength?: number | null;
}): Promise<ChunkAckResponse> {
  const { uploadId, chunkIndex, req, userId, uploadDir, declaredLength } = params;

  const session = requireSession(uploadId, userId, uploadDir);
  if (!RECEIVING.has(session.status)) {
    throw new UploadError('conflict', `Session non modifiable: ${session.status}`);
  }
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= session.totalChunks) {
    throw new UploadError('bad_request', `Index de chunk hors limites: ${chunkIndex}`);
  }
  const expected = expectedChunkSize(session, chunkIndex);
  if (declaredLength !== undefined && declaredLength !== null) {
    if (declaredLength > expected) throw new UploadError('too_large', 'Taille de chunk dépassée');
    if (declaredLength < expected) throw new UploadError('bad_request', 'Taille de chunk déclarée invalide');
  }
  if (session.receivedChunks.has(chunkIndex)) return ackFor(session, chunkIndex);

  const rt = runtimeOf(session);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const previous = rt.tails.get(chunkIndex);
  rt.tails.set(chunkIndex, gate);
  rt.writers.add(gate);

  let fh: fs.promises.FileHandle | undefined;
  try {
    if (previous) await previous;
    if (!RECEIVING.has(session.status)) {
      throw new UploadError('conflict', `Session non modifiable: ${session.status}`);
    }
    if (session.receivedChunks.has(chunkIndex)) return ackFor(session, chunkIndex);

    const disk = await getDiskSpace(session.tempPath);
    if (disk.free < CHUNK_SIZE * 2) {
      throw new UploadError(
        'insufficient_storage',
        `Espace disque insuffisant: ${(disk.free / 1024 / 1024).toFixed(0)} Mo libres`
      );
    }
    if (!RECEIVING.has(session.status)) {
      throw new UploadError('conflict', `Session non modifiable: ${session.status}`);
    }

    fh = await fs.promises.open(session.tempPath, 'r+');
    await pump(req, fh, chunkIndex * session.chunkSize, expected, rt);
    await fh.sync();
    const closing = fh;
    fh = undefined;
    await closing.close();

    session.receivedChunks.add(chunkIndex);
    session.status = 'uploading';
    try {
      persist(session);
    } catch (e) {
      session.receivedChunks.delete(chunkIndex);
      throw e;
    }
    return ackFor(session, chunkIndex);
  } finally {
    if (fh) await fh.close().catch(() => {});
    release();
    rt.writers.delete(gate);
    if (rt.tails.get(chunkIndex) === gate) rt.tails.delete(chunkIndex);
  }
}

async function hashFile(file: string): Promise<{ md5: string; sha1: string; sha256: string; bytes: number }> {
  const md5 = crypto.createHash('md5');
  const sha1 = crypto.createHash('sha1');
  const sha256 = crypto.createHash('sha256');
  let bytes = 0;
  const readStream = fs.createReadStream(file, { highWaterMark: 64 * 1024 });
  await new Promise<void>((resolve, reject) => {
    readStream.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      bytes += buf.length;
      md5.update(buf);
      sha1.update(buf);
      sha256.update(buf);
    });
    readStream.on('end', resolve);
    readStream.on('error', reject);
  });
  return { md5: md5.digest('hex'), sha1: sha1.digest('hex'), sha256: sha256.digest('hex'), bytes };
}

export async function completeUpload(params: {
  uploadId: string;
  caseId: string;
  userId: string;
  finalDir: string;
  uploadDir?: string;
}): Promise<CompleteUploadResponse & { tempPath: string; finalPath: string }> {
  const { uploadId, caseId, userId, finalDir } = params;

  const session = requireSession(uploadId, userId, params.uploadDir ?? finalDir);
  if (session.caseId !== caseId) {
    throw new UploadError('forbidden', 'Dossier différent de celui de la session');
  }
  if (!RECEIVING.has(session.status)) {
    throw new UploadError('conflict', `Session non finalisable: ${session.status}`);
  }
  const rt = runtimeOf(session);
  if (rt.writers.size > 0) {
    throw new UploadError('conflict', 'Écriture de chunk en cours');
  }
  const missing: number[] = [];
  for (let i = 0; i < session.totalChunks; i++) {
    if (!session.receivedChunks.has(i)) missing.push(i);
  }
  if (missing.length > 0) {
    throw new UploadError('conflict', `Chunks manquants: ${missing.slice(0, 10).join(', ')}${missing.length > 10 ? '…' : ''}`);
  }

  const previousStatus = session.status;
  session.status = 'finalizing';
  try {
    persist(session);
  } catch (e) {
    session.status = previousStatus;
    throw e;
  }

  const caseDir = path.join(path.resolve(finalDir), caseId);
  const stagingPath = stagingPathOf(finalDir, caseId, uploadId);
  let finalPath: string | null = null;

  try {
    const before = await fs.promises.stat(session.tempPath);
    if (!before.isFile() || before.size !== session.totalSize) {
      throw new UploadError('invalid', 'Taille finale différente de la taille déclarée');
    }

    await fs.promises.mkdir(caseDir, { recursive: true });
    await fs.promises.rename(session.tempPath, stagingPath);

    session.status = 'hashing';
    const digests = await hashFile(stagingPath);

    const after = await fs.promises.stat(stagingPath);
    if (
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ino !== before.ino ||
      after.dev !== before.dev ||
      digests.bytes !== session.totalSize
    ) {
      throw new UploadError('invalid', 'Le fichier a été modifié pendant la finalisation');
    }
    if (session.checksumSha256 && session.checksumSha256 !== digests.sha256) {
      throw new UploadError('invalid', 'checksum SHA-256 différent de celui annoncé');
    }

    const safeOriginal = path.basename(session.originalName).replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const finalFilename = `${Date.now()}-${digests.sha256.slice(0, 8)}-${safeOriginal}`;
    finalPath = path.join(caseDir, finalFilename);
    await fs.promises.rename(stagingPath, finalPath);

    const fileSize = (await fs.promises.stat(finalPath)).size;
    if (fileSize !== session.totalSize) {
      throw new UploadError('invalid', 'Taille finale différente de la taille déclarée');
    }

    session.status = 'complete';
    await removeQuietly(metaPathOf(session.uploadDir, uploadId));
    forgetLater(uploadId);

    return {
      evidenceId: uuidv4(),
      name: session.originalName,
      filePath: finalPath,
      fileSize,
      hash_md5: digests.md5,
      hash_sha1: digests.sha1,
      hash_sha256: digests.sha256,
      tempPath: session.tempPath,
      finalPath,
    };
  } catch (err) {
    session.status = 'failed';
    await removeSessionFiles(session);
    if (finalPath) await removeQuietly(finalPath);
    forgetLater(uploadId);
    throw err;
  }
}

export async function abortUpload(params: {
  uploadId: string;
  userId: string;
  uploadDir: string;
}): Promise<void> {
  const session = requireSession(params.uploadId, params.userId, params.uploadDir);
  if (!RECEIVING.has(session.status)) {
    throw new UploadError('conflict', `Session non annulable: ${session.status}`);
  }
  session.status = 'aborting';
  const rt = runtimeOf(session);
  for (const cancel of Array.from(rt.cancelers)) cancel();
  while (rt.writers.size > 0) {
    await Promise.all(Array.from(rt.writers));
  }
  await removeSessionFiles(session);
  sessions.delete(session.uploadId);
}

export function getSessionOwner(uploadId: string, uploadDir: string = defaultUploadDir()): { userId: string; caseId: string } | null {
  const dir = ensureRecovered(uploadDir);
  const session = typeof uploadId === 'string' ? sessions.get(uploadId) : undefined;
  if (!session || session.uploadDir !== dir) return null;
  return { userId: session.userId, caseId: session.caseId };
}

export async function getSessionStatus(params: {
  uploadId: string;
  userId: string;
  uploadDir: string;
}): Promise<{
  found: boolean;
  receivedChunks: number[];
  totalChunks: number;
  status: string;
}> {
  const session = lookup(params.uploadId, params.userId, params.uploadDir);
  if (!session) return { found: false, receivedChunks: [], totalChunks: 0, status: 'not_found' };
  return {
    found: true,
    receivedChunks: Array.from(session.receivedChunks).sort((a, b) => a - b),
    totalChunks: session.totalChunks,
    status: session.status,
  };
}

export { CHUNK_SIZE, MAX_RETRIES_PER_CHUNK };
