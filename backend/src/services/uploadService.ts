
import fs from 'fs';
import logger from '../config/logger';
import path from 'path';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { IncomingMessage } from 'http';
import type {
  UploadSession,
  InitUploadResponse,
  ChunkAckResponse,
  CompleteUploadResponse,
  DiskSpace,
  SafePathResult,
} from '../types/index';

const CHUNK_SIZE = 50 * 1024 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_RETRIES_PER_CHUNK = 3;

const sessions = new Map<string, UploadSession>();

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      cleanupSession(session).catch(e => logger.warn('[Upload] cleanup failed:', e.message));
      sessions.delete(id);
    }
  }
}, 60 * 60 * 1000);

export function safePath(untrusted: string, allowedBase: string): SafePathResult {
  const base = path.resolve(allowedBase);

  const resolved = path.resolve(base, path.basename(untrusted));

  if (!resolved.startsWith(base + path.sep) && resolved !== base) {
    return { safe: false, resolvedPath: resolved, reason: 'Path traversal detected' };
  }
  return { safe: true, resolvedPath: resolved };
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

async function cleanupSession(session: UploadSession): Promise<void> {
  try {
    if (fs.existsSync(session.tempPath)) {
      await fs.promises.unlink(session.tempPath);
    }
  } catch {

  }
}

export function initUpload(params: {
  originalName: string;
  totalSize: number;
  caseId: string;
  userId: string;
  uploadDir: string;
}): InitUploadResponse {
  const { originalName, totalSize, caseId, userId, uploadDir } = params;

  const uploadId = uuidv4();
  const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);

  const tempDir = path.resolve(uploadDir, 'chunks');
  fs.mkdirSync(tempDir, { recursive: true });
  const tempPath = path.join(tempDir, `${uploadId}.tmp`);

  const fd = fs.openSync(tempPath, 'w');
  try { fs.ftruncateSync(fd, totalSize); } finally { fs.closeSync(fd); }

  const session: UploadSession = {
    uploadId,
    originalName,
    totalSize,
    chunkSize: CHUNK_SIZE,
    totalChunks,
    receivedChunks: new Set(),
    tempPath,
    caseId,
    userId,
    createdAt: Date.now(),
    status: 'pending',
  };

  sessions.set(uploadId, session);

  return { uploadId, chunkSize: CHUNK_SIZE, totalChunks };
}

export async function receiveChunk(params: {
  uploadId: string;
  chunkIndex: number;
  req: IncomingMessage;
  uploadDir: string;
}): Promise<ChunkAckResponse> {
  const { uploadId, chunkIndex, req, uploadDir } = params;

  const session = sessions.get(uploadId);
  if (!session) throw new Error('Session invalide ou expirée');
  if (session.status === 'complete' || session.status === 'failed') {
    throw new Error(`Session already in terminal state: ${session.status}`);
  }
  if (chunkIndex < 0 || chunkIndex >= session.totalChunks) {
    throw new Error(`Index de chunk hors limites: ${chunkIndex}`);
  }

  const disk = await getDiskSpace(session.tempPath);
  if (disk.free < CHUNK_SIZE * 2) {
    throw new Error(
      `Espace disque insuffisant: ${(disk.free / 1024 / 1024).toFixed(0)} Mo libres`
    );
  }

  if (session.receivedChunks.has(chunkIndex)) {
    const progress = Math.round((session.receivedChunks.size / session.totalChunks) * 100);
    return { uploadId, chunkIndex, received: session.receivedChunks.size, total: session.totalChunks, progress };
  }

  const offset = chunkIndex * session.chunkSize;
  const writeStream = fs.createWriteStream(session.tempPath, { flags: 'r+', start: offset });

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    function fail(err: Error) {
      if (settled) return;
      settled = true;
      writeStream.destroy();
      req.destroy();
      reject(err);
    }

    req.pipe(writeStream);
    writeStream.on('finish', () => { settled = true; resolve(); });
    writeStream.on('error', fail);
    req.on('error', fail);

    req.on('close', () => {
      if (!req.readableEnded) {
        fail(new Error('Connexion interrompue par le client'));
      }
    });
  });

  session.receivedChunks.add(chunkIndex);
  session.status = 'uploading';

  const progress = Math.round((session.receivedChunks.size / session.totalChunks) * 100);
  return {
    uploadId,
    chunkIndex,
    received: session.receivedChunks.size,
    total: session.totalChunks,
    progress,
  };
}

export async function completeUpload(params: {
  uploadId: string;
  caseId: string;
  userId: string;
  finalDir: string;
}): Promise<CompleteUploadResponse & { tempPath: string; finalPath: string }> {
  const { uploadId, caseId, userId, finalDir } = params;

  const session = sessions.get(uploadId);
  if (!session) throw new Error('Session invalide ou expirée');

  const missing: number[] = [];
  for (let i = 0; i < session.totalChunks; i++) {
    if (!session.receivedChunks.has(i)) missing.push(i);
  }
  if (missing.length > 0) {
    throw new Error(`Chunks manquants: ${missing.slice(0, 10).join(', ')}${missing.length > 10 ? '…' : ''}`);
  }

  session.status = 'hashing';

  const md5Hash = crypto.createHash('md5');
  const sha1Hash = crypto.createHash('sha1');
  const sha256Hash = crypto.createHash('sha256');

  const readStream = fs.createReadStream(session.tempPath, {
    highWaterMark: 64 * 1024,
  });

  await new Promise<void>((resolve, reject) => {
    readStream.on('data', (chunk: Buffer) => {
      md5Hash.update(chunk);
      sha1Hash.update(chunk);
      sha256Hash.update(chunk);
    });
    readStream.on('end', resolve);
    readStream.on('error', reject);
  });

  const hash_md5 = md5Hash.digest('hex');
  const hash_sha1 = sha1Hash.digest('hex');
  const hash_sha256 = sha256Hash.digest('hex');

  const caseDir = path.join(path.resolve(finalDir), caseId);
  fs.mkdirSync(caseDir, { recursive: true });

  const safeOriginal = path.basename(session.originalName).replace(/[^a-zA-Z0-9.\-_]/g, '_');
  const finalFilename = `${Date.now()}-${hash_sha256.slice(0, 8)}-${safeOriginal}`;
  const finalPath = path.join(caseDir, finalFilename);

  await fs.promises.rename(session.tempPath, finalPath);

  const fileSize = (await fs.promises.stat(finalPath)).size;
  session.status = 'complete';

  setTimeout(() => sessions.delete(uploadId), 5000);

  return {
    evidenceId: uuidv4(),
    name: session.originalName,
    filePath: finalPath,
    fileSize,
    hash_md5,
    hash_sha1,
    hash_sha256,
    tempPath: session.tempPath,
    finalPath,
  };
}

export function getSessionStatus(uploadId: string): {
  found: boolean;
  receivedChunks: number[];
  totalChunks: number;
  status: string;
} {
  const session = sessions.get(uploadId);
  if (!session) return { found: false, receivedChunks: [], totalChunks: 0, status: 'not_found' };
  return {
    found: true,
    receivedChunks: Array.from(session.receivedChunks).sort((a, b) => a - b),
    totalChunks: session.totalChunks,
    status: session.status,
  };
}

export { CHUNK_SIZE, MAX_RETRIES_PER_CHUNK };
