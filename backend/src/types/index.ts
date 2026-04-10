
import type { Request } from 'express';

export interface AuthUser {
  id: string;
  username: string;
  role: 'admin' | 'analyst';
  full_name: string;
}

export interface AuthRequest extends Request {
  user: AuthUser;
}

export type UploadStatus =
  | 'pending'
  | 'uploading'
  | 'assembling'
  | 'hashing'
  | 'complete'
  | 'failed';

export interface UploadSession {

  uploadId: string;

  originalName: string;

  totalSize: number;

  chunkSize: number;

  totalChunks: number;

  receivedChunks: Set<number>;

  tempPath: string;

  caseId: string;

  userId: string;

  createdAt: number;

  status: UploadStatus;
}

export interface InitUploadResponse {
  uploadId: string;
  chunkSize: number;
  totalChunks: number;
}

export interface ChunkAckResponse {
  uploadId: string;
  chunkIndex: number;
  received: number;
  total: number;
  progress: number;
}

export interface CompleteUploadResponse {
  evidenceId: string;
  name: string;
  filePath: string;
  fileSize: number;
  hash_md5: string;
  hash_sha1: string;
  hash_sha256: string;
}

export type ParserStatus =
  | 'INIT'
  | 'RUNNING'
  | 'SUCCESS'
  | 'FAILED';

export interface ZimmermanTool {

  dll: string;

  name: string;
  description: string;

  extensions: string[];
}

export interface ParserRunConfig {

  parser: string;

  evidenceId: string;

  caseId: string;

  userId: string;

  socketId: string;

  extraArgs?: Record<string, string>;
}

export interface ParserStatusEvent {
  status: ParserStatus;
  message?: string;
  exitCode?: number;
  resultId?: string;
  recordCount?: number;
}

export interface ParserLogEvent {
  stream: 'stdout' | 'stderr';
  line: string;
  ts: number;
}

export interface SafePathResult {
  safe: boolean;
  resolvedPath: string;
  reason?: string;
}

export interface DiskSpace {
  free: number;
  size: number;
}
