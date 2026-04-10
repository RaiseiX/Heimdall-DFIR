
export type UploadPhase =
  | 'idle'
  | 'initializing'
  | 'uploading'
  | 'assembling'
  | 'hashing'
  | 'complete'
  | 'error';

export interface ChunkState {
  index: number;
  status: 'pending' | 'uploading' | 'done' | 'error';
  retries: number;
  bytesSent: number;
}

export interface UploadState {
  phase: UploadPhase;
  uploadId: string | null;
  file: File | null;
  totalChunks: number;
  chunkSize: number;
  chunks: ChunkState[];

  progress: number;

  speed: number;
  errorMessage: string | null;

  result: CompleteUploadResult | null;
}

export interface InitUploadResponse {
  uploadId: string;
  chunkSize: number;
  totalChunks: number;
}

export interface ChunkAck {
  uploadId: string;
  chunkIndex: number;
  received: number;
  total: number;
  progress: number;
}

export interface CompleteUploadResult {
  evidenceId: string;
  name: string;
  fileSize: number;
  hash_md5: string;
  hash_sha1: string;
  hash_sha256: string;
}

export type ParserStatus = 'INIT' | 'RUNNING' | 'SUCCESS' | 'FAILED';

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

export interface LogEntry extends ParserLogEvent {
  id: number;
}

export interface AvailableTool {
  dll: string;
  name: string;
  description: string;
  extensions: string[];
  available: boolean;
  path: string;
}

export type AvailableTools = Record<string, AvailableTool>;

export interface TimelineEvent {
  id: string;
  case_id: string;
  event_time: string;
  event_type: 'alert' | 'malware' | 'exfil' | 'network' | 'analysis' | 'response' | 'persistence' | 'lateral' | 'discovery' | 'other';
  title: string;
  description: string | null;
  source: string | null;
  evidence_id: string | null;
  created_by: string | null;
}

export interface Evidence {
  id: string;
  case_id: string;
  name: string;
  original_filename: string;
  file_path: string;
  file_size: number;
  evidence_type: string;
  hash_md5: string | null;
  hash_sha1: string | null;
  hash_sha256: string | null;
  is_highlighted: boolean;
  notes: string | null;
  added_by: string | null;
  added_by_name: string | null;
  created_at: string;
}

export interface SocketHookReturn {
  socket: import('socket.io-client').Socket | null;
  isConnected: boolean;
  socketId: string | null;
}
