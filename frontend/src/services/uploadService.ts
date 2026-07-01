
import type {
  InitUploadResponse,
  ChunkAck,
  CompleteUploadResult,
  UploadState,
  ChunkState,
} from '../types/forensic';
import i18n from '../i18n/index.js';

const CHUNK_SIZE = 50 * 1024 * 1024;
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

const API_BASE = '/api';

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function isFrench(): boolean {
  return String(i18n.language || '').toLowerCase().startsWith('fr');
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface UploadCallbacks {

  onProgress: (state: Readonly<UploadState>) => void;

  onPhaseChange: (phase: UploadState['phase'], message?: string) => void;

  onComplete: (result: CompleteUploadResult) => void;

  onError: (message: string) => void;
}

export interface UploadOptions {
  caseId: string;
  evidenceType?: string;
  notes?: string;

  chunkSize?: number;
}

class SpeedTracker {
  private samples: { bytes: number; ts: number }[] = [];
  private readonly windowMs = 5000;

  record(bytes: number): void {
    this.samples.push({ bytes, ts: Date.now() });
    const cutoff = Date.now() - this.windowMs;
    this.samples = this.samples.filter((s) => s.ts >= cutoff);
  }

  get bytesPerSecond(): number {
    if (this.samples.length < 2) return 0;
    const oldest = this.samples[0];
    const newest = this.samples[this.samples.length - 1];
    const elapsed = (newest.ts - oldest.ts) / 1000;
    if (elapsed === 0) return 0;
    const totalBytes = this.samples.reduce((acc, s) => acc + s.bytes, 0);
    return Math.round(totalBytes / elapsed);
  }
}

export async function uploadFile(
  file: File,
  options: UploadOptions,
  callbacks: UploadCallbacks
): Promise<void> {
  const { caseId, evidenceType = 'other', notes = '', chunkSize = CHUNK_SIZE } = options;
  const { onProgress, onPhaseChange, onComplete, onError } = callbacks;

  const totalChunks = Math.ceil(file.size / chunkSize);
  const speedTracker = new SpeedTracker();

  let state: UploadState = {
    phase: 'initializing',
    uploadId: null,
    file,
    totalChunks,
    chunkSize,
    chunks: Array.from({ length: totalChunks }, (_, i): ChunkState => ({
      index: i,
      status: 'pending',
      retries: 0,
      bytesSent: 0,
    })),
    progress: 0,
    speed: 0,
    errorMessage: null,
    result: null,
  };

  function updateState(patch: Partial<UploadState>): void {
    state = { ...state, ...patch };
    onProgress(state);
  }

  onPhaseChange('initializing', i18n.t('upload.init_session'));

  let initData: InitUploadResponse;
  try {
    const res = await fetch(`${API_BASE}/upload/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ originalName: file.name, totalSize: file.size, caseId }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    initData = (await res.json()) as InitUploadResponse;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    onError(i18n.t('upload.error_init', { msg }));
    return;
  }

  updateState({ uploadId: initData.uploadId, phase: 'uploading' });
  onPhaseChange('uploading', i18n.t('upload.chunks_to_send', { count: totalChunks }));

  let alreadyReceived = new Set<number>();
  try {
    const resumeRes = await fetch(
      `${API_BASE}/upload/status/${initData.uploadId}`,
      { headers: authHeaders() }
    );
    if (resumeRes.ok) {
      const resumeData = await resumeRes.json();
      alreadyReceived = new Set<number>(resumeData.receivedChunks || []);
      if (alreadyReceived.size > 0) {
        onPhaseChange('uploading', i18n.t('upload.resume_received', { received: alreadyReceived.size, total: totalChunks }));
      }
    }
  } catch {

  }

  let doneCount = alreadyReceived.size;

  for (let idx = 0; idx < totalChunks; idx++) {

    if (alreadyReceived.has(idx)) {
      const chunks = [...state.chunks];
      chunks[idx] = { ...chunks[idx], status: 'done', bytesSent: getChunkSize(file, idx, chunkSize) };
      updateState({ chunks, progress: Math.round((doneCount / totalChunks) * 100) });
      continue;
    }

    const chunkBlob = file.slice(idx * chunkSize, (idx + 1) * chunkSize);
    const chunkBytes = chunkBlob.size;

    const chunks = [...state.chunks];
    chunks[idx] = { ...chunks[idx], status: 'uploading' };
    updateState({ chunks });

    let success = false;
    let lastError = '';

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        onPhaseChange('uploading', i18n.t('upload.chunk_retry', { index: idx, attempt: attempt + 1, max: MAX_RETRIES + 1, delay }));
        await sleep(delay);
      }

      try {
        const url = `${API_BASE}/upload/chunk?uploadId=${initData.uploadId}&chunkIndex=${idx}`;
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(chunkBytes),
            ...authHeaders(),
          },
          body: chunkBlob,
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({ error: res.statusText }));
          throw new Error(errData.error || `HTTP ${res.status}`);
        }

        const ack = (await res.json()) as ChunkAck;
        doneCount++;
        speedTracker.record(chunkBytes);

        const updatedChunks = [...state.chunks];
        updatedChunks[idx] = { ...updatedChunks[idx], status: 'done', bytesSent: chunkBytes };
        updateState({
          chunks: updatedChunks,
          progress: ack.progress,
          speed: speedTracker.bytesPerSecond,
        });

        success = true;
        break;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        const updatedChunks = [...state.chunks];
        updatedChunks[idx] = {
          ...updatedChunks[idx],
          status: attempt < MAX_RETRIES ? 'uploading' : 'error',
          retries: attempt + 1,
        };
        updateState({ chunks: updatedChunks });
      }
    }

    if (!success) {
      const msg = i18n.t('upload.error_chunk', { index: idx, attempts: MAX_RETRIES + 1, msg: lastError });
      updateState({ phase: 'error', errorMessage: msg });
      onError(msg);
      return;
    }
  }

  updateState({ phase: 'assembling', progress: 100 });
  onPhaseChange('assembling', i18n.t('upload.finalizing'));

  try {
    const res = await fetch(`${API_BASE}/upload/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({
        uploadId: initData.uploadId,
        caseId,
        evidenceType,
        notes,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const result = (await res.json()) as CompleteUploadResult;
    updateState({ phase: 'complete', result });
    onPhaseChange('complete');
    onComplete(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    updateState({ phase: 'error', errorMessage: msg });
    onError(i18n.t('upload.error_finalize', { msg }));
  }
}

function getChunkSize(file: File, index: number, chunkSize: number): number {
  const end = Math.min((index + 1) * chunkSize, file.size);
  return end - index * chunkSize;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 o';
  const k = 1024;
  const sizes = isFrench() ? ['o', 'Ko', 'Mo', 'Go', 'To'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatSpeed(bps: number): string {
  return `${formatBytes(bps)}/s`;
}
