
import * as http from 'http';

const OLLAMA_URL  = process.env.OLLAMA_URL || 'http://ollama:11434';
const DEFAULT_MODEL = process.env.AI_MODEL || 'qwen3.5:4b';

// ── Types ─────────────────────────────────────────────────────────────────────

export type TaskTier    = 'fast' | 'standard' | 'deep';
export type ThinkingMode = 'think' | 'no_think';

export interface ModelInfo {
  name:           string;
  parameterCount: number | null;  // parsed from model name (billions)
  sizeGB:         number | null;  // from Ollama metadata
}

export interface OllamaStatus {
  reachable: boolean;
  models:    ModelInfo[];
  tier:      TaskTier | 'none';
  preferred: Record<TaskTier, string | null>;
}

export interface OllamaMessage {
  role:    'system' | 'user' | 'assistant';
  content: string;
}

export interface StreamConfig {
  model:              string;
  messages:           OllamaMessage[];
  thinkingMode?:      ThinkingMode;   // default 'no_think'
  temperature?:       number;
  onToken:            (token: string) => void;
  onReasoningToken?:  (token: string) => void;  // content inside <think>…</think>
  onDone:             (fullText: string) => void;
  onError:            (err: Error) => void;
}

// ── Model tier detection ───────────────────────────────────────────────────────

function parseParamCount(name: string): number | null {
  const m = name.toLowerCase().match(/(\d+(?:\.\d+)?)b/);
  return m ? parseFloat(m[1]) : null;
}

function tierForParams(params: number | null): TaskTier {
  if (params === null) return 'standard';
  if (params >= 14)   return 'deep';
  if (params >= 7)    return 'standard';
  return 'fast';
}

// ── Status cache (60 s TTL) ───────────────────────────────────────────────────

let _cache: { status: OllamaStatus; at: number } | null = null;

export async function probe(): Promise<OllamaStatus> {
  if (_cache && Date.now() - _cache.at < 60_000) return _cache.status;

  try {
    const data = await ollamaGet('/api/tags');
    const raw: Array<{ name: string; size?: number }> =
      (data as any).models ?? [];

    const models: ModelInfo[] = raw.map((m) => ({
      name:           m.name,
      parameterCount: parseParamCount(m.name),
      sizeGB:         m.size ? Math.round(m.size / 1e9 * 10) / 10 : null,
    }));

    const preferred: Record<TaskTier, string | null> = {
      fast: null, standard: null, deep: null,
    };

    for (const tier of ['fast', 'standard', 'deep'] as TaskTier[]) {
      const candidates = models
        .filter((m) => tierForParams(m.parameterCount) === tier)
        .sort((a, b) => (b.parameterCount ?? 0) - (a.parameterCount ?? 0));
      preferred[tier] = candidates[0]?.name ?? null;
    }

    const tier: TaskTier | 'none' =
      preferred.deep     ? 'deep'     :
      preferred.standard ? 'standard' :
      preferred.fast     ? 'fast'     : 'none';

    const status: OllamaStatus = { reachable: true, models, tier, preferred };
    _cache = { status, at: Date.now() };
    return status;
  } catch {
    const status: OllamaStatus = {
      reachable: false,
      models:    [],
      tier:      'none',
      preferred: { fast: null, standard: null, deep: null },
    };
    _cache = { status, at: Date.now() };
    return status;
  }
}

export function invalidateCache(): void {
  _cache = null;
}

/** Best available model for the requested tier, with graceful fallback. */
export async function selectModel(tier: TaskTier): Promise<string> {
  const status = await probe();
  return (
    status.preferred[tier] ??
    status.preferred.standard ??
    status.preferred.deep ??
    status.preferred.fast ??
    DEFAULT_MODEL
  );
}

// ── Thinking-mode injection ───────────────────────────────────────────────────
// Qwen 3 activates chain-of-thought via a /think or /no_think prefix on the
// system message. Thinking mode emits <think>…</think> blocks before the answer.

function applyThinkingMode(
  messages: OllamaMessage[],
  mode: ThinkingMode
): OllamaMessage[] {
  const prefix = mode === 'think' ? '/think\n' : '/no_think\n';
  return messages.map((m, i) =>
    m.role === 'system' && i === 0
      ? { ...m, content: prefix + m.content }
      : m
  );
}

// ── Stream parser: separates <think> tokens from answer tokens ────────────────

function parseThinkStream(
  token: string,
  state: { inThink: boolean },
  onToken:    (t: string) => void,
  onThinkToken?: (t: string) => void
): void {
  let rest = token;

  while (rest.length > 0) {
    if (state.inThink) {
      const closeIdx = rest.indexOf('</think>');
      if (closeIdx === -1) {
        onThinkToken?.(rest);
        rest = '';
      } else {
        onThinkToken?.(rest.slice(0, closeIdx));
        state.inThink = false;
        rest = rest.slice(closeIdx + 8); // 8 = '</think>'.length
      }
    } else {
      const openIdx = rest.indexOf('<think>');
      if (openIdx === -1) {
        onToken(rest);
        rest = '';
      } else {
        if (openIdx > 0) onToken(rest.slice(0, openIdx));
        state.inThink = true;
        rest = rest.slice(openIdx + 7); // 7 = '<think>'.length
      }
    }
  }
}

// ── Streaming chat via /api/chat ──────────────────────────────────────────────

export async function streamChat(config: StreamConfig): Promise<void> {
  const {
    model,
    thinkingMode = 'no_think',
    temperature  = 0.1,
    onToken,
    onReasoningToken,
    onDone,
    onError,
  } = config;

  const messages = applyThinkingMode(config.messages, thinkingMode);
  const body = JSON.stringify({
    model,
    messages,
    stream:  true,
    options: { temperature },
  });

  return new Promise((resolve, reject) => {
    const url = new URL('/api/chat', OLLAMA_URL);
    const req = http.request(
      {
        hostname: url.hostname,
        port:     parseInt(url.port) || 11434,
        path:     url.pathname,
        method:   'POST',
        headers: {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (ollamaRes) => {
        let fullText  = '';
        let remainder = '';
        let doneCalled = false;
        const thinkState = { inThink: false };

        const callDone = () => {
          if (doneCalled) return;
          doneCalled = true;
          onDone(fullText);
        };

        ollamaRes.on('data', (chunk: Buffer) => {
          const text  = remainder + chunk.toString('utf8');
          const lines = text.split('\n');
          remainder   = lines.pop() ?? '';

          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const j = JSON.parse(line);
              if (j.done) { callDone(); continue; }

              const token: string = j.message?.content ?? '';
              if (!token) continue;

              parseThinkStream(
                token,
                thinkState,
                (t) => { fullText += t; onToken(t); },
                onReasoningToken
              );
            } catch (_e) {}
          }
        });

        ollamaRes.on('end', () => {
          callDone();
          resolve();
        });

        ollamaRes.on('error', (err) => {
          onError(err);
          reject(err);
        });
      }
    );

    req.on('error', (err) => {
      onError(err);
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

// ── Non-streaming chat via /api/chat ──────────────────────────────────────────

export async function chat(config: {
  model:         string;
  messages:      OllamaMessage[];
  thinkingMode?: ThinkingMode;
  temperature?:  number;
}): Promise<string> {
  const { model, thinkingMode = 'no_think', temperature = 0.1 } = config;
  const messages = applyThinkingMode(config.messages, thinkingMode);

  const body = JSON.stringify({
    model,
    messages,
    stream:  false,
    options: { temperature },
  });

  const data = await ollamaPost('/api/chat', body);
  const raw: string = (data as any).message?.content ?? '';

  // Strip thinking blocks from non-streaming response
  return raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function ollamaGet(path: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, OLLAMA_URL);
    http.get(
      { hostname: url.hostname, port: parseInt(url.port) || 11434, path: url.pathname },
      (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          try   { resolve(JSON.parse(data)); }
          catch { reject(new Error('Invalid JSON from Ollama')); }
        });
        res.on('error', reject);
      }
    ).on('error', reject);
  });
}

function ollamaPost(path: string, body: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, OLLAMA_URL);
    const req = http.request(
      {
        hostname: url.hostname,
        port:     parseInt(url.port) || 11434,
        path:     url.pathname,
        method:   'POST',
        headers: {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          try   { resolve(JSON.parse(data)); }
          catch { reject(new Error('Invalid JSON from Ollama')); }
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
