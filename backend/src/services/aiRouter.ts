
import * as http from 'http';

const OLLAMA_URL  = process.env.OLLAMA_URL || 'http://ollama:11434';
const DEFAULT_MODEL = process.env.AI_MODEL || 'qwen2.5:7b';

// Timeouts (ms) — a hung Ollama (model load / OOM) must never block a request forever.
const PROBE_TIMEOUT_MS = parseInt(process.env.AI_PROBE_TIMEOUT_MS || '8000', 10);   // /api/tags is fast
const GEN_TIMEOUT_MS   = parseInt(process.env.AI_GEN_TIMEOUT_MS   || '180000', 10); // generation: generous (slow hosts)
const STREAM_IDLE_MS   = parseInt(process.env.AI_STREAM_IDLE_MS   || '120000', 10);  // no token for 60s = stalled

// In-process semaphore: caps concurrent Ollama generations so a modest host
// doesn't thrash when several chats/reports fire at once.
const MAX_CONCURRENT = parseInt(process.env.AI_MAX_CONCURRENT || '2', 10);
const MAX_QUEUE      = parseInt(process.env.AI_MAX_QUEUE      || '8', 10);
let _aiActive = 0;
const _aiWaiters: Array<() => void> = [];
function acquireAi(): Promise<void> {
  if (_aiActive < MAX_CONCURRENT) { _aiActive++; return Promise.resolve(); }
  if (_aiWaiters.length >= MAX_QUEUE) return Promise.reject(new Error('IA saturée : trop de demandes en attente, réessayez dans un instant.'));
  return new Promise<void>((resolve) => { _aiWaiters.push(resolve); });
}
function releaseAi(): void {
  const next = _aiWaiters.shift();
  if (next) next();                 // hand the active slot directly to the next waiter
  else if (_aiActive > 0) _aiActive--;
}

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

  await acquireAi();
  try {
  await new Promise<void>((resolve, reject) => {
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
    req.setTimeout(STREAM_IDLE_MS, () => { req.destroy(new Error('Ollama: flux interrompu (aucune réponse, timeout).')); });
    req.write(body);
    req.end();
  });
  } finally {
    releaseAi();
  }
}

// ── Non-streaming chat via /api/chat ──────────────────────────────────────────

export async function chat(config: {
  model:         string;
  messages:      OllamaMessage[];
  thinkingMode?: ThinkingMode;
  temperature?:  number;
  format?:       'json' | string;   // pass 'json' to constrain Ollama to valid JSON output
}): Promise<string> {
  const { model, thinkingMode = 'no_think', temperature = 0.1, format } = config;
  const messages = applyThinkingMode(config.messages, thinkingMode);

  const body = JSON.stringify({
    model,
    messages,
    stream:  false,
    options: { temperature },
    ...(format ? { format } : {}),
  });

  await acquireAi();
  try {
    const data = await ollamaPost('/api/chat', body);
    const raw: string = (data as any).message?.content ?? '';
    // Strip thinking blocks from non-streaming response
    const out = raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    if (!out) throw new Error(`Le modèle « ${model} » n'a renvoyé aucune réponse (modèle absent ou non chargé ?).`);
    return out;
  } finally {
    releaseAi();
  }
}

// ── Tool-calling (agentic) ────────────────────────────────────────────────────
// One non-streaming round: the model decides which case tools to call.

function safeJson(s: string): any { try { return JSON.parse(s); } catch { return {}; } }

export async function chatWithTools(config: {
  model:       string;
  messages:    OllamaMessage[];
  tools:       any[];
  temperature?: number;
}): Promise<{ content: string; toolCalls: Array<{ name: string; args: any }> }> {
  const { model, messages, tools, temperature = 0 } = config;
  const body = JSON.stringify({ model, messages, tools, stream: false, options: { temperature } });
  await acquireAi();
  try {
    const data: any = await ollamaPost('/api/chat', body);
    const msg = data.message || {};
    const toolCalls = (msg.tool_calls || [])
      .map((tc: any) => ({
        name: tc.function?.name,
        args: typeof tc.function?.arguments === 'string' ? safeJson(tc.function.arguments) : (tc.function?.arguments || {}),
      }))
      .filter((t: any) => t.name);
    return { content: msg.content || '', toolCalls };
  } finally {
    releaseAi();
  }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function ollamaGet(path: string, timeoutMs: number = PROBE_TIMEOUT_MS): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, OLLAMA_URL);
    const req = http.get(
      { hostname: url.hostname, port: parseInt(url.port) || 11434, path: url.pathname },
      (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          let parsed: any;
          try { parsed = JSON.parse(data); } catch { return reject(new Error('Réponse Ollama invalide')); }
          if (parsed && parsed.error) return reject(new Error(`Ollama: ${parsed.error}`));
          resolve(parsed);
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(new Error(`Ollama: délai dépassé (${timeoutMs} ms)`)); });
  });
}

function ollamaPost(path: string, body: string, timeoutMs: number = GEN_TIMEOUT_MS): Promise<unknown> {
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
          let parsed: any;
          try { parsed = JSON.parse(data); } catch { return reject(new Error('Réponse Ollama invalide')); }
          if (parsed && parsed.error) return reject(new Error(`Ollama: ${parsed.error}`));
          resolve(parsed);
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(new Error(`Ollama: délai dépassé (${timeoutMs} ms)`)); });
    req.write(body);
    req.end();
  });
}
