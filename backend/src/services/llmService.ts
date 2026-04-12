
import * as http from 'http';

const OLLAMA_URL = process.env.OLLAMA_URL;

export function isAvailable(): boolean {
  return Boolean(OLLAMA_URL);
}

export async function listModels(): Promise<string[]> {
  if (!OLLAMA_URL) return [];
  try {
    const url = new URL('/api/tags', OLLAMA_URL);
    const data = await fetchJson(url.toString());
    return ((data as any).models || []).map((m: any) => m.name).filter(Boolean);
  } catch {
    return [];
  }
}

export async function streamAnalysis(
  prompt: string,
  model: string,
  res: import('express').Response
): Promise<void> {
  if (!OLLAMA_URL) {
    res.status(503).json({ error: 'OLLAMA_URL not configured' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const keepAlive = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_e) {}
  }, 5000);

  const ollamaUrl = new URL('/api/generate', OLLAMA_URL);
  const body = JSON.stringify({ model, prompt, stream: true });

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: ollamaUrl.hostname,
        port: parseInt(ollamaUrl.port) || 11434,
        path: ollamaUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (ollamaRes) => {
        ollamaRes.on('data', (chunk: Buffer) => {
          const lines = chunk.toString().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const j = JSON.parse(line);
              if (j.response) res.write(`data: ${JSON.stringify({ response: j.response })}\n\n`);
              if (j.done) { res.write('data: [DONE]\n\n'); }
            } catch (_e) {}
          }
        });
        ollamaRes.on('end', () => {
          clearInterval(keepAlive);
          res.end();
          resolve();
        });
        ollamaRes.on('error', (err) => {
          clearInterval(keepAlive);
          reject(err);
        });
      }
    );
    req.on('error', (err) => {
      clearInterval(keepAlive);
      res.write(`data: ${JSON.stringify({ error: `Ollama unreachable: ${err.message}` })}\n\n`);
      res.end();
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

export async function pullModel(
  model: string,
  res: import('express').Response
): Promise<void> {
  if (!OLLAMA_URL) {
    res.status(503).json({ error: 'OLLAMA_URL not configured' });
    return;
  }

  const ollamaUrl = new URL('/api/pull', OLLAMA_URL);
  const body = JSON.stringify({ model, stream: true });

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: ollamaUrl.hostname,
        port: parseInt(ollamaUrl.port) || 11434,
        path: ollamaUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (ollamaRes) => {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders?.();

        ollamaRes.on('data', (chunk: Buffer) => {
          const lines = chunk.toString().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const j = JSON.parse(line);

              res.write(`data: ${JSON.stringify(j)}\n\n`);
              if (j.status === 'success') res.write('data: [DONE]\n\n');
            } catch (_e) {}
          }
        });
        ollamaRes.on('end', () => { res.end(); resolve(); });
        ollamaRes.on('error', reject);
      }
    );
    req.on('error', (err) => {
      if (!res.headersSent) res.status(502).json({ error: `Ollama unreachable: ${err.message}` });
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

export async function deleteModel(model: string): Promise<void> {
  if (!OLLAMA_URL) return;
  const ollamaUrl = new URL('/api/delete', OLLAMA_URL);
  const body = JSON.stringify({ model });
  await new Promise<void>((resolve, reject) => {
    const req = http.request(
      {
        hostname: ollamaUrl.hostname,
        port: parseInt(ollamaUrl.port) || 11434,
        path: ollamaUrl.pathname,
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      },
      (ollamaRes) => { ollamaRes.resume(); ollamaRes.on('end', resolve); }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function fetchJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (c: string) => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } });
    }).on('error', reject);
  });
}
