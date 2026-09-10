const MAX_DETAIL = 2000;

function scalar(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Error) return value.message;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean' || t === 'bigint') return String(value);
  return null;
}

export function foldDetail(message: string, extras: unknown[]): { message: string; meta?: Record<string, unknown> } {
  const parts: string[] = [];
  let meta: Record<string, unknown> | undefined;

  for (const extra of extras) {
    const s = scalar(extra);
    if (s !== null) { parts.push(s); continue; }
    if (extra && typeof extra === 'object') {
      meta = { ...(meta ?? {}), ...(extra as Record<string, unknown>) };
    }
  }

  const detail = parts.join(' ').slice(0, MAX_DETAIL);
  return { message: detail ? `${message} ${detail}` : message, meta };
}
