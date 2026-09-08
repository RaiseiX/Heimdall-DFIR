export const PROBE_BYTES = 16;

export async function probeFile(file) {
  if (!file) return { readable: false, reason: 'missing' };

  const size = typeof file.size === 'number' ? file.size : 0;
  if (size === 0) return { readable: false, reason: 'empty' };

  if (typeof file.slice !== 'function') return { readable: false, reason: 'unreadable' };

  try {
    const buffer = await file.slice(0, Math.min(PROBE_BYTES, size)).arrayBuffer();
    if (!buffer || buffer.byteLength === 0) return { readable: false, reason: 'unreadable' };
    return { readable: true, reason: null };
  } catch {
    return { readable: false, reason: 'unreadable' };
  }
}
