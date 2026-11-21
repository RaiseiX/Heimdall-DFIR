import { cyberchefError } from './errors.js';

export async function decompress(bytes, format) {
  if (typeof DecompressionStream === 'undefined') throw cyberchefError('errors.decompression_unsupported');
  try {
    const stream = new Response(bytes).body.pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    throw cyberchefError('errors.decompression_failed');
  }
}
