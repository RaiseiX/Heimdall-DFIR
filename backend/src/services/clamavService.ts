
import net  from 'net';
import fs   from 'fs';

const CLAMD_HOST         = process.env.CLAMAV_HOST || 'clamav';
const CLAMD_PORT         = parseInt(process.env.CLAMAV_PORT || '3310', 10);
const CONNECT_TIMEOUT_MS = 5_000;
const SCAN_TIMEOUT_MS    = 5 * 60_000;

export interface ClamScanResult {

  clean:   boolean;

  threat?: string;

  error?:  string;
}

export async function scanFile(filePath: string): Promise<ClamScanResult> {
  return new Promise<ClamScanResult>((resolve) => {
    const socket  = net.createConnection({ host: CLAMD_HOST, port: CLAMD_PORT });
    let   response = '';
    let   settled  = false;

    const deadline = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ clean: false, error: `ClamAV scan timed out after ${SCAN_TIMEOUT_MS / 1000}s` });
    }, SCAN_TIMEOUT_MS);

    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.destroy();
      resolve({
        clean: false,
        error: 'ClamAV non disponible (initialisation en cours ou service arrêté)',
      });
    });

    function finish(err?: Error): void {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.destroy();

      if (err) {
        resolve({ clean: false, error: err.message });
        return;
      }

      const text = response.replace(/\0/g, '').trim();

      if (text.endsWith('OK')) {
        resolve({ clean: true });
      } else {
        const m = text.match(/stream:\s+(.+?)\s+FOUND/i);
        resolve({ clean: false, threat: m?.[1] ?? text });
      }
    }

    socket.on('error', (err) => finish(err));

    socket.on('connect', () => {

      socket.setTimeout(0);

      socket.write('zINSTREAM\0');

      const rs = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });

      rs.on('data', (chunk: Buffer) => {

        const lenBuf = Buffer.allocUnsafe(4);
        lenBuf.writeUInt32BE(chunk.length, 0);
        socket.write(lenBuf);
        socket.write(chunk);
      });

      rs.on('end', () => {

        socket.write(Buffer.alloc(4));
      });

      rs.on('error', (err) => finish(err));
    });

    socket.on('data', (data: Buffer) => {
      response += data.toString();

      if (response.includes('\0') || response.includes('\n')) {
        finish();
      }
    });

    socket.on('close', () => finish());
    socket.on('end',   () => finish());
  });
}
