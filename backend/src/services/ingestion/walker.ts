import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export type WalkedFile = { relativePath: string; absPath: string; size: number; sha256: string; header: Buffer };

async function hashAndHeader(absPath: string): Promise<{ sha256: string; header: Buffer }> {
  const h = crypto.createHash('sha256');
  const chunks: Buffer[] = []; let got = 0;
  await new Promise<void>((resolve, reject) => {
    const rs = fs.createReadStream(absPath, { highWaterMark: 64 * 1024 });
    rs.on('data', (c: Buffer) => { h.update(c); if (got < 2048) { chunks.push(c.slice(0, 2048 - got)); got += c.length; } });
    rs.on('end', resolve); rs.on('error', reject);
  });
  return { sha256: h.digest('hex'), header: Buffer.concat(chunks).slice(0, 2048) };
}

export async function* walk(rootDir: string): AsyncGenerator<WalkedFile> {
  const stack = [rootDir];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const dirent of await fs.promises.readdir(dir, { withFileTypes: true })) {
      const abs = path.join(dir, dirent.name);
      if (dirent.isDirectory()) { stack.push(abs); continue; }
      if (!dirent.isFile()) continue; // skip symlinks/sockets — safety
      const stat = await fs.promises.stat(abs);
      const { sha256, header } = await hashAndHeader(abs);
      yield { relativePath: path.relative(rootDir, abs).split(path.sep).join('/'), absPath: abs, size: stat.size, sha256, header };
    }
  }
}
