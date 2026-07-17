import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import yazl from 'yazl'; // dev-only: build fixtures. If unavailable, craft zip bytes inline.
import { extractZip, ExtractionError, isArchive, safeJoin } from '../../../src/services/ingestion/extractor';

function tmp(): string { return fs.mkdtempSync(path.join(os.tmpdir(), 'extr-')); }
function makeZip(entries: Array<[string, string]>): Promise<string> {
  const zip = new yazl.ZipFile();
  for (const [name, body] of entries) zip.addBuffer(Buffer.from(body), name);
  zip.end();
  const out = path.join(tmp(), 'a.zip');
  return new Promise(res => { const ws = fs.createWriteStream(out); zip.outputStream.pipe(ws); ws.on('close', () => res(out)); });
}

// yazl validates entry names and refuses to build a zip containing a
// `../` traversal segment (it throws "invalid relative path" on addBuffer),
// so a malicious zip-slip fixture cannot be produced via the yazl helper
// above. Per the brief's fallback note, craft the zip bytes by hand here
// (single local file header + central directory + EOCD, stored/uncompressed)
// to feed a crafted, attacker-shaped archive through extractZip.
//
// NOTE: this fixture is caught by yauzl's OWN built-in validateFileName()
// (which rejects `../` and absolute paths before the 'entry' handler fires),
// NOT by our safeJoin guard. So the zip-slip integration test below verifies
// yauzl's filename validation as our first line of defense. Our own safeJoin
// guard is covered separately and directly by the dedicated 'safeJoin' tests.
function crc32(buf: Buffer): number {
  const table: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c;
  }
  let crc = 0 ^ -1;
  for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
  return (crc ^ -1) >>> 0;
}

function makeMaliciousZip(entryName: string, content: string): string {
  const nameBuf = Buffer.from(entryName, 'utf8');
  const dataBuf = Buffer.from(content, 'utf8');
  const crc = crc32(dataBuf);

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(0, 8);
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(dataBuf.length, 18);
  localHeader.writeUInt32LE(dataBuf.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28);
  const localEntry = Buffer.concat([localHeader, nameBuf, dataBuf]);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0, 8);
  centralHeader.writeUInt16LE(0, 10);
  centralHeader.writeUInt16LE(0, 12);
  centralHeader.writeUInt16LE(0, 14);
  centralHeader.writeUInt32LE(crc, 16);
  centralHeader.writeUInt32LE(dataBuf.length, 20);
  centralHeader.writeUInt32LE(dataBuf.length, 24);
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  centralHeader.writeUInt32LE(0, 42);
  const centralEntry = Buffer.concat([centralHeader, nameBuf]);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralEntry.length, 12);
  eocd.writeUInt32LE(localEntry.length, 16);
  eocd.writeUInt16LE(0, 20);

  const zipBuf = Buffer.concat([localEntry, centralEntry, eocd]);
  const out = path.join(tmp(), 'evil.zip');
  fs.writeFileSync(out, zipBuf);
  return out;
}

describe('extractZip', () => {
  it('detects archives by extension', () => { expect(isArchive('x/y.zip')).toBe(true); expect(isArchive('a.mft')).toBe(false); });

  // FIX E: only .zip is extractable (extractZip is the only implemented
  // extractor). tar/tgz/gz/7z must NOT be treated as archives until their
  // extractors land, otherwise they're routed into extractZip and fail.
  it('does not treat tar/gz/7z as archives (only .zip is extractable today)', () => {
    expect(isArchive('a.tar')).toBe(false);
    expect(isArchive('a.tar.gz')).toBe(false);
    expect(isArchive('a.tgz')).toBe(false);
    expect(isArchive('a.gz')).toBe(false);
    expect(isArchive('a.7z')).toBe(false);
  });

  it('extracts a normal zip preserving tree', async () => {
    const zip = await makeZip([['dir/a.txt', 'hello'], ['b.txt', 'world']]);
    const dest = tmp();
    const r = await extractZip(zip, dest);
    expect(r.entries).toBe(2);
    expect(fs.readFileSync(path.join(dest, 'dir/a.txt'), 'utf8')).toBe('hello');
  });

  it('rejects a zip-slip entry (via yauzl built-in filename validation)', async () => {
    // This exercises yauzl's OWN validateFileName() (first line of defense),
    // which rejects `../` before our 'entry' handler runs. Our safeJoin guard
    // is verified directly by the 'safeJoin' describe block below.
    const zip = makeMaliciousZip('../../evil.txt', 'pwned');
    await expect(extractZip(zip, tmp())).rejects.toThrow(ExtractionError);
  });

  it('stops at the entry limit', async () => {
    const zip = await makeZip(Array.from({ length: 5 }, (_, i) => [`f${i}.txt`, 'x'] as [string, string]));
    await expect(extractZip(zip, tmp(), { maxEntries: 2, maxTotalBytes: 1e9 })).rejects.toThrow(ExtractionError);
  });

  it('stops at the total byte limit', async () => {
    // Two small text entries whose combined size exceeds maxTotalBytes=3.
    const zip = await makeZip([['a.txt', 'hello'], ['b.txt', 'world']]);
    await expect(extractZip(zip, tmp(), { maxEntries: 1_000_000, maxTotalBytes: 3 })).rejects.toThrow(ExtractionError);
  });
});

describe('safeJoin', () => {
  it('preserves subdirectories under the dest dir', () => {
    const dest = tmp();
    const joined = safeJoin(dest, 'dir/a.txt');
    expect(joined).not.toBeNull();
    // Use path.join to compare in an OS-agnostic way.
    expect(joined).toBe(path.join(dest, 'dir', 'a.txt'));
    expect(joined!.endsWith(path.join('dir', 'a.txt'))).toBe(true);
  });

  it('rejects `../` traversal that escapes the dest dir', () => {
    const dest = tmp();
    expect(safeJoin(dest, '../../evil.txt')).toBeNull();
  });

  it('rejects an absolute path that escapes the dest dir', () => {
    const dest = tmp();
    expect(safeJoin(dest, '/etc/passwd')).toBeNull();
  });

  it('rejects a prefix-collision sibling directory (uses dest + path.sep, not bare startsWith)', () => {
    // Craft an entry name that resolves to a SIBLING dir whose path starts
    // with dest as a string prefix but is not actually inside dest, e.g.
    // dest=/tmp/x -> /tmp/xevil/f. A bare startsWith(dest) would wrongly
    // allow this; the guard must anchor on dest + path.sep.
    const dest = tmp();
    const sibling = dest + 'evil'; // string-prefix collision, not a child of dest
    const entryName = path.relative(dest, path.join(sibling, 'f'));
    // Sanity: the crafted entry really does resolve to the sibling, not under dest.
    expect(path.resolve(dest, entryName)).toBe(path.join(sibling, 'f'));
    expect(safeJoin(dest, entryName)).toBeNull();
  });
});
