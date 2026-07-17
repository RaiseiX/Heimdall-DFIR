import * as fs from 'fs';
import * as path from 'path';
import yauzl from 'yauzl';

export type ExtractLimits = { maxEntries: number; maxTotalBytes: number };
export const DEFAULT_LIMITS: ExtractLimits = { maxEntries: 100_000, maxTotalBytes: 50 * 1024 ** 3 };
export class ExtractionError extends Error {}

// Only .zip is actually extractable today (extractZip is the only extractor
// implemented). tar/tgz/gz/7z previously matched here but had no extractor,
// so isArchive(true) → extractZip() → yauzl fails to open a non-zip archive
// → ExtractionError. Restricting the regex avoids routing those uploads into
// a doomed-to-fail extraction path; tar/gz/7z support is a documented
// FOLLOW-UP (the `tar` dep is already installed for that future work).
const ARCHIVE_RE = /\.zip$/i;
export function isArchive(filePath: string): boolean { return ARCHIVE_RE.test(filePath); }

// Zip-slip-safe join that PRESERVES subdirectories. Do NOT reuse
// uploadService.safePath here: it path.basename()s the entry, which would
// flatten the archive tree. Returns null on traversal (`../`) attempts.
// Exported so its guard can be unit-tested directly (the zip-slip integration
// test is short-circuited by yauzl's own validateFileName before this runs).
export function safeJoin(destDir: string, entryName: string): string | null {
  const dest = path.resolve(destDir);
  const target = path.resolve(dest, entryName);
  if (target !== dest && !target.startsWith(dest + path.sep)) return null;
  return target;
}

export function extractZip(archivePath: string, destDir: string, limits: ExtractLimits = DEFAULT_LIMITS): Promise<{ entries: number; bytes: number }> {
  return new Promise((resolve, reject) => {
    yauzl.open(archivePath, { lazyEntries: true }, (err, zip) => {
      if (err || !zip) return reject(new ExtractionError(`cannot open zip: ${err?.message}`));
      let entries = 0, bytes = 0;
      zip.on('entry', (entry) => {
        // yauzl autoCloses the zip fd on 'error'/'end', but the reject paths
        // below emit neither, so close it explicitly to avoid a slow fd leak
        // in a long-lived worker that processes many rejected archives.
        if (++entries > limits.maxEntries) { zip.close(); return reject(new ExtractionError('archive entry limit exceeded')); }
        // Zip-slip guard that preserves subdirectories.
        const target = safeJoin(destDir, entry.fileName);
        if (!target) { zip.close(); return reject(new ExtractionError(`zip-slip blocked: ${entry.fileName}`)); }
        if (/\/$/.test(entry.fileName)) { fs.mkdirSync(target, { recursive: true }); return zip.readEntry(); }
        zip.openReadStream(entry, (e, rs) => {
          if (e || !rs) { zip.close(); return reject(new ExtractionError(`read entry failed: ${e?.message}`)); }
          fs.mkdirSync(path.dirname(target), { recursive: true });
          const ws = fs.createWriteStream(target);
          rs.on('data', (c: Buffer) => { bytes += c.length; if (bytes > limits.maxTotalBytes) { rs.destroy(); ws.destroy(); zip.close(); reject(new ExtractionError('archive size limit exceeded')); } });
          ws.on('close', () => zip.readEntry());
          ws.on('error', err2 => reject(new ExtractionError(String(err2))));
          rs.pipe(ws);
        });
      });
      zip.on('end', () => resolve({ entries, bytes }));
      zip.on('error', e => reject(new ExtractionError(String(e))));
      zip.readEntry();
    });
  });
}
