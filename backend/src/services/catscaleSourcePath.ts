import * as fs from 'fs';
import * as path from 'path';

// The single source value that travels with the data, from read to display.
//
// Two rules make this worth its own module. The folder is forensic information
// in itself: Persistence does not say the same thing as Misc. And the host and
// DTG prefix belongs to the collection, not to each of its 335,715 rows, where
// it costs 24 characters of a 170px column.
//
// No parser may write a category (systemd, syslog, .bash_history) here. The
// category belongs to artifact_type, which already exists.

/** The `<host>-<DTG>-` prefix Cat-Scale.sh gives every output it writes. */
export function outfilePrefix(hostname: string, collectedAt: Date): string {
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const d = collectedAt;
  const dtg = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}`;
  return `${hostname}-${dtg}-`;
}

/**
 * The prefix, read off the collection instead of reconstructed from it.
 *
 * `outfilePrefix(hostname, collectedAt)` looked right and was wrong in production:
 * `collectedAt` is the mtime of the extracted directory, not the DTG Cat-Scale
 * burned into the filenames. On 2026-08-17 that mismatch left every stored path
 * as `Misc/Dlinux-20260730-1444-full-timeline.csv` — the folder gained, the
 * 24-character prefix still there.
 *
 * The filenames are the only authority on their own prefix, so it is taken by
 * majority vote across them. A collection whose files disagree yields no prefix
 * and keeps its names whole, which loses nothing.
 */
export function detectOutfilePrefix(catscaleRoot: string): string {
  const counts = new Map<string, number>();
  const walk = (dir: string, depth: number): void => {
    if (depth > 2) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) { walk(path.join(dir, e.name), depth + 1); continue; }
      const m = /^(.+-\d{8}-\d{4}-)/.exec(e.name);
      if (m) counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
    }
  };
  walk(catscaleRoot, 0);
  let best = '';
  let bestN = 0;
  for (const [p, n] of counts) if (n > bestN) { best = p; bestN = n; }
  return best;
}

/** `<folder>/<file>`, prefix removed when present. Archives carry none. */
export function buildSourcePath(catscaleRoot: string, absPath: string, prefix: string): string {
  const rel = path.relative(catscaleRoot, absPath).split(path.sep).join('/');
  const dir = path.posix.dirname(rel);
  const base = path.posix.basename(rel);
  const stripped = prefix && base.startsWith(prefix) ? base.slice(prefix.length) : base;
  return dir === '.' ? stripped : `${dir}/${stripped}`;
}

/** `<folder>/<archive> -> <internal path>`. The arrow is U+2192. */
export function archiveMemberPath(outerSourcePath: string, extractRoot: string, memberAbsPath: string): string {
  const inner = path.relative(extractRoot, memberAbsPath).split(path.sep).join('/');
  return `${outerSourcePath} → ${inner}`;
}
