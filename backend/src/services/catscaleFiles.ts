// File discovery inside a CatScale collection.
//
// Lives in its own module so both catscaleService (the timeline parsers) and
// catscaleStateCollect (the state artifacts) can use it without importing each
// other.
import * as fs from 'fs';
import * as path from 'path';

/** One thing that did not work. `stage` names where, so the UI can be specific. */
export type CatScaleFailure = { stage: 'extract' | 'insert' | 'parse'; target: string; reason: string };

// Cat-Scale.sh names every output `<host>-<DTG>-<artifact>[-<discriminator>].<ext>`.
// A plain substring test is wrong because artifact names are prefixes of each
// other — 'last-utmp' also matches 'last-utmpdump' (Cat-Scale.sh:393-394) and
// 'last-wtmp' also matches 'last-wtmpx' (Cat-Scale.sh:426). Feeding a utmpdump
// file to the `last` parser yields zero events and silently drops the real one.
//
// So the artifact name must be delimited: preceded by '-' (or start of name) and
// followed by '.' (end of the artifact name) or '-' (a discriminator such as the
// container id in docker-inspect-<id>.txt).
function artifactRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|-)${escaped}(?=$|[.-])`);
}

// Artifact names that are a strict extension of another artifact name, where the
// delimiter cannot tell them apart. 'dev-dir-files' is followed by '-' inside
// 'dev-dir-files-hashes', and that same '-' is what lets 'docker-inspect' match
// 'docker-inspect-<container id>' — so the delimiter must stay permissive and the
// exception must be declared.
//
// This was harmless while neither artifact produced anything. It stopped being
// harmless once the registry declared both, with incompatible shapes: path_desc
// for the file list, hash_list for the hashes. Feeding one to the other's parser
// attributes rows to the wrong file, which is exactly what the coverage ledger
// must be able to trust.
const SIBLINGS: Record<string, string[]> = {
  'dev-dir-files': ['dev-dir-files-hashes'],
};

export function findArtifactFiles(dir: string, ...patterns: string[]): string[] {
  if (!fs.existsSync(dir)) return [];
  let entries: string[];
  try { entries = fs.readdirSync(dir); } catch { return []; }
  const regexes = patterns.map(artifactRegex);
  const excluded = patterns
    .flatMap(p => SIBLINGS[p] ?? [])
    .filter(s => !patterns.includes(s))
    .map(artifactRegex);
  return entries
    .filter(e => regexes.some(r => r.test(e)))
    .filter(e => !excluded.some(r => r.test(e)))
    .sort()
    .map(e => path.join(dir, e));
}

// For artifacts where Cat-Scale writes one of several mutually exclusive formats
// — the `ps` chain at Cat-Scale.sh:192-202, the ss/netstat chain at 269-279 — the
// patterns are alternatives, not a set. Take the first format that is present.
export function findArtifactFile(dir: string, ...patterns: string[]): string | null {
  for (const p of patterns) {
    const [first] = findArtifactFiles(dir, p);
    if (first) return first;
  }
  return null;
}
