// Generic shape parsers for CatScale artifacts.
//
// A collection carries ~25 unparsed files, but they only take five shapes:
// digest lists, path lists, whitespace tables, key/value blocks, "path:
// description" and `head` markers. Writing one parser per file would be writing
// the same code five times, each with its own bugs. Formats below were read off
// a real collection before being implemented.

/** "<sha1>  <path>" — module-sha1, exec-perm-files, processhashes, *-hashes. */
export function parseHashList(content: string): { sha1: string; path: string }[] {
  const out: { sha1: string; path: string }[] = [];
  for (const line of content.split('\n')) {
    // Paths may contain spaces, so only the digest is delimited.
    const m = /^([0-9a-f]{32,64})\s+(\/.*\S)\s*$/i.exec(line.trim());
    if (!m) continue;
    out.push({ sha1: m[1].toLowerCase(), path: m[2] });
  }
  return out;
}

/** One absolute path per line — Setuid-Setguid-tools, the *-list.txt inventories. */
export function parsePathList(content: string): string[] {
  const out: string[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    // Duplicates are kept: two lines are two observations, and collapsing them
    // would quietly change what the collector reported.
    if (t.startsWith('/')) out.push(t);
  }
  return out;
}

function normaliseHeader(h: string): string {
  return h.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

/**
 * Whitespace-aligned table whose first non-empty line is the header — lsmod, who,
 * w, lsof, docker top, container ls. Values are split on runs of whitespace and
 * the final column absorbs the remainder, because the last field (a command line,
 * a dependent-module list) legitimately contains spaces.
 */
export function parseHeaderTable(content: string, columns?: string[]): Record<string, string>[] {
  const lines = content.split('\n');
  const headerIdx = lines.findIndex(l => l.trim().length > 0);
  if (headerIdx === -1) return [];
  // Column names are separated by two or more spaces in an aligned table, which
  // is what keeps `lsmod`'s "Used by" one column instead of two. A few tools —
  // lsof notably — put a single space between two headers; those pass their
  // column names in explicitly rather than bend the rule for everyone.
  const headers = (columns ?? lines[headerIdx].trim().split(/\s{2,}/)).map(normaliseHeader);
  if (!headers.length) return [];

  const out: Record<string, string>[] = [];
  for (const line of lines.slice(headerIdx + 1)) {
    if (!line.trim()) continue;
    const parts = line.trim().split(/\s+/);
    if (parts.length < headers.length) {
      // Short row: map what is there, leave the rest empty rather than shift
      // every value one column to the left.
      const row: Record<string, string> = {};
      headers.forEach((h, i) => { row[h] = parts[i] ?? ''; });
      out.push(row);
      continue;
    }
    const row: Record<string, string> = {};
    headers.forEach((h, i) => {
      row[h] = i === headers.length - 1 ? parts.slice(i).join(' ') : parts[i];
    });
    out.push(row);
  }
  return out;
}

/**
 * "key: value" or KEY="value" lines with no block structure — os-release, cpuinfo,
 * meminfo, docker info and version. Indentation is part of docker's layout, not of
 * the key, so it is trimmed.
 */
export function parseKeyValueLines(content: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = /^([^:=]{1,80}?)\s*[:=]\s*(.*)$/.exec(t);
    if (!m) continue;
    // os-release quotes its values; the quotes are syntax, the content is evidence.
    const value = m[2].replace(/^"(.*)"$/, '$1');
    out.push({ key: m[1].trim(), value });
  }
  return out;
}

/**
 * Last resort: one row per non-empty line, numbered.
 *
 * Used where the format carries no structure worth extracting yet — dmesg, a
 * container's stdout, `sudo -V`. It exists so that "we have not written a parser
 * for this shape" never becomes "this file contained nothing": the content is
 * recorded, attributed to its file, and searchable. A better shape can replace it
 * later without the evidence having been absent in between.
 */
export function parseTextLines(content: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const t = lines[i].trim();
    if (t) out.push({ line: i + 1, text: t });
  }
  return out;
}

/**
 * A JSON document — `docker network inspect` emits an array of objects. One row
 * per top-level element; a document that is not an array becomes a single row.
 * Invalid JSON yields nothing rather than throwing, so one malformed file cannot
 * abort the collection.
 */
export function parseJsonDoc(content: string): Record<string, unknown>[] {
  let parsed: unknown;
  try { parsed = JSON.parse(content); } catch { return []; }
  if (Array.isArray(parsed)) {
    return parsed.map(e => (e && typeof e === 'object' ? e as Record<string, unknown> : { value: e }));
  }
  if (parsed && typeof parsed === 'object') return [parsed as Record<string, unknown>];
  return [];
}

export interface AuthorizedKey {
  algo: string;
  key: string;
  comment: string;
  options: string;
}

/**
 * An OpenSSH authorized_keys file. One row per key.
 *
 * Adding a key here is the quietest durable foothold on a Linux host: it survives
 * a password change, needs no process, and leaves no entry in shell history. The
 * file lives inside ssh-folders.tar.gz, an archive this parser never opened until
 * 2026-08-17 — the reference collection carried a planted key the whole time.
 *
 * Leading options (`command=`, `from=`, `no-pty`) are kept: a key restricted to a
 * command is a different fact from an unrestricted one, in both directions.
 */
export function parseAuthorizedKeys(content: string): AuthorizedKey[] {
  const out: AuthorizedKey[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = /(^|\s)(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+)\s+([A-Za-z0-9+/=]+)\s*(.*)$/.exec(t);
    if (!m) continue;
    out.push({
      options: t.slice(0, m.index + (m[1] ? m[1].length : 0)).trim(),
      algo: m[2],
      key: m[3],
      comment: m[4].trim(),
    });
  }
  return out;
}

export interface ProcLink {
  pid: string;
  /** The fd number, or the address range of the mapped region. */
  slot: string;
  target: string;
  deleted: boolean;
  memfd: boolean;
}

/**
 * `ls -l` over /proc/<pid>/fd and /proc/<pid>/map_files — 182,025 lines on a real
 * collection, none of them read before this shape existed.
 *
 * The forensic value is the `(deleted)` marker: a mapping or descriptor whose
 * backing file is gone from disk. That is how a process running a binary it
 * erased after launch stays visible, and `/memfd:` is the fileless equivalent —
 * memfd_create plus fexecve, executing something that was never on disk at all.
 *
 * No finding is raised from here, deliberately. Measured on the reference host:
 * 5,566 deleted mappings, of which 1,144 are Firefox IPC memfds, 1,440 are NSS
 * libraries left mapped by a package upgrade, and 1,008 under /tmp or /dev/shm
 * are Chromium shared memory and POSIX semaphores. A rule firing on any of those
 * would bury the one that matters, which is the mistake this registry already
 * documents for webshell candidates. The rows are labelled and counted; the
 * analyst pivots on them.
 */
export function parseProcLinks(content: string): ProcLink[] {
  const out: ProcLink[] = [];
  const seen = new Set<string>();
  const DELETED = ' (deleted)';
  let headerPid: string | null = null;

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trimEnd();

    // Cat-Scale lists each directory twice, in two `ls -l` forms: once with the
    // full path per entry, once as a "/proc/<pid>/fd:" header followed by bare
    // entry names. Measured on the reference collection: 78,195 entries in the
    // first form, 78,197 in the second, 78,195 common. Reading only one form
    // loses entries; reading both without dedup reports 156,392 mappings for a
    // host that had 78,197. Both are read, and the key is deduplicated.
    //
    // The two entries the second listing alone caught are a process that mapped
    // two io_uring regions between the two runs. A collection is not a perfect
    // point in time, and that difference is evidence, not noise.
    const h = /^(?:\/proc\/(\d+)\/(?:fd|map_files)):$/.exec(line);
    if (h) { headerPid = h[1]; continue; }

    const arrow = line.indexOf(' -> ');
    if (arrow === -1) continue;
    const left = line.slice(0, arrow);

    let pid: string;
    let slot: string;
    // Anchored on the /proc path so a target containing " -> " cannot split the
    // line in the wrong place.
    const full = /\/proc\/(\d+)\/(?:fd|map_files)\/(\S+)$/.exec(left);
    if (full) {
      pid = full[1];
      slot = full[2];
    } else if (headerPid) {
      // Bare entry under a header. A slot is an fd number or an address range,
      // never containing a space, so the last field is the whole name.
      const parts = left.trim().split(/\s+/);
      slot = parts[parts.length - 1];
      if (!slot) continue;
      pid = headerPid;
    } else {
      continue;
    }

    let target = line.slice(arrow + 4);
    const deleted = target.endsWith(DELETED);
    if (deleted) target = target.slice(0, -DELETED.length);

    // Separator written as an escape, not as a literal NUL byte. A raw \0 in the
    // source makes ripgrep and git treat this whole file as binary and skip it —
    // a grep for anything defined here comes back empty, silently. Same value.
    const key = `${pid}\u0000${slot}\u0000${target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ pid, slot, target, deleted, memfd: target.startsWith('/memfd:') });
  }
  return out;
}

export interface KeyValueBlock { label: string; fields: Record<string, string> }

/**
 * Blocks introduced by a header key — "Module: mptcp_diag" then "key: value"
 * lines, as modinfo emits for every kernel module.
 */
export function parseKeyValueBlocks(content: string, blockKey: string): KeyValueBlock[] {
  const out: KeyValueBlock[] = [];
  let current: KeyValueBlock | null = null;
  const head = new RegExp(`^${blockKey}\\s*:\\s*(.+)$`, 'i');

  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const h = head.exec(t);
    if (h) {
      current = { label: h[1].trim(), fields: {} };
      out.push(current);
      continue;
    }
    if (!current) continue; // anything before the first block header is preamble
    const kv = /^([A-Za-z0-9_.\-]+)\s*:\s*(.*)$/.exec(t);
    if (kv) current.fields[normaliseHeader(kv[1])] = kv[2].trim();
  }
  return out;
}

/** "<path>: <description>" — dev-dir-files, the output of `file` over /dev. */
export function parsePathDescription(content: string): { path: string; description: string }[] {
  const out: { path: string; description: string }[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('/')) continue;
    const idx = t.indexOf(':');
    if (idx === -1) continue;
    out.push({ path: t.slice(0, idx).trim(), description: t.slice(idx + 1).trim() });
  }
  return out;
}

// One kilobyte of context is enough to tell a webshell from a toolkit sample;
// beyond that a single file would dominate its row.
const PREVIEW_CAP = 2048;

/**
 * `head` over many files: "==> <path> <==" followed by that file's first bytes.
 * pot-webshell-first-1000 is 208,810 lines but only 1,283 candidates — the
 * content is the evidence, so it is kept as a capped preview rather than dropped.
 */
export function parseHeadMarkers(content: string): { path: string; preview: string }[] {
  const out: { path: string; preview: string }[] = [];
  let current: { path: string; parts: string[] } | null = null;

  const flush = () => {
    if (!current) return;
    out.push({ path: current.path, preview: current.parts.join('\n').trim().slice(0, PREVIEW_CAP) });
  };

  for (const line of content.split('\n')) {
    const m = /^==>\s*(.+?)\s*<==$/.exec(line);
    if (m) {
      flush();
      current = { path: m[1], parts: [] };
      continue;
    }
    if (current && current.parts.join('\n').length < PREVIEW_CAP * 2) current.parts.push(line);
  }
  flush();
  return out;
}


export interface DpkgRow {
  state: string;
  name: string;
  version: string;
  architecture: string;
  description: string;
}

// `dpkg -l`, read as a table rather than as lines.
//
// The file is not a list of installed packages: it is every package dpkg knows about,
// each carrying a two- or three-letter state. That state is the part worth querying —
// `rc` is a package removed with its configuration left in place, `iU` one unpacked
// and never configured, `iF` one whose configuration failed. Read as `text_lines`,
// all of it is a single string and none of it can be filtered on.
//
// Column boundaries come from the `+++-===-===` separator line, never from runs of
// whitespace: descriptions contain multiple spaces and a naive split loses them.
//
// Field names are fixed English keys and are deliberately NOT taken from the header
// row. The reference host answers in French ("Souhait", "Nom", "État"), so keying off
// the header would make the schema depend on the locale of the machine under
// investigation — the evidence would decide the column names.
export function parseDpkgTable(content: string): DpkgRow[] {
  const lines = String(content ?? '').split(/\r?\n/);
  const sepIdx = lines.findIndex(l => /^\+\+\+-=+/.test(l));
  if (sepIdx === -1) return [];

  // Each run of '=' is a column; the leading '+++' is the state column. Offsets
  // advance by the run length plus the single '-' that separates two runs.
  const spans: Array<{ start: number; width: number }> = [];
  let off = 0;
  for (const seg of lines[sepIdx].split('-')) {
    spans.push({ start: off, width: seg.length });
    off += seg.length + 1;
  }
  const keys: Array<keyof DpkgRow> = ['state', 'name', 'version', 'architecture', 'description'];

  const rows: DpkgRow[] = [];
  for (const line of lines.slice(sepIdx + 1)) {
    if (!line.trim()) continue;
    const row = {} as DpkgRow;
    spans.forEach((sp, i) => {
      const key = keys[i];
      if (!key) return;
      // The last column runs to the end of the line: a description is not padded.
      const raw = i === spans.length - 1 ? line.slice(sp.start) : line.substr(sp.start, sp.width);
      row[key] = (raw ?? '').trim();
    });
    if (row.name) rows.push(row);
  }
  return rows;
}

// dpkg's status codes, spelled out. Two letters nobody re-reads at three in the
// morning become a desired state, a current state and an error flag.
const DPKG_DESIRED: Record<string, string> = {
  u: 'unknown', i: 'install', h: 'hold', r: 'remove', p: 'purge',
};
const DPKG_CURRENT: Record<string, string> = {
  n: 'not-installed', i: 'installed', c: 'config-files', U: 'unpacked',
  F: 'half-configured', H: 'half-installed', W: 'triggers-awaiting', t: 'triggers-pending',
};

export interface DpkgState {
  desired: string;
  current: string;
  reinstallRequired: boolean;
  fullyInstalled: boolean;
}

// An unrecognised letter is returned as itself and never reported as fully installed.
// Claiming health from a code we cannot read would be inventing a fact about evidence.
export function dpkgStateMeaning(code: string): DpkgState {
  const c = String(code ?? '');
  const d = c[0] ?? '';
  const s = c[1] ?? '';
  return {
    desired: DPKG_DESIRED[d] ?? d,
    current: DPKG_CURRENT[s] ?? s,
    reinstallRequired: c[2] === 'R',
    fullyInstalled: d === 'i' && s === 'i',
  };
}
