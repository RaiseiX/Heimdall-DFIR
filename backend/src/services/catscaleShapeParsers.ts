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

/**
 * `head` dump where each section's body is NUL-separated — process-cmdline and
 * process-environment write `/proc/<pid>/cmdline` with embedded \u0000 between
 * arguments. The raw NUL bytes are split back into readable tokens.
 */
export function parseNulHeadMarkers(content: string, joinWith: string): { path: string; text: string }[] {
  const out: { path: string; text: string }[] = [];
  let current: { path: string; parts: string[] } | null = null;

  const flush = () => {
    if (!current) return;
    // Each block's body may itself be NUL-terminated; the trailing \u0000 yields an
    // empty last token that is dropped here.
    const tokens = current.parts.join('').split('\u0000').map(s => s.trim()).filter(Boolean);
    out.push({ path: current.path, text: tokens.join(joinWith) });
  };

  for (const line of content.split('\n')) {
    const m = /^==>\s*(.+?)\s*<==$/.exec(line);
    if (m) {
      flush();
      current = { path: m[1], parts: [] };
      continue;
    }
    if (current) current.parts.push(line);
  }
  flush();
  return out;
}

/**
 * `ls -l` over /proc/<pid>/fd — "lr-x------ 1 root root 64 Dec 26 10:02
 * /proc/1072/fd/0 -> /dev/null". Deleted-but-open files are the signal: the
 * path ends with " (deleted)" while the process still holds the descriptor.
 */
export function parseFdLinks(content: string): { pid: string; fd: string; target: string; deleted: boolean }[] {
  const out: { pid: string; fd: string; target: string; deleted: boolean }[] = [];
  for (const line of content.split('\n')) {
    const m = /\/proc\/(\d+)\/fd\/(\d+)\s*->\s*(.*)$/.exec(line.trim());
    if (!m) continue;
    const target = m[3].trim();
    out.push({ pid: m[1], fd: m[2], target: target.replace(/\s*\(deleted\)$/, ''), deleted: /\(deleted\)$/.test(target) });
  }
  return out;
}

/**
 * `ls -l` over /proc/<pid>/map_files — "... /proc/1072/map_files/5623...-5623...
 * -> /usr/sbin/cron". The target is the mapped file (binary, library), so this
 * is a per-process list of loaded executables.
 */
export function parseMapFilesLinks(content: string): { pid: string; range: string; target: string; deleted: boolean }[] {
  const out: { pid: string; range: string; target: string; deleted: boolean }[] = [];
  for (const line of content.split('\n')) {
    const m = /\/proc\/(\d+)\/map_files\/([0-9a-f-]+)\s*->\s*(.*)$/.exec(line.trim());
    if (!m) continue;
    const target = m[3].trim();
    out.push({ pid: m[1], range: m[2], target: target.replace(/\s*\(deleted\)$/, ''), deleted: /\(deleted\)$/.test(target) });
  }
  return out;
}

/** `service --status-all`: " [ + ]  apparmor". */
export function parseServiceStatus(content: string): { service: string; state: string }[] {
  const out: { service: string; state: string }[] = [];
  for (const line of content.split('\n')) {
    const m = /^\s*\[\s*([+\-?])\s*\]\s+(\S.*)$/.exec(line.trim());
    if (!m) continue;
    out.push({ service: m[2].trim(), state: m[1] === '+' ? 'running' : (m[1] === '-' ? 'stopped' : 'unknown') });
  }
  return out;
}

/** `mount`: "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)". */
export function parseMountTable(content: string): { device: string; mountpoint: string; fstype: string; options: string }[] {
  const out: { device: string; mountpoint: string; fstype: string; options: string }[] = [];
  for (const line of content.split('\n')) {
    const m = /^\s*(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\(([^)]*)\)/.exec(line);
    if (!m) continue;
    out.push({ device: m[1], mountpoint: m[2], fstype: m[3], options: m[4] });
  }
  return out;
}

/** `dpkg -l` — skip the status-key legend and parse "ii  name version arch desc". */
export function parseDpkgList(content: string): { status: string; name: string; version: string; arch: string; description: string }[] {
  const out: { status: string; name: string; version: string; arch: string; description: string }[] = [];
  const lines = content.split('\n');
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    // Legend lines start with '|' or '+++'; data rows start with a 2-char status
    // like "ii", "rc", "un".
    if (/^\|/.test(t) || /^\++-/.test(t) || /^Desired=/.test(t) || /^\|\/?\s*Name/.test(t)) continue;
    const m = /^([a-z]{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/.exec(t);
    if (!m) continue;
    out.push({ status: m[1], name: m[2], version: m[3], arch: m[4], description: m[5].trim() });
  }
  return out;
}

/** `/proc/meminfo`: "MemTotal: 2011044 kB". */
export function parseKeyValueLines(content: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const line of content.split('\n')) {
    const m = /^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({ key: m[1], value: m[2].trim() });
  }
  return out;
}

/** `lsusb`: "Bus 001 Device 015: ID 0930:6544 Toshiba Corp. ...". */
export function parseLsusb(content: string): { bus: string; device: string; id: string; description: string }[] {
  const out: { bus: string; device: string; id: string; description: string }[] = [];
  for (const line of content.split('\n')) {
    const m = /^Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+(\S+)\s+(.*)$/.exec(line.trim());
    if (!m) continue;
    out.push({ bus: m[1], device: m[2], id: m[3], description: m[4].trim() });
  }
  return out;
}

/** `sudo -V` — "Sudo version 1.9.9" plus a few key: value lines. */
export function parseSudoInfo(content: string): { version: string; options: string }[] {
  const version = /Sudo version\s+([\d.]+)/.exec(content)?.[1] ?? '';
  const options = /Configure options:\s*(.*)$/m.exec(content)?.[1]?.trim() ?? '';
  return [{ version, options }];
}

/** `/proc/modules`: "exfat 86016 1 - Live 0xffffffffc0d9d000". */
export function parseProcModules(content: string): { module: string; size: string; refs: string; state: string; address: string }[] {
  const out: { module: string; size: string; refs: string; state: string; address: string }[] = [];
  for (const line of content.split('\n')) {
    const m = /^\s*(\S+)\s+(\d+)\s+(\d+)\s+([\-\w]+)\s+(.*)$/.exec(line);
    if (!m) continue;
    out.push({ module: m[1], size: m[2], refs: m[3], state: m[4], address: m[5].trim() });
  }
  return out;
}
