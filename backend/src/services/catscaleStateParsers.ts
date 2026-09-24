// Parsers for the CatScale artifacts that carry host *state* rather than events.
//
// Every format here was read off a real collection before being implemented —
// docker inspect really is JSON, deb-package-verify really is dpkg --verify
// output, process-exe-links really is `ls -l` over /proc/<pid>/exe. None of it
// is inferred from the collector script.

export interface DockerContainer {
  container_id: string;
  full_id: string;
  name: string;
  image: string;
  status: string;
  pid: number | null;
  command: string;
  created_at: Date | null;
  started_at: Date | null;
  finished_at: Date | null;
  privileged: boolean;
  cap_add: string[];
  network_mode: string;
  env: string[];
  mounts: { type: string; source: string; destination: string; rw: boolean }[];
  suspicious_mounts: string[];
}

// Docker writes the zero time for a container that never stopped. Date parses it
// to year 1, which would anchor the event at the far left of every timeline.
const DOCKER_ZERO_TIME = '0001-01-01T00:00:00Z';

function dockerDate(value: unknown): Date | null {
  if (typeof value !== 'string' || !value || value === DOCKER_ZERO_TIME) return null;
  const d = new Date(value);
  if (isNaN(d.getTime()) || d.getUTCFullYear() < 1980) return null;
  return d;
}

// Host paths that give a container a route back onto the host filesystem or the
// Docker control plane. A bind of any of these is worth surfacing on its own.
const ESCAPE_MOUNTS = ['/', '/etc', '/root', '/var/run/docker.sock', '/run/docker.sock', '/proc', '/sys'];

export function parseDockerInspect(content: string): DockerContainer | null {
  let parsed: any;
  try { parsed = JSON.parse(content); } catch { return null; }
  const c = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!c || typeof c !== 'object' || !c.Id) return null;

  const mounts = Array.isArray(c.Mounts) ? c.Mounts.map((m: any) => ({
    type: String(m?.Type ?? ''),
    source: String(m?.Source ?? ''),
    destination: String(m?.Destination ?? ''),
    rw: Boolean(m?.RW),
  })) : [];

  const args = Array.isArray(c.Args) ? c.Args.map(String) : [];

  return {
    container_id: String(c.Id).slice(0, 12),
    full_id: String(c.Id),
    name: String(c.Name ?? '').replace(/^\//, ''),
    image: String(c.Config?.Image ?? ''),
    status: String(c.State?.Status ?? ''),
    pid: typeof c.State?.Pid === 'number' && c.State.Pid > 0 ? c.State.Pid : null,
    command: [String(c.Path ?? ''), ...args].filter(Boolean).join(' '),
    created_at: dockerDate(c.Created),
    started_at: dockerDate(c.State?.StartedAt),
    finished_at: dockerDate(c.State?.FinishedAt),
    privileged: Boolean(c.HostConfig?.Privileged),
    cap_add: Array.isArray(c.HostConfig?.CapAdd) ? c.HostConfig.CapAdd.map(String) : [],
    network_mode: String(c.HostConfig?.NetworkMode ?? ''),
    env: Array.isArray(c.Config?.Env) ? c.Config.Env.map(String) : [],
    mounts,
    suspicious_mounts: mounts.filter((m: { source: string }) => ESCAPE_MOUNTS.includes(m.source))
      .map((m: { source: string }) => m.source),
  };
}

export interface DockerProcess {
  uid: string; pid: number; ppid: number; stime: string; tty: string; time: string; cmd: string;
}

// `docker top` output: UID PID PPID C STIME TTY TIME CMD, space-aligned, with the
// command as the last field — it contains spaces, so split on the first 7 columns
// only.
export function parseDockerTop(content: string): DockerProcess[] {
  const out: DockerProcess[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('UID')) continue;
    const m = /^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/.exec(t);
    if (!m) continue;
    out.push({
      uid: m[1], pid: Number(m[2]), ppid: Number(m[3]),
      stime: m[5], tty: m[6], time: m[7], cmd: m[8].trim(),
    });
  }
  return out;
}

export interface DockerDiffEntry { change: 'added' | 'changed' | 'deleted'; path: string }

const DIFF_KIND: Record<string, DockerDiffEntry['change']> = { A: 'added', C: 'changed', D: 'deleted' };

// `docker diff` — everything the container's writable layer holds that its image
// does not. This is the forensically meaningful slice of a container filesystem:
// on a real host the whole overlay tree was 3.28M paths, while the diffs of all
// 15 containers came to 612 lines for the same signal.
export function parseDockerDiff(content: string): DockerDiffEntry[] {
  const out: DockerDiffEntry[] = [];
  for (const line of content.split('\n')) {
    const m = /^([ACD])\s+(\/\S.*)$/.exec(line.trim());
    if (!m) continue;
    out.push({ change: DIFF_KIND[m[1]], path: m[2].trim() });
  }
  return out;
}

export interface DockerPortEntry {
  container_port: number; protocol: string;
  host_ip: string; host_port: number; world_exposed: boolean;
}

// `docker port` — "9000/tcp -> 0.0.0.0:9000", IPv6 as "[::]:9000".
// A bind on 0.0.0.0 or :: reaches every interface; 127.0.0.1 does not leave the
// host. The difference decides whether a container service was reachable.
export function parseDockerPorts(content: string): DockerPortEntry[] {
  const out: DockerPortEntry[] = [];
  for (const line of content.split('\n')) {
    const m = /^(\d+)\/(\w+)\s*->\s*(\[[^\]]+\]|[^:]+):(\d+)$/.exec(line.trim());
    if (!m) continue;
    const hostIp = m[3].replace(/^\[|\]$/g, '');
    out.push({
      container_port: Number(m[1]),
      protocol: m[2],
      host_ip: hostIp,
      host_port: Number(m[4]),
      world_exposed: hostIp === '0.0.0.0' || hostIp === '::',
    });
  }
  return out;
}

export interface PackageVerifyEntry {
  path: string; flags: string; md5_mismatch: boolean; is_conffile: boolean; missing: boolean;
}

// `dpkg --verify` output: a 9-character attribute mask, an optional file-type
// letter, then the path. Position 3 of the mask is '5' when the file's MD5 no
// longer matches the package manifest — i.e. the file changed since install.
// 'c' marks a conffile, where local edits are expected and usually benign.
export function parsePackageVerify(content: string): PackageVerifyEntry[] {
  const out: PackageVerifyEntry[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const m = /^(\S+)\s+(?:([a-z])\s+)?(\/\S.*)$/.exec(t);
    if (!m) continue;
    const flags = m[1];
    out.push({
      path: m[3].trim(),
      flags,
      md5_mismatch: flags[2] === '5',
      is_conffile: m[2] === 'c',
      missing: flags.toLowerCase() === 'missing',
    });
  }
  return out;
}

export interface ModuleHash {
  sha1: string; path: string; module: string; outside_lib_modules: boolean;
}

// `sha1sum` over the kernel module tree: "<sha1>  <path>".
export function parseModuleHashes(content: string): ModuleHash[] {
  const out: ModuleHash[] = [];
  for (const line of content.split('\n')) {
    const m = /^([0-9a-f]{40})\s+(\/\S.*)$/.exec(line.trim());
    if (!m) continue;
    const p = m[2].trim();
    // strip .ko, .ko.xz, .ko.gz, .ko.zst
    const module = (p.split('/').pop() || '').replace(/\.ko(\.(xz|gz|zst))?$/, '');
    out.push({
      sha1: m[1],
      path: p,
      module,
      outside_lib_modules: !p.startsWith('/lib/modules/') && !p.startsWith('/usr/lib/modules/'),
    });
  }
  return out;
}

export interface ProcExeLink {
  pid: number; exe: string | null; deleted: boolean; unreadable: boolean;
}

// `ls -l /proc/<pid>/exe`. Two cases matter beyond the happy path:
//   "-> /path (deleted)"  the binary was unlinked but the process still runs
//   no "-> target" at all  the link could not be read (permissions, or the
//                          process exited between the find and the ls)
// Dropping the second case would silently shrink the process inventory, so it is
// recorded as unreadable instead.
export function parseProcExeLinks(content: string): ProcExeLink[] {
  const out: ProcExeLink[] = [];
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const pidMatch = /\/proc\/(\d+)\/exe/.exec(t);
    if (!pidMatch) continue;
    const pid = Number(pidMatch[1]);
    const arrow = t.indexOf('-> ');
    if (arrow === -1) {
      out.push({ pid, exe: null, deleted: false, unreadable: true });
      continue;
    }
    let target = t.slice(arrow + 3).trim();
    const deleted = target.endsWith(' (deleted)');
    if (deleted) target = target.slice(0, -' (deleted)'.length).trim();
    out.push({ pid, exe: target || null, deleted, unreadable: false });
  }
  return out;
}
