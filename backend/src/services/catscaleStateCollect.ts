// Routes a CatScale collection's state artifacts into two shapes:
//   - stateRows    → catscale_state, the point-in-time inventory
//   - timelineRows → collection_timeline, only for things that really happened
//                    at a known time
//
// Kept out of catscaleService.ts, which is already long, and kept free of any
// database call so the routing decisions are testable on their own.
import * as fs from 'fs';
import * as path from 'path';
import { findArtifactFiles, type CatScaleFailure } from './catscaleFiles';
import type { StateRow } from './catscaleStateStore';
import {
  parseDockerInspect, parseDockerTop, parseDockerDiff, parseDockerPorts,
  parsePackageVerify, parseModuleHashes, parseProcExeLinks,
} from './catscaleStateParsers';
import { ARTIFACT_REGISTRY, applySpec, type SpecContext } from './catscaleArtifactRegistry';
import { hostUtcOffset } from './catscaleEventTime';
import {
  parseIpAddr, parseRouteTable, parseIptables, parsePasswdCheck,
} from './catscaleNetworkParsers';
import { buildSourcePath } from './catscaleSourcePath';

export interface TimelineRow {
  case_id: string;
  timestamp: Date;
  artifact_type: string;
  /** NOT NULL in collection_timeline — always set it, never leave it undefined. */
  artifact_name: string;
  source: string;
  description: string;
  raw: Record<string, unknown>;
  host_name?: string | null;
  process_name?: string | null;
  timestamp_kind?: string | null;
  path?: string | null;
}

export interface StateCollectResult {
  stateRows: StateRow[];
  timelineRows: TimelineRow[];
}

// Locations no package manager installs executables into. A binary unlinked from
// one of these while still running is an implant indicator; one unlinked from
// /usr/share is an application that updated itself mid-run, which happens
// constantly on a desktop and drowns the signal if treated the same way.
const SUSPICIOUS_EXEC_PATHS = [
  '/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/', '/dev/',
];

// Hidden directories that exist on essentially every Linux install. Treating
// these as suspicious flags Discord and VS Code instead of implants: measured on
// a real collection, /home/<user>/.config/discord/.../chrome_crashpad_handler was
// the only false positive left after path filtering.
const STANDARD_HIDDEN_DIRS = new Set([
  '.config', '.cache', '.local', '.ssh', '.gnupg', '.mozilla', '.thunderbird',
  '.npm', '.nvm', '.cargo', '.rustup', '.pyenv', '.rbenv', '.gem', '.m2',
  '.gradle', '.docker', '.kube', '.aws', '.azure', '.var', '.steam', '.wine',
  '.java', '.vscode', '.vscode-server', '.git', '.dotnet', '.nuget', '.yarn',
]);

function isSuspiciousExecPath(p: string | null): boolean {
  if (!p) return false;
  if (SUSPICIOUS_EXEC_PATHS.some(prefix => p.startsWith(prefix))) return true;
  // A hidden directory anywhere in the path — /home/user/.x/payload — but not the
  // standard ones, which carry no signal on their own.
  return p.split('/').slice(0, -1).some(
    seg => seg.startsWith('.') && seg.length > 1 && !STANDARD_HIDDEN_DIRS.has(seg));
}

// Paths a running image has no business writing to.
//
// Measured on a real host, a first attempt that covered all of /etc and /root
// produced 13 findings and 13 false positives: nginx writing conf.d, traefik
// writing traefik.yml, minio creating its cert directory. Containers are *meant*
// to write their configuration at startup. The signal is narrower — an
// executable, an account database, or a persistence mechanism.
const CONTAINER_SENSITIVE_RE = new RegExp([
  // executables and libraries
  '^/(usr/)?(bin|sbin)(/|$)',
  '^/usr/local/(bin|sbin)(/|$)',
  '^/(lib|lib64|usr/lib|usr/lib64|boot)(/|$)',
  // account and authentication databases
  '^/etc/(passwd|shadow|group|gshadow|sudoers)(\\.|$|/)',
  '^/etc/ssh(/|$)',
  '^/(root|home/[^/]+)/\\.ssh(/|$)',
  // persistence
  '^/etc/(cron[^/]*|init\\.d|rc[0-9S]?\\.d|systemd)(/|$)',
  '^/var/spool/cron(/|$)',
  '^/etc/ld\\.so\\.(preload|conf)',
].join('|'));

// docker-inspect-<id>.txt / docker-top-<id>.txt — recover the id from the name so
// per-container rows stay correlatable even when the file content is unusable.
function containerIdFromName(base: string, kind: string): string {
  const m = new RegExp(`-${kind}-([0-9a-f]+)\\.`).exec(base);
  return m ? m[1] : '';
}

function readText(fp: string, failures?: CatScaleFailure[]): string | null {
  try {
    return fs.readFileSync(fp, 'utf8');
  } catch (e: any) {
    failures?.push({ stage: 'parse', target: fp, reason: e?.message ?? String(e) });
    return null;
  }
}

export function collectStateArtifacts(
  catscaleRoot: string,
  caseId: string,
  hostName: string,
  collectedAt: Date,
  /** The `<host>-<DTG>-` prefix for this collection, from outfilePrefix — passed
   *  in rather than recomputed, so the caller's already-resolved hostname/time
   *  stay the single source of truth. See catscaleSourcePath.ts. */
  prefix: string,
  failures?: CatScaleFailure[],
): StateCollectResult {
  const stateRows: StateRow[] = [];
  const timelineRows: TimelineRow[] = [];

  const dockerDir = path.join(catscaleRoot, 'Docker');
  const podmanDir = path.join(catscaleRoot, 'Podman');
  const sysDir = path.join(catscaleRoot, 'System_Info');
  const procDir = path.join(catscaleRoot, 'Process_and_Network');

  // Canonical path for every artifact this function reads — same rule as the
  // timeline parsers in catscaleService.ts: no category, no bare basename may
  // reach source_file (or, via timelineRow/finding below, collection_timeline.source).
  const srcOf = (p: string) => buildSourcePath(catscaleRoot, p, prefix);

  const timelineRow = (
    timestamp: Date, kind: string, description: string,
    c: { name: string; container_id: string }, source: string, raw: Record<string, unknown>,
  ): TimelineRow => ({
    case_id: caseId,
    timestamp,
    artifact_type: 'catscale_docker',
    artifact_name: 'Docker Container Lifecycle',
    source,
    description,
    raw,
    host_name: hostName,
    process_name: c.name || c.container_id,
    timestamp_kind: kind,
  });

  // State carries no timestamp of its own, so a finding derived from it is dated
  // at the collection time. Only findings are promoted — never the inventory, or
  // the timeline would gain 438 /proc rows and 525k lsof rows per collection.
  const FINDING_NAMES: Record<string, string> = {
    catscale_docker: 'Docker Container Finding',
    catscale_package: 'Package Integrity Finding',
    catscale_kernel_module: 'Kernel Module Finding',
    catscale_proc_exe: 'Process Executable Finding',
  };

  const finding = (
    kind: string, artifactType: string, description: string,
    p: string | null, source: string, raw: Record<string, unknown>,
  ): TimelineRow => ({
    case_id: caseId,
    timestamp: collectedAt,
    artifact_type: artifactType,
    artifact_name: FINDING_NAMES[artifactType] ?? 'CatScale Finding',
    source,
    description,
    raw,
    host_name: hostName,
    timestamp_kind: kind,
    path: p,
  });

  // Podman implemente la meme interface que Docker : memes formats de sortie,
  // seuls le dossier et le nom des fichiers changent. Deux moteurs, un seul
  // corps de code — une regle recopiee en deux exemplaires n'est pas une regle.
  const CONTAINER_ENGINES = [
    { dir: dockerDir, kind: 'docker', artifact: 'catscale_docker',
      inspect: 'docker-inspect', top: 'docker-top',
      diff: 'docker-container-diff', port: 'docker-container-port' },
    { dir: podmanDir, kind: 'podman', artifact: 'catscale_podman',
      inspect: 'podman-inspect', top: 'podman-container-top',
      diff: 'podman-container-diff', port: 'podman-container-port' },
  ];

  for (const engine of CONTAINER_ENGINES) {
    // ── Docker containers ─────────────────────────────────────────────────────
    for (const fp of findArtifactFiles(engine.dir, engine.inspect)) {
      const sourcePath = srcOf(fp);
      const content = readText(fp, failures);
      if (content === null) continue;
      const c = parseDockerInspect(content);
      if (!c) {
        failures?.push({ stage: 'parse', target: fp, reason: `${engine.kind} inspect JSON unreadable` });
        continue;
      }

      stateRows.push({
        kind: `${engine.kind}_container`,
        label: c.name || c.container_id,
        source_file: sourcePath,
        raw: {
          container_id: c.container_id, full_id: c.full_id, name: c.name, image: c.image,
          status: c.status, pid: c.pid, command: c.command, privileged: c.privileged,
          cap_add: c.cap_add, network_mode: c.network_mode, env: c.env,
          mounts: c.mounts, suspicious_mounts: c.suspicious_mounts,
          created_at: c.created_at?.toISOString() ?? null,
          started_at: c.started_at?.toISOString() ?? null,
          finished_at: c.finished_at?.toISOString() ?? null,
        },
      });

      const common = {
        container_id: c.container_id, name: c.name, image: c.image, status: c.status,
        pid: c.pid, privileged: c.privileged, suspicious_mounts: c.suspicious_mounts,
        command: c.command,
      };
      if (c.created_at) {
        timelineRows.push(timelineRow(c.created_at, 'container_created',
          `Container created: ${c.name || c.container_id} (${c.image})`, c, sourcePath, common));
      }
      if (c.started_at) {
        timelineRows.push(timelineRow(c.started_at, 'container_started',
          `Container started: ${c.name || c.container_id} (${c.image})`, c, sourcePath, common));
      }
      // Docker keeps the previous exit time in FinishedAt across a restart, so a
      // running container carries a stop timestamp that never applied to this run.
      if (c.finished_at && c.status !== 'running') {
        timelineRows.push(timelineRow(c.finished_at, 'container_stopped',
          `Container stopped: ${c.name || c.container_id} (${c.image})`, c, sourcePath, common));
      }

      // A privileged container shares the host's kernel capabilities: escaping it
      // is close to trivial, so its mere existence is worth an analyst's attention.
      if (c.privileged) {
        timelineRows.push(finding('container_privileged', engine.artifact,
          `Container running privileged: ${c.name || c.container_id} (${c.image})`,
          null, sourcePath, common));
      }
      // A bind onto the host root or the Docker socket gives the container a route
      // back out — the canonical container escape.
      for (const m of c.suspicious_mounts) {
        timelineRows.push(finding('container_escape_mount', engine.artifact,
          `Container ${c.name || c.container_id} binds host path ${m}`,
          m, sourcePath, { ...common, mount: m }));
      }
    }

    // ── Processes inside each container ───────────────────────────────────────
    for (const fp of findArtifactFiles(engine.dir, engine.top)) {
      const base = path.basename(fp);
      const sourcePath = srcOf(fp);
      const content = readText(fp, failures);
      if (content === null) continue;
      const containerId = containerIdFromName(base, engine.top);
      for (const p of parseDockerTop(content)) {
        stateRows.push({
          kind: `${engine.kind}_process`, label: p.cmd.slice(0, 512), source_file: sourcePath,
          raw: { ...p, container_id: containerId },
        });
      }
    }

    // ── What each container wrote at runtime ──────────────────────────────────
    // `docker diff` is the reason the filesystem timeline can skip /var/lib/docker
    // entirely: it carries the same evidence in three orders of magnitude fewer rows.
    for (const fp of findArtifactFiles(engine.dir, engine.diff)) {
      const base = path.basename(fp);
      const sourcePath = srcOf(fp);
      const content = readText(fp, failures);
      if (content === null) continue;
      const containerId = containerIdFromName(base, engine.diff);
      for (const d of parseDockerDiff(content)) {
        stateRows.push({
          kind: `${engine.kind}_diff`, label: d.path, source_file: sourcePath,
          raw: { ...d, container_id: containerId },
        });
        // A deletion inside a container is anti-forensic by nature; an addition or
        // change only matters when it lands somewhere a running image should not
        // be writing. Runtime caches under /tmp are the normal case and would bury
        // the signal if treated the same way.
        const sensitive = CONTAINER_SENSITIVE_RE.test(d.path);
        if (d.change === 'deleted' || sensitive) {
          timelineRows.push(finding('container_file_change', engine.artifact,
            `Container ${containerId}: ${d.change} ${d.path}`, d.path, sourcePath,
            { ...d, container_id: containerId }));
        }
      }
    }

    // ── Published ports ───────────────────────────────────────────────────────
    for (const fp of findArtifactFiles(engine.dir, engine.port)) {
      const base = path.basename(fp);
      const sourcePath = srcOf(fp);
      const content = readText(fp, failures);
      if (content === null) continue;
      const containerId = containerIdFromName(base, engine.port);
      // Docker publishes each port twice, once per address family. One exposure,
      // one finding — an analyst should not read 0.0.0.0:443 and :::443 as two.
      const reported = new Set<string>();
      for (const p of parseDockerPorts(content)) {
        stateRows.push({
          kind: `${engine.kind}_port`, label: `${p.host_ip}:${p.host_port}`, source_file: sourcePath,
          raw: { ...p, container_id: containerId },
        });
        const key = `${p.container_port}/${p.protocol}->${p.host_port}`;
        if (p.world_exposed && !reported.has(key)) {
          reported.add(key);
          timelineRows.push(finding('container_port_exposed', engine.artifact,
            `Container ${containerId} publishes ${p.container_port}/${p.protocol} on port ${p.host_port} — reachable from every interface`,
            null, sourcePath, { ...p, container_id: containerId }));
        }
      }
    }
  }


  // ── Package integrity ─────────────────────────────────────────────────────
  for (const fp of findArtifactFiles(sysDir, 'deb-package-verify', 'rpm-package-verify')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const e of parsePackageVerify(content)) {
      stateRows.push({ kind: 'package_verify', label: e.path, source_file: sourcePath, raw: { ...e } });
      // An md5 mismatch means the file on disk differs from what the package
      // shipped. Conffiles are excluded: local edits to /etc are the normal case
      // and would bury the one binary that was actually replaced.
      if (e.md5_mismatch && !e.is_conffile) {
        timelineRows.push(finding('package_tampered', 'catscale_package',
          `Package file altered since install: ${e.path}`, e.path, sourcePath, { ...e }));
      }
    }
  }

  // ── Kernel modules ────────────────────────────────────────────────────────
  for (const fp of findArtifactFiles(sysDir, 'module-sha1')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const m of parseModuleHashes(content)) {
      stateRows.push({ kind: 'kernel_module', label: m.module, source_file: sourcePath, raw: { ...m } });
      // Kernel modules live under /lib/modules. One loaded from anywhere else is
      // not something a distribution does.
      if (m.outside_lib_modules) {
        timelineRows.push(finding('module_outside_lib', 'catscale_kernel_module',
          `Kernel module outside /lib/modules: ${m.path}`, m.path, sourcePath, { ...m }));
      }
    }
  }

  // ── /proc/<pid>/exe ───────────────────────────────────────────────────────
  for (const fp of findArtifactFiles(procDir, 'process-exe-links')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const l of parseProcExeLinks(content)) {
      const suspicious = l.deleted && isSuspiciousExecPath(l.exe);
      stateRows.push({
        kind: 'proc_exe',
        label: l.exe ?? `pid:${l.pid}`,
        source_file: sourcePath,
        raw: { ...l, suspicious_path: suspicious },
      });
      // "Deleted binary still running" alone is not a finding: on a real host it
      // fires 18 times for VS Code and Discord updating themselves in place. The
      // finding is a deleted binary in a path no package installs to.
      if (suspicious) {
        timelineRows.push(finding('deleted_binary_running', 'catscale_proc_exe',
          `Running process ${l.pid} executes deleted binary from ${l.exe}`,
          l.exe, sourcePath, { ...l, suspicious_path: true }));
      }
    }
  }

  // ── Network configuration and account check ───────────────────────────────
  // Singular formats, so they stay hand-written rather than bent into a shape.
  for (const fp of findArtifactFiles(procDir, 'ip-a')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const iface of parseIpAddr(content)) {
      stateRows.push({ kind: 'net_interface', label: iface.name, source_file: sourcePath, raw: { ...iface } });
      // PROMISC means the interface accepts frames not addressed to it — a packet
      // capture, which on a server is worth knowing about.
      if (iface.promiscuous) {
        timelineRows.push(finding('interface_promiscuous', 'catscale_network_config',
          `Interface ${iface.name} is in promiscuous mode — traffic capture possible`,
          null, sourcePath, { ...iface }));
      }
    }
  }

  for (const fp of findArtifactFiles(procDir, 'routetable')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const r of parseRouteTable(content)) {
      stateRows.push({ kind: 'route', label: r.destination, source_file: sourcePath, raw: { ...r } });
    }
  }

  for (const fp of findArtifactFiles(procDir, 'iptables-numerical', 'iptables')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const c of parseIptables(content)) {
      stateRows.push({ kind: 'firewall_chain', label: c.chain, source_file: sourcePath, raw: { ...c } });
    }
  }

  for (const fp of findArtifactFiles(path.join(catscaleRoot, 'Logs'), 'passwd-check')) {
    const sourcePath = srcOf(fp);
    const content = readText(fp, failures);
    if (content === null) continue;
    for (const e of parsePasswdCheck(content)) {
      stateRows.push({ kind: 'passwd_check', label: e.user, source_file: sourcePath, raw: { ...e } });
    }
  }

  // ── Everything whose format repeats, driven by the registry ───────────────
  // Twenty-odd artifacts across six shapes. Adding one is a registry row, not a
  // module — which is what keeps the remaining families tractable.
  // Read once, before any spec runs. `dmesg -T` writes local wall-clock time with
  // no offset; Cat-Scale collects `host-date-timezone` precisely so the offset need
  // not be guessed. On the reference host it reads `+00:00` — assuming UTC happened
  // to be right there, and would have been two hours wrong on a Paris host.
  const tzFiles = findArtifactFiles(path.join(catscaleRoot, 'System_Info'), 'host-date-timezone');
  const tzContent = tzFiles.length ? readText(tzFiles[0], failures) : null;
  const ctx: SpecContext = { hostOffset: tzContent ? hostUtcOffset(tzContent) : null };

  for (const spec of ARTIFACT_REGISTRY) {
    for (const fp of findArtifactFiles(path.join(catscaleRoot, spec.dir), spec.pattern)) {
      const sourcePath = srcOf(fp);
      const content = readText(fp, failures);
      if (content === null) continue;
      const applied = applySpec(spec, content, sourcePath, ctx);
      // Not `push(...rows)`: spreading passes every element as an argument, and
      // the engine caps that around 65k. lsof alone carries 525,000 rows.
      for (const row of applied.stateRows) stateRows.push(row);
      for (const f of applied.findings) {
        timelineRows.push(finding(f.kind, `catscale_${spec.kind}`, f.description, f.path, sourcePath, f.raw));
      }
    }
  }

  return { stateRows, timelineRows };
}
