// Declarative registry of the CatScale artifacts that take a generic shape.
//
// Adding an artifact is a row here, not a module: folder, file pattern, the shape
// it takes, how a parsed row becomes a state entry, and — optionally — when it
// deserves to surface as a finding. The bespoke parsers (docker inspect, dpkg
// --verify, /proc/<pid>/exe) stay in catscaleStateParsers; everything whose
// format repeats lives here.
import type { StateRow } from './catscaleStateStore';
import {
  parseHashList, parsePathList, parseHeaderTable,
  parseKeyValueBlocks, parsePathDescription, parseHeadMarkers,
  parseNulHeadMarkers, parseFdLinks, parseMapFilesLinks, parseServiceStatus,
  parseMountTable, parseDpkgList, parseKeyValueLines, parseLsusb, parseProcModules,
  parseSudoInfo,
} from './catscaleShapeParsers';

export type Shape =
  | 'hash_list' | 'path_list' | 'header_table' | 'kv_blocks' | 'path_desc' | 'head_markers'
  | 'nul_head' | 'fd_links' | 'map_links' | 'service_status' | 'mount_table'
  | 'dpkg_list' | 'kv_lines' | 'lsusb' | 'proc_modules' | 'sudo_info';

export interface SpecFinding {
  kind: string;
  description: string;
  path: string | null;
  raw: Record<string, unknown>;
}

export interface ArtifactSpec {
  /** CatScale folder the artifact lives in. */
  dir: string;
  /** Artifact name as it appears in `<host>-<DTG>-<pattern>.<ext>`. */
  pattern: string;
  /** catscale_state.kind written for every row. */
  kind: string;
  shape: Shape;
  /** kv_blocks only: the key that introduces a block. */
  blockKey?: string;
  /** header_table only: explicit column names, for tables whose header is not
   *  reliably splittable (lsof separates two headers with a single space). */
  columns?: string[];
  labelOf: (row: any) => string;
  findingOf?: (row: any) => Omit<SpecFinding, 'raw'> | null;
}

export interface AppliedSpec { stateRows: StateRow[]; findings: SpecFinding[] }

// Anywhere a non-root user can write. A setuid binary here is the textbook
// privilege-escalation primitive; one in /usr/bin is the operating system.
const WRITABLE_PREFIXES = ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/', '/home/', '/srv/upload'];

// Directories a web server actually serves from.
const WEB_ROOT_RE = /^\/(var\/www|srv\/(www|http)|usr\/share\/(nginx|apache2)|opt\/lampp\/htdocs|home\/[^/]+\/public_html)(\/|$)/;

// Container image layers. A webshell sample here is almost always a tool baked
// into an image, not something dropped on the host: measured on a real host,
// 1,283 candidates were nearly all a pentest toolkit inside a container image.
const IMAGE_STORAGE_RE = /\/(containers\/storage|var\/lib\/docker|var\/lib\/containerd)\/|\/overlay2?\//;

export const ARTIFACT_REGISTRY: ArtifactSpec[] = [
  // ── Misc ────────────────────────────────────────────────────────────────
  {
    dir: 'Misc', pattern: 'exec-perm-files', kind: 'executable_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Misc', pattern: 'Setuid-Setguid-tools', kind: 'setuid_binary', shape: 'path_list',
    labelOf: r => r.path,
    // Measured on a real host: 69 of 229 setuid binaries sat under a writable
    // prefix, and 49 of those were inside container image storage — content of an
    // image, not a privilege-escalation primitive on the host.
    findingOf: r => (WRITABLE_PREFIXES.some(p => String(r.path).startsWith(p))
      && !IMAGE_STORAGE_RE.test(String(r.path))
      ? { kind: 'setuid_in_writable_path', path: r.path, description: `Setuid/setgid binary in a user-writable location: ${r.path}` }
      : null),
  },
  {
    dir: 'Misc', pattern: 'pot-webshell-first-1000', kind: 'webshell_candidate', shape: 'head_markers',
    labelOf: r => r.path,
    findingOf: r => (WEB_ROOT_RE.test(String(r.path)) && !IMAGE_STORAGE_RE.test(String(r.path))
      ? { kind: 'webshell_candidate', path: r.path, description: `Possible webshell under a web root: ${r.path}` }
      : null),
  },
  {
    dir: 'Misc', pattern: 'pot-webshell-hashes', kind: 'webshell_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Misc', pattern: 'dev-dir-files', kind: 'dev_file', shape: 'path_desc',
    labelOf: r => r.path,
    findingOf: r => (/\bELF\b/.test(String(r.description))
      ? { kind: 'executable_in_dev', path: r.path, description: `Executable in /dev: ${r.path} (${r.description})` }
      : null),
  },
  {
    dir: 'Misc', pattern: 'dev-dir-files-hashes', kind: 'dev_file_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },

  // ── System_Info ─────────────────────────────────────────────────────────
  {
    dir: 'System_Info', pattern: 'lsmod', kind: 'loaded_module', shape: 'header_table',
    labelOf: r => r.module ?? '',
  },
  {
    dir: 'System_Info', pattern: 'modinfo', kind: 'module_info', shape: 'kv_blocks', blockKey: 'Module',
    labelOf: r => r.label ?? '',
  },
  {
    dir: 'System_Info', pattern: 'procmod', kind: 'proc_module', shape: 'proc_modules',
    labelOf: r => r.module ?? '',
  },
  {
    dir: 'System_Info', pattern: 'meminfo', kind: 'memory_info', shape: 'kv_lines',
    labelOf: r => r.key ?? '',
  },
  {
    dir: 'System_Info', pattern: 'cpuinfo', kind: 'cpu_core', shape: 'kv_blocks', blockKey: 'processor',
    labelOf: r => r.label ?? '',
  },
  {
    dir: 'System_Info', pattern: 'lsusb', kind: 'usb_device', shape: 'lsusb',
    labelOf: r => r.id ?? '',
  },
  {
    dir: 'System_Info', pattern: 'sudo', kind: 'sudo_version', shape: 'sudo_info',
    labelOf: r => r.version ?? '',
  },
  {
    dir: 'System_Info', pattern: 'df', kind: 'disk_usage', shape: 'header_table',
    labelOf: r => r.filesystem ?? '',
  },
  {
    dir: 'System_Info', pattern: 'mount', kind: 'mount_point', shape: 'mount_table',
    labelOf: r => r.mountpoint ?? '',
    findingOf: r => (r.fstype === 'cifs' || r.fstype === 'nfs' || /\/\d{1,3}(\.\d{1,3}){3}/.test(String(r.device))
      ? { kind: 'remote_mount', path: r.mountpoint, description: `Remote filesystem mounted: ${r.device} on ${r.mountpoint} (${r.fstype})` }
      : null),
  },
  {
    dir: 'System_Info', pattern: 'deb-packages', kind: 'installed_package', shape: 'dpkg_list',
    labelOf: r => r.name ?? '',
  },
  {
    dir: 'System_Info', pattern: 'etc-key-files-list', kind: 'etc_key_file', shape: 'path_list',
    labelOf: r => r.path,
  },
  {
    dir: 'System_Info', pattern: 'etc-modified-files-list', kind: 'etc_modified_file', shape: 'path_list',
    labelOf: r => r.path,
    // A freshly added unit under /etc/systemd/system is the standard persistence
    // spot; flag it so it surfaces without opening the file browser.
    findingOf: r => (/^\/etc\/systemd\/system\/[^\/]+\.service$/.test(String(r.path))
      ? { kind: 'systemd_unit_modified', path: String(r.path), description: `Systemd unit in /etc/systemd/system: ${r.path}` }
      : null),
  },

  // ── Logs ────────────────────────────────────────────────────────────────
  {
    dir: 'Logs', pattern: 'who', kind: 'logged_on_user', shape: 'header_table',
    labelOf: r => Object.values(r)[0] as string ?? '',
  },
  {
    dir: 'Logs', pattern: 'whoandwhat', kind: 'active_session', shape: 'header_table',
    labelOf: r => Object.values(r)[0] as string ?? '',
  },
  {
    dir: 'Logs', pattern: 'lastlog', kind: 'last_login', shape: 'header_table',
    labelOf: r => Object.values(r)[0] as string ?? '',
  },
  {
    dir: 'Logs', pattern: 'var-log-list', kind: 'var_log_file', shape: 'path_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Logs', pattern: 'var-crash-list', kind: 'crash_file', shape: 'path_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Logs', pattern: 'hidden-user-home-dir-list', kind: 'user_home_file', shape: 'path_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Persistence', pattern: 'service_status', kind: 'service_status', shape: 'service_status',
    labelOf: r => r.service ?? '',
  },
  {
    dir: 'Persistence', pattern: 'cron-folder-list', kind: 'cron_spool_file', shape: 'path_list',
    labelOf: r => r.path,
  },

  // ── Process_and_Network ─────────────────────────────────────────────────
  {
    dir: 'Process_and_Network', pattern: 'lsof-list-open-files', kind: 'open_file', shape: 'header_table',
    columns: ['command', 'pid', 'tid', 'taskcmd', 'ppid', 'user', 'fd', 'type', 'device', 'size_off', 'node', 'name'],
    labelOf: r => r.name ?? '',
  },
  {
    dir: 'Process_and_Network', pattern: 'processhashes', kind: 'process_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-cmdline', kind: 'process_cmdline', shape: 'nul_head',
    // The command line is the content worth searching; the path only names the PID.
    labelOf: r => r.text?.substring(0, 200) ?? r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-environment', kind: 'process_environment', shape: 'nul_head',
    labelOf: r => r.text?.substring(0, 200) ?? r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-fd-links', kind: 'process_fd', shape: 'fd_links',
    labelOf: r => r.target,
    // A descriptor still open on a deleted file is an implant signature: the
    // process ran from (or wrote to) something that has since been removed.
    findingOf: r => (r.deleted
      ? { kind: 'open_deleted_file', path: r.target, description: `Process ${r.pid} holds a deleted file open: ${r.target}` }
      : null),
  },
  {
    dir: 'Process_and_Network', pattern: 'process-map_files-links', kind: 'process_mapped_file', shape: 'map_links',
    labelOf: r => r.target,
    // A mapped executable that is not on disk anymore = an unlinked binary that
    // is still running. Same signal as fd-links but for the executable itself.
    findingOf: r => (r.deleted
      ? { kind: 'unlinked_running_binary', path: r.target, description: `Process ${r.pid} maps a deleted binary: ${r.target}` }
      : null),
  },
  {
    dir: 'Process_and_Network', pattern: 'process-map_files-link-hashes', kind: 'process_mapped_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'ssh-folders-list', kind: 'ssh_folder', shape: 'path_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-details', kind: 'process_detail', shape: 'kv_blocks', blockKey: 'Name',
    labelOf: r => r.label,
  },

  // ── Collection itself ────────────────────────────────────────────────────
  {
    dir: '.', pattern: 'console-error-log', kind: 'console_error', shape: 'kv_lines',
    labelOf: r => r.key ?? '',
  },

  // ── Podman — the CLI is Docker-compatible, so the shapes are the same ────
  {
    dir: 'Podman', pattern: 'podman-container-ls-all-size', kind: 'podman_container', shape: 'header_table',
    labelOf: r => r.names ?? r.container_id ?? '',
  },
  {
    dir: 'Podman', pattern: 'podman-image-ls-all', kind: 'podman_image', shape: 'header_table',
    labelOf: r => r.repository ?? r.image_id ?? '',
  },
];

function shapeRows(spec: ArtifactSpec, content: string): any[] {
  switch (spec.shape) {
    case 'hash_list':      return parseHashList(content);
    case 'path_list':      return parsePathList(content).map(path => ({ path }));
    case 'header_table':   return parseHeaderTable(content, spec.columns);
    case 'kv_blocks':      return parseKeyValueBlocks(content, spec.blockKey ?? 'Module')
      .map(b => ({ label: b.label, ...b.fields }));
    case 'path_desc':      return parsePathDescription(content);
    case 'head_markers':   return parseHeadMarkers(content);
    case 'nul_head':       return parseNulHeadMarkers(content, ' ');
    case 'fd_links':       return parseFdLinks(content);
    case 'map_links':      return parseMapFilesLinks(content);
    case 'service_status': return parseServiceStatus(content);
    case 'mount_table':    return parseMountTable(content);
    case 'dpkg_list':      return parseDpkgList(content);
    case 'kv_lines':       return parseKeyValueLines(content);
    case 'lsusb':          return parseLsusb(content);
    case 'proc_modules':   return parseProcModules(content);
    case 'sudo_info':      return parseSudoInfo(content);
    default:               return [];
  }
}

export function applySpec(spec: ArtifactSpec, content: string, sourceFile: string): AppliedSpec {
  const stateRows: StateRow[] = [];
  const findings: SpecFinding[] = [];

  for (const row of shapeRows(spec, content)) {
    const label = String(spec.labelOf(row) ?? '');
    // A row whose label is empty carries no key an analyst can search on; it is
    // still recorded, keyed by nothing rather than dropped.
    stateRows.push({ kind: spec.kind, label, source_file: sourceFile, raw: { ...row } });
    const f = spec.findingOf?.(row);
    if (f) findings.push({ ...f, raw: { ...row } });
  }
  return { stateRows, findings };
}
