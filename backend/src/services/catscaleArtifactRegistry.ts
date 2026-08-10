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
} from './catscaleShapeParsers';

export type Shape =
  | 'hash_list' | 'path_list' | 'header_table' | 'kv_blocks' | 'path_desc' | 'head_markers';

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
    dir: 'Process_and_Network', pattern: 'ssh-folders-list', kind: 'ssh_folder', shape: 'path_list',
    labelOf: r => r.path,
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
    case 'hash_list':    return parseHashList(content);
    case 'path_list':    return parsePathList(content).map(path => ({ path }));
    case 'header_table': return parseHeaderTable(content, spec.columns);
    case 'kv_blocks':    return parseKeyValueBlocks(content, spec.blockKey ?? 'Module')
      .map(b => ({ label: b.label, ...b.fields }));
    case 'path_desc':    return parsePathDescription(content);
    case 'head_markers': return parseHeadMarkers(content);
    default:             return [];
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
