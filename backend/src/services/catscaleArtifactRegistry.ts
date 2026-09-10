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
  parseKeyValueBlocks, parsePathDescription, parseHeadMarkers, parseProcLinks,
  parseKeyValueLines, parseTextLines, parseJsonDoc,
  parseDpkgTable, dpkgStateMeaning,
} from './catscaleShapeParsers';
import { dmesgStamp, containerLogStamp } from './catscaleEventTime';

export type Shape =
  | 'hash_list' | 'path_list' | 'header_table' | 'kv_blocks' | 'path_desc' | 'head_markers'
  | 'proc_link' | 'kv_lines' | 'text_lines' | 'json_doc' | 'dpkg_table';

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
  /** Reads the event's own wall-clock time out of a parsed row, when the artifact
   *  records one. Absent means the artifact is inventory: it describes an object
   *  that exists, not something that happened at a moment. */
  eventTimeOf?: (row: any, ctx: SpecContext) => string | null;
  /** Declared, not returned, so the projection's purge can enumerate every
   *  timestamp_kind this registry can write. A purge that only knew 'inventory'
   *  would leave dated rows behind and double them on the next backfill. */
  eventTimeKind?: string;
}

/** Collection-wide facts a spec may need. `hostOffset` comes from the
 *  `host-date-timezone` artifact: `dmesg -T` renders local wall-clock time with no
 *  offset, so defaulting to UTC would shift every event on a European host by two
 *  hours — a plausible-looking timeline that is wrong everywhere. */
export interface SpecContext { hostOffset: string | null }

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

// An unpacked forensic collection: a full filesystem copy of another machine,
// usually sitting in an analyst's home directory. Matched on the collector
// layouts this product ingests — CatScale writes `catscale_out/`, CyLR and
// Magnet RESPONSE write a `filesystem/` root — plus the naming an analyst
// gives the archive they expanded.
//
// Deliberately narrow, and never a silent exclusion: a directory can be named
// to look like a collection. Findings under it are labelled, counted, and left
// on screen for the analyst to judge.
const EXTRACTED_COLLECTION_RE =
  /\/(catscale_out|uploads\/collections)\/|\/filesystem\/(usr|etc|var|bin|sbin|opt|root|home)\/|[-_](collecte|collection)\//i;

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
    //
    // A third class showed up on 2026-08-13, and it is the normal case on a DFIR
    // workstation: all 20 findings on that host pointed inside
    // /home/<user>/Téléchargements/srv-vpn01-collecte/filesystem/, an unpacked
    // collection of ANOTHER machine. Every setuid binary of that machine sits
    // under /home/, outside image storage, and fires the rule correctly while
    // saying nothing true about the host being examined.
    //
    // These are classified rather than dropped. Silently discarding a path is how
    // an attacker who plants a payload under an overlay/ or a directory named
    // like a collection disappears from the screen — the analyst must see the
    // count and the reason, then decide.
    findingOf: r => {
      const p = String(r.path);
      if (!WRITABLE_PREFIXES.some(w => p.startsWith(w))) return null;
      if (IMAGE_STORAGE_RE.test(p)) {
        return { kind: 'setuid_in_container_image', path: r.path,
          description: `Setuid/setgid binary inside container image storage, not on the host filesystem: ${r.path}` };
      }
      if (EXTRACTED_COLLECTION_RE.test(p)) {
        return { kind: 'setuid_in_extracted_collection', path: r.path,
          description: `Setuid/setgid binary inside an unpacked forensic collection — evidence of another host, not this one: ${r.path}` };
      }
      return { kind: 'setuid_in_writable_path', path: r.path,
        description: `Setuid/setgid binary in a user-writable location: ${r.path}` };
    },
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
  // The /proc inventory: 280,000 lines that no parser read until 2026-08-14. A
  // process holding or executing a file that no longer exists on disk becomes
  // visible only here.
  {
    dir: 'Process_and_Network', pattern: 'process-map_files-links',
    kind: 'proc_mapped_file', shape: 'proc_link',
    labelOf: r => r.target,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-map_files-link-hashes',
    kind: 'proc_mapped_file_hash', shape: 'hash_list',
    labelOf: r => r.path,
  },
  {
    dir: 'Process_and_Network', pattern: 'process-fd-links',
    kind: 'proc_open_fd', shape: 'proc_link',
    labelOf: r => r.target,
  },
  {
    // /proc/<pid>/status, one block per process, keyed by its Name line.
    dir: 'Process_and_Network', pattern: 'process-details',
    kind: 'proc_status', shape: 'kv_blocks', blockKey: 'Name',
    labelOf: r => r.label,
  },
  {
    // `head` over /proc/<pid>/cmdline: the full argument vector, which the ps
    // listing truncates.
    dir: 'Process_and_Network', pattern: 'process-cmdline',
    kind: 'proc_cmdline', shape: 'head_markers',
    labelOf: r => r.path,
  },
  {
    // /proc/<pid>/environ. LD_PRELOAD and LD_LIBRARY_PATH live here, and they are
    // among the quietest persistence mechanisms on Linux.
    dir: 'Process_and_Network', pattern: 'process-environment',
    kind: 'proc_environment', shape: 'head_markers',
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
  // ── The remainder of the collection ─────────────────────────────────────
  // Every file below produced nothing before 2026-08-17. Where the format carries
  // structure worth extracting it gets a shape; where it does not yet, `text_lines`
  // records the content line by line rather than letting the file read as empty.
  // "No parser written for this shape" must never present itself as "no data".
  { dir: 'Docker', pattern: 'docker-container-logs', kind: 'docker_container_log', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200),
    eventTimeKind: 'container_log',
    eventTimeOf: (r, ctx) => containerLogStamp(String(r.text), ctx.hostOffset) },
  { dir: 'Docker', pattern: 'docker-network-inspect', kind: 'docker_network', shape: 'json_doc',
    labelOf: r => String(r.Name ?? r.Id ?? '') },
  { dir: 'Docker', pattern: 'docker-info', kind: 'docker_info', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'Docker', pattern: 'docker-version', kind: 'docker_version', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'Docker', pattern: 'docker-image-ls-all', kind: 'docker_image', shape: 'header_table',
    labelOf: r => r.image ?? r.id ?? '' },
  { dir: 'Docker', pattern: 'docker-container-ls-all-size', kind: 'docker_container_size', shape: 'header_table',
    labelOf: r => r.names ?? r.container_id ?? '' },

  { dir: 'Podman', pattern: 'podman-info', kind: 'podman_info', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'Podman', pattern: 'podman-version', kind: 'podman_version', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'Podman', pattern: 'podman-network-inspect', kind: 'podman_network', shape: 'json_doc',
    labelOf: r => String(r.Name ?? r.Id ?? '') },

  { dir: 'System_Info', pattern: 'release', kind: 'os_release', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'System_Info', pattern: 'cpuinfo', kind: 'cpu_info', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'System_Info', pattern: 'meminfo', kind: 'mem_info', shape: 'kv_lines',
    labelOf: r => r.key },
  { dir: 'System_Info', pattern: 'df', kind: 'filesystem_usage', shape: 'header_table',
    labelOf: r => Object.values(r)[0] ?? '' },
  { dir: 'System_Info', pattern: 'mount', kind: 'mount_point', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'lsusb', kind: 'usb_device', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  // The only registry artifact that dates every one of its own lines. Kept as
  // `text_lines` so nothing is dropped: the bracket stays whole in `raw.text`,
  // while the label shows the message alone and the time becomes a real column.
  { dir: 'System_Info', pattern: 'dmesg', kind: 'kernel_message', shape: 'text_lines',
    labelOf: r => dmesgStamp(String(r.text), null).text.slice(0, 200),
    eventTimeKind: 'dmesg',
    eventTimeOf: (r, ctx) => dmesgStamp(String(r.text), ctx.hostOffset).time },
  { dir: 'System_Info', pattern: 'sudo', kind: 'sudo_config', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  // Structured since 2026-08-18. As `text_lines` this produced 2,670 rows for 2,665
  // packages — the five header lines of `dpkg -l` counted as packages — and the state
  // code was buried in a string nobody could filter on.
  //
  // No findingOf, deliberately. `rc` is what `apt remove` leaves behind by default and
  // a healthy Debian host has dozens; a rule firing on it would bury the states that
  // matter. The state is recorded and queryable, which is what an investigation needs
  // — the decision of what is abnormal here belongs to the analyst, not the parser.
  { dir: 'System_Info', pattern: 'deb-packages', kind: 'installed_package', shape: 'dpkg_table',
    labelOf: r => (r.fullyInstalled
      ? `${r.name} ${r.version}`
      : `${r.name} ${r.version} [${r.state}]`).slice(0, 200) },
  { dir: 'System_Info', pattern: 'procmod', kind: 'proc_module', shape: 'text_lines',
    labelOf: r => String(r.text).split(/\s+/)[0] ?? '' },
  { dir: 'System_Info', pattern: 'host-date-timezone', kind: 'host_time', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'etc-key-files-list', kind: 'etc_key_file', shape: 'path_list',
    labelOf: r => r.path },
  { dir: 'System_Info', pattern: 'etc-modified-files-list', kind: 'etc_modified_file', shape: 'path_list',
    labelOf: r => r.path },

  // Failed authentications. Empty here ("has no entries"), and that emptiness is
  // itself an observation about an exposed host — it must be recorded, not absent.
  { dir: 'Logs', pattern: 'last-btmp', kind: 'failed_login', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Logs', pattern: 'var-log-list', kind: 'var_log_file', shape: 'path_list',
    labelOf: r => r.path },

  // Systemd unit definitions, concatenated. The timeline parser reads this file
  // for its unit list and produced nothing from it; `text_lines` keeps the whole
  // definition — an ExecStart pointing somewhere unexpected is the finding, and it
  // only exists in the body.
  { dir: 'Persistence', pattern: 'persistence-systemdlist', kind: 'systemd_unit_definition', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Persistence', pattern: 'cron-tab-list', kind: 'crontab_entry', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Persistence', pattern: 'cron-folder-list', kind: 'cron_folder_file', shape: 'path_list',
    labelOf: r => r.path },
  { dir: 'Persistence', pattern: 'service_status', kind: 'service_status', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },

  { dir: 'User_Files', pattern: 'hidden-user-home-dir-list', kind: 'hidden_home_file', shape: 'path_list',
    labelOf: r => r.path },

  // Written at the collection root, not in a folder. '.' rather than '' so the
  // "every entry declares a folder" invariant keeps its teeth; path.join
  // normalises it away.
  { dir: '.', pattern: 'console-error-log', kind: 'collector_error', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },

  // ── Couverture du catalogue complet, 2026-09-09 ────────────────────────────
  // Le support etait en forme de Debian + Docker : 34 des 121 artefacts du
  // catalogue Cat-Scale n'etaient reconnus par aucun motif. Un hote RHEL perdait
  // son inventaire logiciel, un hyperviseur tout son parc invite.
  //
  // `text_lines` partout ou le format n'a pas pu etre echantillonne : il conserve
  // chaque ligne non vide, la ou `kv_lines` et `header_table` jettent en silence
  // ce qu'ils ne savent pas decouper. Une forme structuree se substituera au cas
  // par cas sur un echantillon reel, jamais sur une supposition.
  { dir: 'Process_and_Network', pattern: 'ifconfig', kind: 'network_interface', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Process_and_Network', pattern: 'selinux', kind: 'selinux_status', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Process_and_Network', pattern: 'getsebool', kind: 'selinux_boolean', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Logs', pattern: 'last-utmpdump', kind: 'logon', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Logs', pattern: 'passwd-check', kind: 'passwd_check', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Logs', pattern: 'last-btmpx', kind: 'failed_login_btmpx', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Logs', pattern: 'var-crash-list', kind: 'var_crash_file', shape: 'path_list',
    labelOf: r => r.path },
  { dir: 'Logs', pattern: 'var-adm-list', kind: 'var_adm_file', shape: 'path_list',
    labelOf: r => r.path },
  { dir: 'System_Info', pattern: 'rpm-packages', kind: 'rpm_package', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'zypper-packages', kind: 'zypper_package', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'solaris-packages', kind: 'solaris_package', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'solaris-package-verify', kind: 'package_verify', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'ProcMemUsage', kind: 'proc_mem_usage', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'SharedMemAndSemaphores', kind: 'shared_memory', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'removeblemedia', kind: 'removable_media', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'System_Info', pattern: 'modules', kind: 'kernel_module', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Podman', pattern: 'podman-container-logs', kind: 'podman_container_log', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200),
    eventTimeKind: 'container_log',
    eventTimeOf: (r, ctx) => containerLogStamp(String(r.text), ctx.hostOffset) },
  { dir: 'Virsh', pattern: 'virsh-list-all', kind: 'virsh_domain', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-domifaddr', kind: 'virsh_domain_interface', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-dominfo', kind: 'virsh_domain_info', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-dommemstat', kind: 'virsh_domain_memory', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-snapshot-list', kind: 'virsh_snapshot', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-vcpuinfo', kind: 'virsh_vcpu', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-net-list-all', kind: 'virsh_network', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-net-info', kind: 'virsh_network_info', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-net-dhcp-leases', kind: 'virsh_dhcp_lease', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-nodeinfo', kind: 'virsh_node_info', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virsh-pool-list-all', kind: 'virsh_storage_pool', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
  { dir: 'Virsh', pattern: 'virt-top-n-1', kind: 'virsh_top', shape: 'text_lines',
    labelOf: r => String(r.text).slice(0, 200) },
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
    case 'proc_link':    return parseProcLinks(content);
    case 'kv_lines':     return parseKeyValueLines(content);
    case 'text_lines':   return parseTextLines(content);
    // The decoded state travels into `raw` alongside the literal code, so the GIN
    // index on catscale_state.raw can answer "which packages were removed but kept
    // their configuration" (raw->>'current' = 'config-files') without re-parsing.
    case 'dpkg_table':   return parseDpkgTable(content)
                                  .map(r => ({ ...r, ...dpkgStateMeaning(r.state) }));
    case 'json_doc':     return parseJsonDoc(content);
    default:             return [];
  }
}

export function applySpec(
  spec: ArtifactSpec,
  content: string,
  sourceFile: string,
  ctx: SpecContext = { hostOffset: null },
): AppliedSpec {
  const stateRows: StateRow[] = [];
  const findings: SpecFinding[] = [];

  for (const row of shapeRows(spec, content)) {
    const label = String(spec.labelOf(row) ?? '');
    // A row whose label is empty carries no key an analyst can search on; it is
    // still recorded, keyed by nothing rather than dropped.
    const at = spec.eventTimeOf?.(row, ctx) ?? null;
    stateRows.push({
      kind: spec.kind,
      label,
      source_file: sourceFile,
      raw: { ...row },
      event_time: at,
      event_time_kind: at ? (spec.eventTimeKind ?? null) : null,
    });
    const f = spec.findingOf?.(row);
    if (f) findings.push({ ...f, raw: { ...row } });
  }
  return { stateRows, findings };
}

/** Every timestamp_kind the inventory projection can write, so its purge covers
 *  what it produced rather than only the undated majority. */
export const PROJECTED_TIMESTAMP_KINDS: string[] = [
  'inventory',
  ...Array.from(new Set(ARTIFACT_REGISTRY.map(s => s.eventTimeKind).filter(Boolean) as string[])),
];
