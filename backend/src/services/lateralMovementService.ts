export interface IdentityObservation { identifiers: string[]; }

const isIpLike = (s: string): boolean =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f]*:[0-9a-f:]*$/i.test(s);

export const LATERAL_PORT_PROTOCOL: Record<number, string> = {
  445: 'SMB', 139: 'NetBIOS', 135: 'WMI', 3389: 'RDP',
  5985: 'WINRM', 5986: 'WINRM', 22: 'SSH', 5900: 'VNC',
};

export function networkEventId(port: number): string | null {
  const proto = LATERAL_PORT_PROTOCOL[port];
  return proto ? `NET:${proto}` : null;
}

export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m) {
    const a = Number(m[1]), b = Number(m[2]);
    if (a === 10) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true; // link-local
    if (a === 127) return true;              // loopback
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // ULA fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true; // link-local fe80::/10
  return false;
}

/**
 * Resolves runtime identities from a list of observations.
 *
 * Constraints:
 * - Only identifiers co-occurring within the SAME observation are unioned.
 * - An IP shared across separate observations does NOT bridge two distinct hosts
 *   (NAT/DHCP boundary rule).
 *
 * Returns a map from every observed identifier to its canonical hostId.
 * Canonical preference: hostname over IP; if multiple hostnames, alphabetically first.
 */
export function resolveIdentities(observations: IdentityObservation[]): Map<string, string> {
  // Each observation produces an independent group.
  // Groups are identified by their canonical name (hostname preferred).
  // We do NOT merge groups solely because they share an IP.

  // Step 1: For each observation, collect all its identifiers.
  const groups: { members: string[] }[] = [];

  for (const obs of observations) {
    const ids = obs.identifiers.filter(Boolean);
    if (ids.length === 0) continue;

    groups.push({ members: ids });
  }

  // Step 2: Merge groups that share a non-IP identifier (hostname co-occurrence across events).
  // IP-only bridges are NOT used for merging.
  // We use union-find over group indices.
  const groupParent: number[] = groups.map((_, i) => i);
  const findGroup = (i: number): number => {
    while (groupParent[i] !== i) {
      groupParent[i] = groupParent[groupParent[i]];
      i = groupParent[i];
    }
    return i;
  };
  const unionGroups = (a: number, b: number) => {
    const ra = findGroup(a), rb = findGroup(b);
    if (ra !== rb) groupParent[ra] = rb;
  };

  // Build index: hostname -> first group index that contains it
  const hostnameToGroup = new Map<string, number>();
  for (let i = 0; i < groups.length; i++) {
    for (const id of groups[i].members) {
      if (!isIpLike(id)) {
        if (hostnameToGroup.has(id)) {
          unionGroups(i, hostnameToGroup.get(id)!);
        } else {
          hostnameToGroup.set(id, i);
        }
      }
    }
  }

  // Step 3: Compute canonical per merged group
  const rootToMembers = new Map<number, { hostnames: Set<string>; all: Set<string> }>();
  for (let i = 0; i < groups.length; i++) {
    const root = findGroup(i);
    if (!rootToMembers.has(root)) rootToMembers.set(root, { hostnames: new Set(), all: new Set() });
    const entry = rootToMembers.get(root)!;
    for (const id of groups[i].members) {
      entry.all.add(id);
      if (!isIpLike(id)) entry.hostnames.add(id);
    }
  }

  const rootCanonical = new Map<number, string>();
  for (const [root, { hostnames, all }] of rootToMembers) {
    const sortedHostnames = [...hostnames].sort();
    const sortedAll = [...all].sort();
    rootCanonical.set(root, sortedHostnames.length > 0 ? sortedHostnames[0] : sortedAll[0]);
  }

  // Step 4: Build output map: identifier -> canonical
  const out = new Map<string, string>();
  for (let i = 0; i < groups.length; i++) {
    const root = findGroup(i);
    const canonical = rootCanonical.get(root)!;
    for (const id of groups[i].members) {
      out.set(id, canonical);
    }
  }

  return out;
}

export interface RawLateralRow {
  src: string; dst: string; username: string;
  event_id: string; logon_type: string | null; artifact_type: string;
  event_count: number; first_seen: string; last_seen: string;
}

export interface NetworkConnRow {
  src_ip: string; dst_ip: string; dst_port: number;
  protocol: string | null; packet_count: number | null;
  first_seen: string; last_seen: string;
}

export function mapNetworkRowsToLateral(rows: NetworkConnRow[]): RawLateralRow[] {
  const out: RawLateralRow[] = [];
  for (const r of rows) {
    const eid = networkEventId(r.dst_port);
    if (!eid) continue;
    if (!r.src_ip || !r.dst_ip || r.src_ip === r.dst_ip) continue;
    if (!isPrivateIp(r.src_ip) || !isPrivateIp(r.dst_ip)) continue;
    out.push({
      src: r.src_ip, dst: r.dst_ip, username: '?',
      event_id: eid, logon_type: null, artifact_type: 'network',
      event_count: r.packet_count && r.packet_count > 0 ? r.packet_count : 1,
      first_seen: r.first_seen, last_seen: r.last_seen,
    });
  }
  return out;
}

export interface LateralNode { id: string; total_events: number; as_source: number; as_target: number; score?: number; factors?: string[]; }
export interface LateralEdge {
  source: string; target: string; count: number;
  event_ids: string[]; usernames: string[]; logon_types: string[];
  first_seen: string; last_seen: string;
  origin: 'evtx' | 'network' | 'both';
}

export function buildLateralGraph(
  rows: RawLateralRow[],
  resolve: (id: string) => string,
): { nodes: LateralNode[]; edges: LateralEdge[] } {
  const nodeMap = new Map<string, LateralNode>();
  const addNode = (id: string) => {
    if (!nodeMap.has(id)) nodeMap.set(id, { id, total_events: 0, as_source: 0, as_target: 0 });
    return nodeMap.get(id)!;
  };
  const edgeMap = new Map<string, LateralEdge & { _eids: Set<string>; _users: Set<string>; _ltypes: Set<string>; _origins: Set<string> }>();

  for (const r of rows) {
    const src = resolve(r.src);
    const dst = resolve(r.dst);
    if (src === dst) continue;
    const s = addNode(src), d = addNode(dst);
    s.total_events += r.event_count; s.as_source += r.event_count;
    d.total_events += r.event_count; d.as_target += r.event_count;

    const key = `${src}|||${dst}`;
    if (!edgeMap.has(key)) {
      edgeMap.set(key, {
        source: src, target: dst, count: 0,
        event_ids: [], usernames: [], logon_types: [],
        first_seen: r.first_seen, last_seen: r.last_seen,
        origin: 'evtx',
        _eids: new Set(), _users: new Set(), _ltypes: new Set(), _origins: new Set(),
      });
    }
    const e = edgeMap.get(key)!;
    e.count += r.event_count;
    e._origins.add(r.artifact_type === 'network' ? 'network' : 'evtx');
    e._eids.add(r.event_id);
    if (r.username && r.username !== '?') e._users.add(r.username);
    if (r.logon_type) e._ltypes.add(r.logon_type);
    if (r.first_seen < e.first_seen) e.first_seen = r.first_seen;
    if (r.last_seen > e.last_seen) e.last_seen = r.last_seen;
  }

  const edges: LateralEdge[] = [...edgeMap.values()].map((e) => ({
    source: e.source, target: e.target, count: e.count,
    event_ids: [...e._eids], usernames: [...e._users], logon_types: [...e._ltypes],
    first_seen: e.first_seen, last_seen: e.last_seen,
    origin: e._origins.has('network') && e._origins.has('evtx')
      ? 'both'
      : (e._origins.has('network') ? 'network' : 'evtx'),
  }));
  return { nodes: [...nodeMap.values()], edges };
}

export const DEFAULT_CHAIN_WINDOW_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_MAX_CHAIN_DEPTH = 10;   // max nodes in a single chain
export const DEFAULT_MAX_CHAINS = 1000;       // cap on total emitted chains (bounds combinatorial blowup)

export interface LateralChain {
  path: string[];        // nodes in order, entry point first
  timestamps: string[];  // hop times; timestamps[i] = time of the hop path[i] -> path[i+1]; length = path.length - 1
  entryPoint: string;
}

export function analyzeChains(
  edges: LateralEdge[],
  opts: { windowMs?: number; maxDepth?: number; maxChains?: number } = {},
): LateralChain[] {
  const windowMs = opts.windowMs ?? DEFAULT_CHAIN_WINDOW_MS;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_CHAIN_DEPTH;
  const maxChains = opts.maxChains ?? DEFAULT_MAX_CHAINS;
  const t = (s: string) => new Date(s).getTime();

  const outgoing = new Map<string, LateralEdge[]>();
  const targets = new Set<string>();
  for (const e of edges) {
    if (!outgoing.has(e.source)) outgoing.set(e.source, []);
    outgoing.get(e.source)!.push(e);
    targets.add(e.target);
  }
  const entryPoints = [...new Set(edges.map((e) => e.source))].filter((s) => !targets.has(s));

  // Only MAXIMAL chains are emitted (a chain that cannot be extended further). Sub-chains
  // are intentionally not emitted to bound output size; intermediate nodes still appear in
  // the path. A visited set keeps every path simple (no repeated node), which terminates on
  // cycles; maxDepth and maxChains bound combinatorial blow-up on dense graphs.
  const chains: LateralChain[] = [];
  const walk = (
    node: string, lastTs: number, path: string[], times: string[],
    entry: string, visited: Set<string>,
  ) => {
    if (chains.length >= maxChains) return;
    const nexts = path.length >= maxDepth ? [] : (outgoing.get(node) ?? []).filter((e) => {
      const et = t(e.first_seen);
      return et >= lastTs && et - lastTs <= windowMs && !visited.has(e.target);
    });
    if (nexts.length === 0) {
      if (path.length >= 2) chains.push({ path: [...path], timestamps: [...times], entryPoint: entry });
      return;
    }
    for (const e of nexts) {
      visited.add(e.target);
      walk(e.target, t(e.first_seen), [...path, e.target], [...times, e.first_seen], entry, visited);
      visited.delete(e.target);
      if (chains.length >= maxChains) return;
    }
  };

  for (const ep of entryPoints) {
    for (const e of outgoing.get(ep) ?? []) {
      if (chains.length >= maxChains) break;
      walk(e.target, t(e.first_seen), [ep, e.target], [e.first_seen], ep, new Set([ep, e.target]));
    }
  }
  return chains;
}

export const DEFAULT_EDGE_CAP = 800;
export interface LateralIndicator { host_name: string | null; description: string; mitre_technique_id: string | null; }

const PIVOT_RE = /psexec|mstsc|\bwmi\b|pass-the|remote service|lateral\s*move/i;
const MITRE_LATERAL_RE = /^T1021|^T1047|^T1550|^T1570/i;
const INTERACTIVE_LOGON = new Set(['9', '10']); // 9 = explicit creds, 10 = RDP

export function scoreLateralNodes(
  nodes: LateralNode[], edges: LateralEdge[],
  indicators: LateralIndicator[], chains: LateralChain[],
  iocHosts: Set<string>,
): LateralNode[] {
  const outByHost = new Map<string, LateralEdge[]>();
  for (const e of edges) {
    if (!outByHost.has(e.source)) outByHost.set(e.source, []);
    outByHost.get(e.source)!.push(e);
  }
  const pivotHosts = new Set(
    indicators.filter((i) => i.host_name && (
      PIVOT_RE.test(i.description) || MITRE_LATERAL_RE.test(i.mitre_technique_id ?? '')
    )).map((i) => i.host_name as string),
  );
  const chainMid = new Set<string>();
  for (const c of chains) for (let i = 1; i < c.path.length - 1; i++) chainMid.add(c.path[i]);

  return nodes.map((n) => {
    const factors: string[] = [];
    let score = 0;
    const ratio = n.total_events ? n.as_source / n.total_events : 0;
    if (ratio >= 0.65 && n.total_events >= 5) { score += 40; factors.push('Pivot source structurel'); }
    else if (n.total_events >= 5) { score += 15; factors.push('Activité notable'); }

    const myEdges = outByHost.get(n.id) ?? [];
    if (myEdges.some((e) => e.logon_types.some((l) => INTERACTIVE_LOGON.has(String(l))))) {
      score += 15; factors.push('Logon interactif (RDP/explicit)');
    }
    if (pivotHosts.has(n.id)) { score += 25; factors.push('Outil de pivot détecté (PsExec/mstsc/WMI)'); }
    if (iocHosts.has(n.id)) { score += 25; factors.push('Recouvrement IOC'); }
    if (chainMid.has(n.id)) { score += 10; factors.push('Pivot intermédiaire dans une chaîne'); }

    return { ...n, score: Math.min(100, score), factors };
  });
}

export function selectSignalAwareEdges(
  edges: LateralEdge[], highSignalHosts: Set<string>, cap: number = DEFAULT_EDGE_CAP,
): LateralEdge[] {
  const isHigh = (e: LateralEdge) => highSignalHosts.has(e.source) || highSignalHosts.has(e.target);
  const high = edges.filter(isHigh).sort((a, b) => b.count - a.count);
  const rest = edges.filter((e) => !isHigh(e)).sort((a, b) => b.count - a.count);
  return [...high, ...rest].slice(0, cap);
}

export interface LateralResult {
  nodes: LateralNode[]; edges: LateralEdge[]; chains: LateralChain[];
  total_events: number; indicators: LateralIndicator[];
}

export function buildLateralMovement(input: {
  rows: RawLateralRow[];
  observations: IdentityObservation[];
  indicators: LateralIndicator[];
  iocHosts: Set<string>;
  chainWindowMs?: number;
  edgeCap?: number;
}): LateralResult {
  const aliasMap = resolveIdentities(input.observations);
  const resolve = (id: string) => aliasMap.get(id) ?? id;

  const { nodes, edges } = buildLateralGraph(input.rows, resolve);

  const highSignal = new Set<string>([
    ...input.indicators.map((i) => i.host_name).filter(Boolean) as string[],
    ...input.iocHosts,
  ].map(resolve));
  const sampledEdges = selectSignalAwareEdges(edges, highSignal, input.edgeCap);

  const chains = analyzeChains(sampledEdges, { windowMs: input.chainWindowMs });
  const scoredNodes = scoreLateralNodes(nodes, sampledEdges, input.indicators, chains, input.iocHosts);

  return {
    nodes: scoredNodes,
    edges: sampledEdges,
    chains,
    total_events: input.rows.reduce((s, r) => s + r.event_count, 0),
    indicators: input.indicators,
  };
}
