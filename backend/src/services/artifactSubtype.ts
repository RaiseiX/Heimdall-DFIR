import path from 'path';

const CSV_SUBTYPES: Record<string, Record<string, string>> = {
  amcache: {
    unassociatedfileentries: 'amcache_files',
    associatedfileentries: 'amcache_files',
    programentries: 'amcache_programs',
    drivebinaries: 'amcache_drivers',
    driverpackages: 'amcache_driver_packages',
    devicepnps: 'amcache_pnp',
    devicecontainers: 'amcache_device_containers',
    shortcuts: 'amcache_shortcuts',
  },
  jumplist: {
    automaticdestinations: 'jumplist_automatic',
    customdestinations: 'jumplist_custom',
  },
};

export function resolveArtifactType(parser: string, csvFileName: unknown): string {
  const table = CSV_SUBTYPES[parser];
  if (!table || typeof csvFileName !== 'string') return parser;
  const stem = path.basename(csvFileName).replace(/\.csv$/i, '').toLowerCase();
  const token = stem.split('_').pop() ?? '';
  return table[token] ?? parser;
}

export function baseArtifactType(artifactType: string): string {
  for (const [parser, table] of Object.entries(CSV_SUBTYPES)) {
    if (Object.values(table).includes(artifactType)) return parser;
  }
  return artifactType;
}

export function subtypesOf(parser: string): string[] {
  const table = CSV_SUBTYPES[parser];
  if (!table) return [];
  return [...new Set(Object.values(table))].sort();
}
