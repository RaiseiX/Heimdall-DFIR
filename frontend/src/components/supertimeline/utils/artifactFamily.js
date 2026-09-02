const FAMILY_BY_SUBTYPE = {
  amcache_files: 'amcache',
  amcache_programs: 'amcache',
  amcache_drivers: 'amcache',
  amcache_driver_packages: 'amcache',
  amcache_pnp: 'amcache',
  amcache_device_containers: 'amcache',
  amcache_shortcuts: 'amcache',
  jumplist_automatic: 'jumplist',
  jumplist_custom: 'jumplist',
};

export function artifactFamily(artifactType) {
  return FAMILY_BY_SUBTYPE[artifactType] || artifactType;
}
