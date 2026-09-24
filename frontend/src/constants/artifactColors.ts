export const ARTIFACT_COLORS: Record<string, string> = {
  evtx:      'var(--fl-artifact-evtx)',
  prefetch:  'var(--fl-artifact-prefetch)',
  mft:       'var(--fl-artifact-mft)',
  usn:       'var(--fl-artifact-mft)',
  indx:      'var(--fl-artifact-mft)',
  userassist:'var(--fl-artifact-registry)',
  netprofile:'var(--fl-artifact-registry)',
  usb:       'var(--fl-artifact-recycle)',
  schtasks:  'var(--fl-artifact-registry)',
  pwsh:      'var(--fl-artifact-evtx)',
  dns:       'var(--fl-artifact-srum)',
  webcache:  'var(--fl-artifact-sqle)',
  wmi:       'var(--fl-artifact-registry)',
  lnk:       'var(--fl-artifact-lnk)',
  registry:  'var(--fl-artifact-registry)',
  amcache:   'var(--fl-artifact-amcache)',
  shellbags: 'var(--fl-artifact-shellbags)',
  jumplist:  'var(--fl-artifact-jumplist)',
  srum:      'var(--fl-artifact-srum)',
  recycle:   'var(--fl-artifact-recycle)',
  wxtcmd:    'var(--fl-artifact-wer)',
  sum:       'var(--fl-artifact-sqle)',
  appcompat: 'var(--fl-artifact-appcompat)',
  bits:      'var(--fl-artifact-bits)',
  hayabusa:  'var(--fl-danger)',
  sqle:      'var(--fl-artifact-sqle)',
};

export const ARTIFACT_FAMILY: Record<string, string> = {
  account:     'var(--fl-artifact-srum)',
  network:     'var(--fl-artifact-sqle)',
  persistence: 'var(--fl-artifact-lnk)',
  system:      'var(--fl-artifact-registry)',
  package:     'var(--fl-artifact-amcache)',
  container:   'var(--fl-artifact-shellbags)',
  process:     'var(--fl-artifact-jumplist)',
  files:       'var(--fl-artifact-bits)',
};

const FAMILY_PREFIXES: Array<[string, readonly string[]]> = [
  ['process',     ['catscale_proc', 'catscale_process']],
  ['container',   ['catscale_docker', 'catscale_podman']],
  ['package',     ['catscale_package', 'catscale_installed', 'catscale_deb']],
  ['network',     ['catscale_net', 'catscale_network', 'catscale_route', 'catscale_firewall', 'catscale_ssh']],
  ['account',     ['catscale_auth', 'catscale_logon', 'catscale_logged', 'catscale_passwd',
                   'catscale_failed', 'catscale_active_session', 'catscale_sudo', 'catscale_history']],
  ['persistence', ['catscale_persistence', 'catscale_cron', 'catscale_crontab', 'catscale_systemd',
                   'catscale_service', 'catscale_setuid', 'catscale_webshell']],
  ['system',      ['catscale_kernel', 'catscale_module', 'catscale_loaded', 'catscale_mem',
                   'catscale_cpu', 'catscale_os', 'catscale_host', 'catscale_mount',
                   'catscale_usb', 'catscale_filesystem', 'catscale_collector']],
  ['files',       ['catscale_open_file', 'catscale_executable', 'catscale_fstimeline', 'catscale_etc',
                   'catscale_hidden', 'catscale_dev_file', 'catscale_var_log', 'catscale_user_file']],
];

export const FAMILY_ORDER: readonly string[] = FAMILY_PREFIXES.map(([family]) => family);

export function artifactFamily(type?: string): string | null {
  const t = String(type ?? '');
  if (!t.startsWith('catscale_')) return null;
  for (const [family, prefixes] of FAMILY_PREFIXES) {
    if (prefixes.some(p => t.startsWith(p))) return family;
  }
  return null;
}

export function artifactColor(type: string): string {
  const direct = ARTIFACT_COLORS[type];
  if (direct) return direct;
  const family = artifactFamily(type);
  return family ? ARTIFACT_FAMILY[family] : 'var(--fl-dim)';
}

export const HAY_SEVERITY_BG: Record<string, string> = {
  critical: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)',
  high:     'color-mix(in srgb, var(--fl-warn)   8%, transparent)',
  medium:   'color-mix(in srgb, var(--fl-gold)   6%, transparent)',
  low:      'color-mix(in srgb, var(--fl-accent)  4%, transparent)',
};
