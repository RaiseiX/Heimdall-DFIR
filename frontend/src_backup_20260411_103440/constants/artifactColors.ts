export const ARTIFACT_COLORS: Record<string, string> = {
  evtx:      'var(--fl-artifact-evtx)',
  prefetch:  'var(--fl-artifact-prefetch)',
  mft:       'var(--fl-artifact-mft)',
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
  catscale_auth:        '#f43f5e',
  catscale_logon:       '#22c55e',
  catscale_process:     '#8b72d6',
  catscale_network:     '#4d82c0',
  catscale_history:     '#d97c20',
  catscale_persistence: '#c89d1d',
  catscale_fstimeline:  '#06b6d4',
};

export function artifactColor(type: string): string {
  return ARTIFACT_COLORS[type] || 'var(--fl-dim)';
}

export const HAY_SEVERITY_BG: Record<string, string> = {
  critical: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)',
  high:     'color-mix(in srgb, var(--fl-warn)   8%, transparent)',
  medium:   'color-mix(in srgb, var(--fl-gold)   6%, transparent)',
  low:      'color-mix(in srgb, var(--fl-accent)  4%, transparent)',
};
