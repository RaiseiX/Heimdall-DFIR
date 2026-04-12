
export const ARTIFACT_COLORS = {
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
  sqle:      'var(--fl-artifact-sqle)',
  wer:       'var(--fl-artifact-wer)',
  catscale:  'var(--fl-artifact-catscale)',

  appcompat: '#f59e0b',
  bits:      '#64748b',
  wxtcmd:    'var(--fl-artifact-wer)',
  sum:       'var(--fl-artifact-sqle)',
  hayabusa:  'var(--fl-danger)',
  network:   '#f0883e',
  dns:       'var(--fl-artifact-shellbags)',
  other:     'var(--fl-dim)',
};

export function artifactColor(type) {
  return ARTIFACT_COLORS[type] || 'var(--fl-dim)';
}

export const PRIORITY_COLORS = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      'var(--fl-ok)',
};

export const SEVERITY_COLORS = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      'var(--fl-ok)',
  info:     'var(--fl-accent)',
};
