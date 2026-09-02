import * as Lucide from 'lucide-react';

export const ICONS = {
  shield:    'Shield',
  dashboard: 'LayoutDashboard',
  timeline:  'Activity',
  network:   'Network',
  ioc:       'Crosshair',
  case:      'FolderOpen',
  host:      'Monitor',
  intel:     'Globe',
  rules:     'SlidersHorizontal',
  reports:   'FileText',
  settings:  'Settings',
  search:    'Search',
  bell:      'Bell',
  filter:    'Filter',
  flag:      'Flag',
  link:      'Link',
  upload:    'Upload',
  bolt:      'Zap',
  globe:     'Globe',
  user:      'User',
};

export default function Icon({ name, size = 14, strokeWidth = 1.6, ...props }) {
  const Cmp = Lucide[ICONS[name] || name] || Lucide.Circle;
  return <Cmp size={size} strokeWidth={strokeWidth} {...props} />;
}
