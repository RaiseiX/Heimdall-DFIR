import * as Lucide from 'lucide-react';

// Charter icon vocabulary (DesignSystem.html §16): stroke-only, 1.6px, round caps.
// Maps a domain concept to its canonical lucide icon so the whole app stays consistent.
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

// <Icon name="case" /> resolves the charter concept; <Icon name="ChevronLeft" /> accepts
// any lucide name directly. Stroke defaults to the charter's 1.6px.
export default function Icon({ name, size = 14, strokeWidth = 1.6, ...props }) {
  const Cmp = Lucide[ICONS[name] || name] || Lucide.Circle;
  return <Cmp size={size} strokeWidth={strokeWidth} {...props} />;
}
