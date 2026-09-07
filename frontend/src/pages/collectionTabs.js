export const COLLECTION_TAB_GROUPS = [
  {
    id: 'collected',
    tabs: [
      { id: 'evidence', label: 'Evidence' },
      { id: 'coverage', label: 'Coverage' },
      { id: 'logs',     label: 'Logs' },
    ],
  },
  {
    id: 'analysis',
    tabs: [
      { id: 'timeline',   label: 'Super Timeline' },
      { id: 'detections', label: 'Detections' },
      { id: 'iocs',       label: 'IOCs' },
      { id: 'network',    label: 'Network' },
      { id: 'mitre',      label: 'MITRE' },
      { id: 'threathunt', label: 'Threat Hunting' },
      { id: 'hayabusa',   label: 'Hayabusa' },
    ],
  },
  {
    id: 'tools',
    tabs: [
      { id: 'cyberchef', label: 'CyberChef' },
      { id: 'volweb',    label: 'VolWeb' },
      { id: 'audit',     label: 'Audit' },
    ],
  },
];

export const EXTERNAL_TABS = new Set(['volweb']);

export function collectionTabs() {
  return COLLECTION_TAB_GROUPS.flatMap(g => g.tabs);
}
