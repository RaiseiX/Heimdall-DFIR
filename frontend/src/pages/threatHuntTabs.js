export const THREAT_HUNT_TABS = ['yara-scan', 'sigma-rules', 'sigma-hunt', 'sysmon', 'run-all'];

export const DEFAULT_THREAT_HUNT_TAB = 'yara-scan';

export const MOVED_TABS = { 'yara-rules': DEFAULT_THREAT_HUNT_TAB };

export function resolveThreatHuntTab(tab) {
  if (typeof tab !== 'string' || tab === '') return DEFAULT_THREAT_HUNT_TAB;
  if (THREAT_HUNT_TABS.includes(tab)) return tab;
  return MOVED_TABS[tab] ?? DEFAULT_THREAT_HUNT_TAB;
}
