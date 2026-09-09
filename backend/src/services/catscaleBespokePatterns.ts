export const BESPOKE_PATTERNS: Record<string, string[]> = {
  Logs: ['var-log', 'var-crash', 'var-adm', 'last-utmp', 'last-wtmp', 'last-wtmpx'],

  Misc: ['full-timeline'],

  Persistence: ['cron-folder', 'systemctl_all', 'systemctl_service_status'],

  Process_and_Network: [
    'ip-a', 'iptables', 'iptables-numerical',
    'netstat-an', 'netstat-antup', 'netstat-pvTanoee', 'netstat-pvWanoee',
    'processes-auxSww', 'processes-auxww', 'processes-axwwSo', 'processes-e',
    'processes-ef', 'processes-eF', 'process-exe-links', 'routetable',
    'ss-anepo', 'ssh-folders',
  ],

  System_Info: [
    'deb-package-verify', 'rpm-package-verify', 'module-sha1',
    'etc-key-files', 'etc-modified-files',
  ],

  Docker: ['docker-inspect', 'docker-top', 'docker-container-diff', 'docker-container-port'],

  Podman: ['podman-inspect', 'podman-container-top', 'podman-container-diff', 'podman-container-port'],

  User_Files: ['hidden-user-home-dir'],
};
