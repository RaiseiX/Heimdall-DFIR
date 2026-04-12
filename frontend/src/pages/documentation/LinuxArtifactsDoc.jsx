import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react';
import { useTheme } from '../../utils/theme';

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1800); }); }}
      title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 6px', borderRadius: 4, cursor: 'pointer',
        fontSize: 9, fontFamily: 'monospace', flexShrink: 0,
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
      }}>
      {ok ? <CheckCheck size={9} /> : <Copy size={9} />}
    </button>
  );
}

const ARTIFACTS = [
  {
    id: 'auth-log',
    title: '/var/log/auth.log & /var/log/secure',
    icon: '🔐',
    category: 'Logs système',
    summary: "Journal d'authentification principal sur Linux (Debian/Ubuntu = auth.log, RHEL/CentOS = secure). Contient SSH, sudo, su, PAM events. Première source à analyser lors d'une compromission.",
    location: ['/var/log/auth.log (Debian/Ubuntu)', '/var/log/secure (RHEL/CentOS/Fedora)'],
    forensic_value: [
      'Connexions SSH réussies et échouées (Failed password, Accepted publickey)',
      'Brute force SSH : volume de "Failed password" depuis même IP',
      "Escalade de privilèges : sudo, su — avec l'utilisateur source et la commande",
      'Connexions depuis IPs inconnues à des heures inhabituelles',
      'Utilisation de comptes inactifs ou comptes système (daemon, www-data)',
    ],
    commands: [
      '# Connexions SSH réussies',
      'grep "Accepted" /var/log/auth.log | awk \'{print $1,$2,$3,$9,$11}\'',
      '# Brute force — top IPs',
      'grep "Failed password" /var/log/auth.log | awk \'{print $11}\' | sort | uniq -c | sort -rn | head',
      '# Connexions sudo',
      'grep "sudo:" /var/log/auth.log | grep "COMMAND"',
      '# Connexions depuis une IP spécifique',
      'grep "10.0.0.1" /var/log/auth.log',
    ],
    iocs: [
      'Centaines de "Failed password" en quelques secondes (brute force)',
      'Accepted publickey depuis clé inconnue / non référencée',
      'sudo COMMAND contenant wget, curl, nc, python, bash',
      'Connexion root directe via SSH (si PermitRootLogin = yes)',
    ],
  },
  {
    id: 'wtmp-utmp',
    title: 'wtmp / utmp / btmp — Sessions utilisateurs',
    icon: '👤',
    category: 'Logs système',
    summary: "Bases de données binaires enregistrant les connexions (wtmp = historique complet, utmp = sessions actives, btmp = échecs). Non modifiables par les commandes texte standard — souvent oubliés par les attaquants.",
    location: ['/var/log/wtmp (historique login/logout)', '/var/run/utmp (sessions actives)', '/var/log/btmp (tentatives échouées)'],
    forensic_value: [
      'Historique complet des sessions : utilisateur, TTY, IP source, heure',
      'btmp : tentatives de connexion échouées avec IP source',
      'Détecter des sessions ouvertes à des heures inhabituelles',
      'Identifier des comptes ayant eu accès au système',
    ],
    commands: [
      '# Historique connexions',
      'last -F -f /var/log/wtmp | head -50',
      '# Connexions échouées',
      'lastb -F -f /var/log/btmp | head -50',
      '# Sessions actives au moment de la collecte',
      'who -a',
      '# Statistiques par utilisateur',
      'last | awk \'{print $1}\' | sort | uniq -c | sort -rn',
      '# Connexions depuis IP externe',
      'last | grep -v "pts/" | grep -v "tty"',
    ],
    iocs: [
      'Connexion root via SSH directe',
      'Utilisateur système (www-data, nobody) avec session interactive',
      'Connexion depuis IP étrangère hors plage habituelle',
      'Session sans logout (machine compromise puis éteinte brutalement)',
    ],
  },
  {
    id: 'bash-history',
    title: '.bash_history / Shell History',
    icon: '💬',
    category: "Artefacts utilisateur",
    summary: "Historique des commandes shell. Souvent purgé par les attaquants mais des traces restent (timestamps, .zsh_history, /proc/$PID/environ). L'absence d'historique est elle-même un IOC.",
    location: [
      '/home/<user>/.bash_history',
      '/root/.bash_history',
      '/home/<user>/.zsh_history',
      '/home/<user>/.config/fish/fish_history',
    ],
    forensic_value: [
      "Commandes exécutées par l'attaquant (reconnaisance, persistence, exfil)",
      'Timestamps si HISTTIMEFORMAT configuré',
      'Commandes sudo, wget, curl, nc, python -c, gcc',
      'Chemins de fichiers malveillants mentionnés',
    ],
    commands: [
      '# Voir historique avec timestamps',
      'HISTTIMEFORMAT="%F %T " history',
      '# Tous les .bash_history du système',
      'find / -name ".bash_history" -type f 2>/dev/null',
      '# Commandes suspectes dans tous les historiques',
      'grep -h "wget\\|curl\\|nc \\|python\\|perl\\|base64\\|chmod +x" /home/*/.bash_history /root/.bash_history 2>/dev/null',
      '# Vérifier si historique a été purgé',
      'ls -la /home/*/.bash_history /root/.bash_history',
    ],
    iocs: [
      ".bash_history vide ou lien symbolique vers /dev/null (l'attaquant désactive l'historique)",
      'Commandes de téléchargement (wget, curl) avec URLs externes',
      'python -c ou perl -e avec code encodé',
      'chmod +x suivi exécution dans /tmp ou /dev/shm',
      'history -c ou unset HISTFILE dans historique',
    ],
  },
  {
    id: 'proc-filesystem',
    title: '/proc — Système de Fichiers Virtuel',
    icon: '🔬',
    category: 'Mémoire & Processus',
    summary: "Interface kernel exposant les processus et la mémoire système en temps réel. Permet d'investiguer des processus malveillants sans outils forensiques spécialisés. Volatile : collecte sur système vivant uniquement.",
    location: ['/proc/<PID>/exe — binaire du processus (symlink)', '/proc/<PID>/cmdline — ligne de commande complète', '/proc/<PID>/maps — mappings mémoire', '/proc/<PID>/net/tcp — connexions réseau', '/proc/<PID>/environ — variables environnement'],
    forensic_value: [
      'Identifier le binaire réel même si supprimé du disque (exe pointe vers deleted)',
      'Voir les connexions réseau des processus',
      'Détecter les injections mémoire (régions anonymes RWX)',
      'Récupérer un binaire malveillant supprimé',
    ],
    commands: [
      '# Lister tous les processus avec binaire',
      'ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied"',
      '# Processus dont le binaire a été supprimé',
      'ls -la /proc/*/exe 2>/dev/null | grep deleted',
      '# Récupérer le binaire supprimé',
      'cp /proc/<PID>/exe /tmp/recovered_binary',
      '# Connexions réseau par processus',
      'cat /proc/<PID>/net/tcp | awk \'{print $2,$3,$4}\'',
      '# Régions mémoire suspectes (rwx anonymes)',
      'cat /proc/<PID>/maps | grep "rwxp" | grep -v ".so" | grep -v "exe"',
      '# Cmdline complet',
      'cat /proc/<PID>/cmdline | tr "\\0" " "; echo',
    ],
    iocs: [
      'Processus avec /proc/<PID>/exe → ... (deleted)',
      'Région mémoire rwxp sans fichier backing (injection)',
      'Processus shell spawné depuis daemon web (apache2, nginx)',
      'Connexions réseau depuis processus système non réseau',
    ],
  },
  {
    id: 'crontabs',
    title: 'Crontabs — Persistance Planifiée',
    icon: '⏰',
    category: 'Persistance',
    summary: "Mécanisme de persistance le plus courant sur Linux. Les attaquants ajoutent des entrées cron pour maintenir l'accès ou exécuter des scripts périodiquement.",
    location: [
      '/var/spool/cron/crontabs/<user> (cron utilisateur)',
      '/etc/cron.d/ (cron système)',
      '/etc/crontab (cron global)',
      '/etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, /etc/cron.monthly/',
      '/var/spool/anacron/',
    ],
    forensic_value: [
      'Persistance : script malveillant exécuté périodiquement',
      'Reverse shell maintenu via cron toutes les minutes',
      'Miner de cryptomonnaie planifié hors heures de travail',
    ],
    commands: [
      '# Tous les crontabs utilisateurs',
      'for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done',
      '# Crontabs système',
      'cat /etc/crontab',
      'ls -la /etc/cron.d/ && cat /etc/cron.d/*',
      '# Fichiers modifiés récemment dans cron dirs',
      'find /etc/cron* /var/spool/cron* -newer /etc/passwd -ls 2>/dev/null',
      '# Entrées suspectes',
      'grep -r "wget\\|curl\\|bash\\|python\\|perl\\|nc " /etc/cron* /var/spool/cron* 2>/dev/null',
    ],
    iocs: [
      '* * * * * (chaque minute) — reverse shell maintenu',
      'Téléchargement depuis URL externe dans cron',
      'Script dans /tmp, /dev/shm, ou répertoire caché',
      'Crontab modifié récemment (mtime proche de la compromission)',
      'Base64 ou encodage dans la commande cron',
    ],
  },
  {
    id: 'systemd-units',
    title: 'Systemd — Services & Timers',
    icon: '⚙️',
    category: 'Persistance',
    summary: "Les attaquants créent des units systemd malveillants pour la persistance. Les timers systemd remplacent avantageusement les crons car moins surveillés.",
    location: [
      '/etc/systemd/system/ (units système — persistance root)',
      '/lib/systemd/system/ (units installés par paquets)',
      '/home/<user>/.config/systemd/user/ (units utilisateur)',
      '/run/systemd/system/ (units temporaires)',
    ],
    forensic_value: [
      'Service malveillant démarrant automatiquement au boot',
      'Timer exécutant un script à intervalles réguliers',
      'Service relançant un reverse shell si tué',
    ],
    commands: [
      '# Tous les services activés',
      'systemctl list-units --type=service --state=active',
      '# Services récemment installés/modifiés',
      'find /etc/systemd /lib/systemd -name "*.service" -newer /etc/passwd -ls 2>/dev/null',
      '# Inspecter un service suspect',
      'systemctl cat <service_name>',
      '# Timers actifs',
      'systemctl list-timers --all',
      '# Services en échec (malware instable)',
      'systemctl list-units --state=failed',
    ],
    iocs: [
      'Service avec ExecStart pointant vers /tmp, /dev/shm, répertoire caché',
      'Service créé hors système de paquets (RPM/DEB)',
      'Restart=always — pour maintenir un reverse shell',
      'Description/Documentation vides ou génériques',
      'Unit modifié récemment dans /etc/systemd/system/',
    ],
  },
  {
    id: 'passwd-shadow',
    title: '/etc/passwd & /etc/shadow — Comptes',
    icon: '👥',
    category: 'Comptes & Accès',
    summary: "Les attaquants créent des comptes backdoor dans /etc/passwd ou modifient les hashs de /etc/shadow pour maintenir l'accès. Vérification essentielle lors de toute réponse à incident.",
    location: ['/etc/passwd (comptes — lisible par tous)', '/etc/shadow (hashs — root only)', '/etc/group (groupes)', '/etc/sudoers et /etc/sudoers.d/ (droits sudo)'],
    forensic_value: [
      'Nouveau compte créé par attaquant (UID 0 = root backdoor)',
      'Compte système avec shell interactif (/bin/bash)',
      'Modification récente de /etc/passwd ou /etc/shadow',
      'Ajout à sudoers pour escalade de privilèges',
    ],
    commands: [
      '# Comptes avec UID 0 (root)',
      'awk -F: \'$3 == 0 {print}\' /etc/passwd',
      '# Comptes avec shell interactif',
      'awk -F: \'$7 ~ /bash|sh|zsh/ {print $1,$3,$7}\' /etc/passwd',
      '# Comptes récemment modifiés',
      'ls -la /etc/passwd /etc/shadow /etc/group',
      'stat /etc/passwd | grep Modify',
      '# Différence avec baseline',
      'diff /etc/passwd /etc/passwd.bak 2>/dev/null || echo "Pas de baseline disponible"',
      '# Droits sudo',
      'cat /etc/sudoers && ls -la /etc/sudoers.d/',
      '# Comptes dans le groupe sudo/wheel',
      'grep -E "^sudo|^wheel" /etc/group',
    ],
    iocs: [
      'Compte avec UID=0 et nom ≠ root (root backdoor)',
      'Compte système avec /bin/bash comme shell',
      '/etc/passwd modifié récemment hors maintenance',
      'Entrée ALL=(ALL) NOPASSWD:ALL dans sudoers',
      'Compte sans mot de passe (champ hash vide dans /etc/shadow)',
    ],
  },
  {
    id: 'ssh-keys',
    title: 'Clés SSH — Backdoors & Accès Persistant',
    icon: '🗝️',
    category: 'Comptes & Accès',
    summary: "L'injection de clés SSH publiques dans authorized_keys est la méthode de backdoor persistante la plus courante sur Linux. Silencieuse, ne nécessite pas de mot de passe.",
    location: [
      '/home/<user>/.ssh/authorized_keys (clés autorisées)',
      '/root/.ssh/authorized_keys',
      '/home/<user>/.ssh/id_rsa (clé privée — intéressante pour exfil)',
      '/etc/ssh/sshd_config (config SSH)',
    ],
    forensic_value: [
      "Clé publique injectée = backdoor permanente sans mot de passe",
      "Clé privée présente = l'attaquant peut se connecter à d'autres systèmes",
      "Config sshd_config modifiée pour permettre root login",
      "Port SSH non standard pour éviter les scans",
    ],
    commands: [
      '# Toutes les authorized_keys du système',
      'find / -name "authorized_keys" -type f 2>/dev/null -exec echo "=== {} ===" \\; -exec cat {} \\;',
      '# Clés ajoutées récemment',
      'find / -name "authorized_keys" -newer /etc/passwd 2>/dev/null',
      '# Config SSH — options sensibles',
      'grep -E "PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|Port" /etc/ssh/sshd_config',
      '# Clés privées sur le système',
      'find / -name "id_rsa" -o -name "id_ecdsa" -o -name "*.pem" 2>/dev/null | grep -v proc',
      '# Fingerprint des clés autorisées',
      'for f in $(find / -name "authorized_keys" 2>/dev/null); do ssh-keygen -l -f "$f" 2>/dev/null; done',
    ],
    iocs: [
      'Clé autorisée non référencée dans le bastion / système de gestion des clés',
      'PermitRootLogin yes dans sshd_config',
      'authorized_keys modifié récemment hors procédure de déploiement',
      'Clé privée dans un répertoire inhabituel',
      'Clé avec commentaire générique (user@compromised, kali, root@evil)',
    ],
  },
  {
    id: 'tmp-devshm',
    title: '/tmp & /dev/shm — Zones d\'Exécution',
    icon: '🗑️',
    category: 'Exécution',
    summary: "Répertoires inscriptibles par tous, utilisés par les attaquants pour déposer et exécuter des payloads. /dev/shm est en RAM — disparaît au reboot, parfait pour les malwares furtifs.",
    location: ['/tmp/ (tmpfs ou disque, persistant entre sessions)', '/dev/shm/ (RAM uniquement, disparaît au reboot)', '/var/tmp/ (persistant entre reboots, souvent oublié)', '/run/user/<UID>/ (tmpfs utilisateur)'],
    forensic_value: [
      "Payloads, scripts, reverse shells stockés temporairement",
      "/dev/shm : malware en RAM uniquement (forensique disque insuffisant)",
      "Fichiers compressés, encodés, ou avec extension trompeuse",
      "Clés SSH temporaires, tokens d'accès",
    ],
    commands: [
      '# Fichiers dans /tmp et /dev/shm',
      'ls -laR /tmp /dev/shm /var/tmp 2>/dev/null',
      '# Fichiers récemment modifiés',
      'find /tmp /dev/shm /var/tmp -newer /proc/uptime -ls 2>/dev/null',
      '# Fichiers exécutables dans /tmp',
      'find /tmp /dev/shm -perm /111 -type f 2>/dev/null',
      '# Fichiers cachés (. prefix)',
      'find /tmp /dev/shm -name ".*" 2>/dev/null',
      '# Hash des exécutables suspects',
      'find /tmp /dev/shm -perm /111 -exec md5sum {} \\; 2>/dev/null',
    ],
    iocs: [
      'Binaire ELF dans /tmp ou /dev/shm',
      'Fichier avec droits d\'exécution dans /tmp',
      'Script shell dans /dev/shm (disparaît au reboot)',
      'Fichier caché (préfixe .) dans /tmp',
      'Fichier avec nom aléatoire (UUIDs, suites de chiffres)',
    ],
  },
  {
    id: 'ld-preload',
    title: 'LD_PRELOAD & Rootkit Userland',
    icon: '🎭',
    category: 'Evasion',
    summary: "LD_PRELOAD permet de charger une bibliothèque partagée avant toutes les autres, interceptant les appels système. Technique utilisée pour les rootkits userland et le hooking de fonctions système.",
    location: [
      '/etc/ld.so.preload (global — root)',
      'Variable d\'environnement LD_PRELOAD (par session)',
      '/etc/ld.so.conf et /etc/ld.so.conf.d/*.conf',
      '/lib/, /lib64/, /usr/lib/ (bibliothèques partagées)',
    ],
    forensic_value: [
      'Hooking de fonctions système pour masquer fichiers, processus, connexions',
      'Keylogger userland via hook de read()',
      'Bypass de détection des outils de monitoring',
    ],
    commands: [
      '# Vérifier /etc/ld.so.preload',
      'cat /etc/ld.so.preload 2>/dev/null',
      '# Variables LD_PRELOAD dans les processus',
      'grep -l "LD_PRELOAD" /proc/*/environ 2>/dev/null | while read f; do echo "$f:"; strings "$f" | grep LD_PRELOAD; done',
      '# Bibliothèques modifiées récemment',
      'find /lib /lib64 /usr/lib -name "*.so*" -newer /etc/passwd -ls 2>/dev/null',
      '# Vérifier intégrité des bibliothèques système',
      'rpm -Va 2>/dev/null | grep "^..5" | grep "\.so"  # RHEL',
      'debsums -c 2>/dev/null | grep "\.so"  # Debian',
    ],
    iocs: [
      '/etc/ld.so.preload non vide (rare en production légitime)',
      'Bibliothèque .so dans /tmp, /dev/shm, /home/',
      'Fonctions système (ls, ps, netstat) ne montrant pas les processus malveillants',
      'Écart entre output de ps/netstat et /proc/',
    ],
  },
  {
    id: 'web-server-logs',
    title: 'Logs Serveur Web (Apache/Nginx)',
    icon: '🌐',
    category: 'Logs système',
    summary: "Les logs HTTP révèlent les tentatives d'exploitation (webshells, SQLi, LFI, RFI), le comportement post-compromission (C2, exfil), et permettent la reconstruction de la chronologie d'attaque.",
    location: [
      '/var/log/apache2/access.log et error.log (Debian)',
      '/var/log/httpd/access_log et error_log (RHEL)',
      '/var/log/nginx/access.log et error.log',
      '/var/www/html/ — répertoire web (webshells)',
    ],
    forensic_value: [
      'Tentatives d\'exploitation dans les URIs',
      'Webshell : POST sur fichier .php/.jsp créé récemment',
      'Volume de requêtes depuis une IP (scan, brute force)',
      'User-Agent de scanner ou outil attaque',
      'Requêtes vers des fichiers qui n\'existent pas (recon)',
    ],
    commands: [
      '# Top IPs par volume',
      'awk \'{print $1}\' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head 20',
      '# Requêtes POST (webshells)',
      'grep "POST" /var/log/apache2/access.log | grep -v "wp-login\\|xmlrpc\\|api/"',
      '# Status 200 sur fichiers PHP non référencés',
      'grep "\\.php" /var/log/apache2/access.log | grep " 200 " | awk \'{print $7}\' | sort | uniq -c | sort -rn',
      '# Erreurs 500 (exploits)',
      'grep " 500 " /var/log/apache2/access.log | tail -50',
      '# Payloads dans les URIs',
      "grep -E \"(\\.\\./|etc/passwd|cmd=|shell=|passthru|system\\()\" /var/log/apache2/access.log",
      '# Webshells dans le webroot',
      'find /var/www -name "*.php" -newer /etc/passwd -ls 2>/dev/null',
    ],
    iocs: [
      'POST sur fichier .php avec Content-Length élevé (upload)',
      'Requêtes contenant ../../../ (path traversal)',
      'User-Agent : sqlmap, nikto, curl/python (scan automatique)',
      'Fichier .php créé récemment dans /var/www (webshell)',
      'Réponse 200 sur fichier sans extension ou .bak, .old',
    ],
  },
  {
    id: 'syslog-journal',
    title: 'Syslog / Journald — Logs Kernel & Système',
    icon: '📋',
    category: 'Logs système',
    summary: "Sources de logs centralisées sur Linux. journald (systemd) conserve les logs structurés. /var/log/syslog contient les messages kernel, daemon et réseau essentiels.",
    location: [
      '/var/log/syslog (Debian/Ubuntu)',
      '/var/log/messages (RHEL/CentOS)',
      'journalctl (systemd journal)',
      '/var/log/kern.log (messages kernel)',
    ],
    forensic_value: [
      'Modules kernel chargés (rootkit kernel)',
      'Segfaults de processus (exploitation ou malware instable)',
      'Erreurs réseau, connexions TCP refusées',
      'Messages cron, daemon, services',
    ],
    commands: [
      '# Logs boot courant',
      'journalctl -b -0 | tail -200',
      '# Logs depuis hier',
      'journalctl --since yesterday',
      '# Modules kernel chargés',
      'journalctl -k | grep "module\\|loaded"',
      'dmesg | grep "module\\|taint"',
      '# Segfaults',
      'journalctl | grep "segfault\\|core dump"',
      '# Erreurs SSH dans le journal',
      'journalctl -u sshd --since "7 days ago" | grep -i "error\\|fail\\|invalid"',
      '# Logs au format JSON (structured)',
      'journalctl -o json-pretty --since "1 hour ago" | jq \'.MESSAGE\'',
    ],
    iocs: [
      'Module kernel chargé inconnu (tainted kernel)',
      'Segfault répété d\'un même processus (exploit en cours)',
      'Messages netfilter/iptables : connexions bloquées vers C2',
      'Kernel: Oops ou BUG: (kernel exploit ou driver malveillant)',
    ],
  },
];

const CATEGORIES = ['Tous', 'Logs système', 'Artefacts utilisateur', 'Mémoire & Processus', 'Persistance', 'Comptes & Accès', 'Exécution', 'Evasion'];

function ArtifactCard({ artifact, search }) {
  const T = useTheme();
  const [open, setOpen] = useState(false);

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return artifact.title.toLowerCase().includes(q) ||
      artifact.summary.toLowerCase().includes(q) ||
      artifact.location.some(l => l.toLowerCase().includes(q)) ||
      artifact.forensic_value.some(f => f.toLowerCase().includes(q)) ||
      (artifact.commands || []).some(c => c.toLowerCase().includes(q)) ||
      artifact.iocs.some(i => i.toLowerCase().includes(q));
  }, [search, artifact]);

  if (!matches) return null;

  return (
    <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginBottom: 10 }}>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left"
        style={{ padding: '12px 16px', background: 'var(--fl-card)', border: 'none', cursor: 'pointer', display: 'block', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 15 }}>{artifact.icon}</span>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 12, color: T.text }}>{artifact.title}</span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, padding: '1px 6px', borderRadius: 3,
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)' }}>
              {artifact.category}
            </span>
          </div>
          {open ? <ChevronDown size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} /> : <ChevronRight size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} />}
        </div>
        <p style={{ fontSize: 11, marginTop: 5, marginLeft: 22, color: T.muted, fontFamily: 'monospace', lineHeight: 1.5 }}>{artifact.summary}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '14px 16px' }}>

          {/* Location */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Localisation</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {artifact.location.map((loc, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 4,
                  background: 'var(--fl-card)', border: '1px solid var(--fl-border)' }}>
                  <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-warn)', flex: 1 }}>{loc}</code>
                  <CopyBtn text={loc.split(' ')[0]} />
                </div>
              ))}
            </div>
          </div>

          {/* Forensic Value */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Valeur Forensique</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {artifact.forensic_value.map((fv, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 11, fontFamily: 'monospace', color: T.text }}>
                  <span style={{ color: 'var(--fl-accent)', flexShrink: 0 }}>›</span>
                  <span>{fv}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Commands */}
          {artifact.commands && artifact.commands.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Commandes d'Investigation</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {artifact.commands.map((cmd, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '5px 9px', borderRadius: 4,
                    background: T.panel, border: '1px solid var(--fl-border)' }}>
                    <code style={{ fontFamily: 'monospace', fontSize: 11, color: cmd.startsWith('#') ? T.dim : 'var(--fl-ok)', wordBreak: 'break-all', flex: 1, lineHeight: 1.5 }}>{cmd}</code>
                    {!cmd.startsWith('#') && <CopyBtn text={cmd} />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Indicateurs Suspects</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {artifact.iocs.map((ioc, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 11, fontFamily: 'monospace', padding: '5px 8px', borderRadius: 4,
                  background: 'color-mix(in srgb, var(--fl-danger) 5%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--fl-danger) 18%, transparent)', color: T.text }}>
                  <AlertTriangle size={10} style={{ color: 'var(--fl-danger)', flexShrink: 0, marginTop: 2 }} />
                  <span>{ioc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function LinuxArtifactsDoc({ search }) {
  const T = useTheme();
  const [catFilter, setCatFilter] = useState('Tous');

  const filtered = useMemo(() => {
    return ARTIFACTS.filter(a => {
      if (catFilter !== 'Tous' && a.category !== catFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.location.some(l => l.toLowerCase().includes(q)) ||
        a.forensic_value.some(f => f.toLowerCase().includes(q)) ||
        (a.commands || []).some(c => c.toLowerCase().includes(q)) ||
        a.iocs.some(i => i.toLowerCase().includes(q));
    });
  }, [search, catFilter]);

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      <div style={{ marginBottom: 14 }}>
        <h1 style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: T.text, marginBottom: 3 }}>Artefacts Forensiques Linux</h1>
        <p style={{ fontFamily: 'monospace', fontSize: 11, color: T.muted }}>
          {search || catFilter !== 'Tous'
            ? `${filtered.length} artefact${filtered.length !== 1 ? 's' : ''} trouvé${filtered.length !== 1 ? 's' : ''}`
            : `${ARTIFACTS.length} artefacts — localisation · valeur forensique · commandes · IOCs`}
        </p>
      </div>

      {/* Category filters */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 16 }}>
        {CATEGORIES.map(c => {
          const active = catFilter === c;
          const count = c === 'Tous' ? ARTIFACTS.length : ARTIFACTS.filter(a => a.category === c).length;
          return (
            <button key={c} onClick={() => setCatFilter(c)}
              style={{
                fontFamily: 'monospace', fontSize: 10, padding: '3px 8px', borderRadius: 4,
                cursor: 'pointer', border: '1px solid',
                background: active ? 'color-mix(in srgb, var(--fl-ok) 18%, transparent)' : 'var(--fl-card)',
                color: active ? 'var(--fl-ok)' : T.dim,
                borderColor: active ? 'color-mix(in srgb, var(--fl-ok) 45%, transparent)' : T.border,
              }}>
              {c} ({count})
            </button>
          );
        })}
      </div>

      {filtered.map(a => <ArtifactCard key={a.id} artifact={a} search={search} />)}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.muted }}>
          <p style={{ fontFamily: 'monospace', fontSize: 13 }}>Aucun artefact ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
