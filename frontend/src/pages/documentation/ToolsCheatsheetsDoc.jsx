import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight } from 'lucide-react';
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

const TOOLS = [
  {
    id: 'volatility3',
    name: 'Volatility 3',
    icon: '🧠',
    category: 'Mémoire',
    version: 'v2.x',
    desc: "Framework d'analyse forensique mémoire. Analyse les images RAM Windows, Linux et macOS. Extraction de processus, connexions réseau, artefacts de malware.",
    install: 'pip install volatility3  # ou git clone https://github.com/volatilityfoundation/volatility3',
    sections: [
      {
        label: 'Profil & Info système',
        cmds: [
          'vol -f memory.raw windows.info  # info système',
          'vol -f memory.raw windows.hashdump  # hashes SAM',
          'vol -f memory.raw windows.envars  # variables env',
          'vol -f memory.raw windows.registry.hivelist  # hives chargées',
          'vol -f memory.raw windows.registry.printkey --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
        ],
      },
      {
        label: 'Processus',
        cmds: [
          'vol -f memory.raw windows.pslist  # liste processus',
          'vol -f memory.raw windows.pstree  # arbre processus',
          'vol -f memory.raw windows.psscan  # scan mémoire (détecte processus cachés)',
          'vol -f memory.raw windows.cmdline  # arguments ligne de commande',
          'vol -f memory.raw windows.dlllist --pid 1234  # DLLs chargées',
          'vol -f memory.raw windows.handles --pid 1234  # handles ouverts',
          'vol -f memory.raw windows.dumpfiles --pid 1234 -o /tmp/dump/  # dump DLLs/EXE',
        ],
      },
      {
        label: 'Réseau',
        cmds: [
          'vol -f memory.raw windows.netstat  # connexions réseau actives',
          'vol -f memory.raw windows.netscan  # scan réseau (inclut connexions fermées)',
        ],
      },
      {
        label: 'Détection malware',
        cmds: [
          'vol -f memory.raw windows.malfind  # régions mémoire suspectes (RWX + PE headers)',
          'vol -f memory.raw windows.malfind --dump -o /tmp/malfind/  # dump les régions',
          'vol -f memory.raw windows.hollowfind  # process hollowing',
          'vol -f memory.raw windows.ldrmodules  # DLLs non linkées (stealth inject)',
          'vol -f memory.raw windows.ssdt  # SSDT hooks (rootkits)',
          'vol -f memory.raw windows.callbacks  # kernel callbacks',
        ],
      },
      {
        label: 'Artefacts Windows',
        cmds: [
          'vol -f memory.raw windows.mftparser  # parser la MFT',
          'vol -f memory.raw windows.filescan  # fichiers dans le cache mémoire',
          'vol -f memory.raw windows.dumpfiles --virtaddr 0x... -o /tmp/  # extraire fichier',
          'vol -f memory.raw windows.clipboard  # contenu presse-papier',
          'vol -f memory.raw windows.iehistory  # historique IE en mémoire',
          'vol -f memory.raw windows.shimcache  # shimcache (exécutions)',
          'vol -f memory.raw windows.amcache  # amcache en mémoire',
        ],
      },
      {
        label: 'Credentials',
        cmds: [
          'vol -f memory.raw windows.hashdump  # NTLM hashes SAM',
          'vol -f memory.raw windows.lsadump  # LSA secrets',
          'vol -f memory.raw windows.cachedump  # cached domain credentials',
          '# Mimikatz en mémoire (si LSASS dumped)',
          '# pypykatz lsa minidump lsass.dmp',
        ],
      },
      {
        label: 'Linux',
        cmds: [
          'vol -f linux.raw linux.pslist',
          'vol -f linux.raw linux.bash  # historique bash',
          'vol -f linux.raw linux.lsmod  # modules kernel',
          'vol -f linux.raw linux.check_modules  # modules cachés (rootkit)',
          'vol -f linux.raw linux.netstat',
          'vol -f linux.raw linux.malfind',
        ],
      },
    ],
  },
  {
    id: 'eztools',
    name: 'EZTools (Eric Zimmermann)',
    icon: '🪟',
    category: 'Windows Artifacts',
    version: '2024',
    desc: "Suite d'outils forensiques Windows de référence : MFTECmd, LECmd, PECmd, RECmd, SBECmd, JLECmd, AppCompatCacheParser. Gratuits, maintenus activement.",
    install: 'https://ericzimmerman.github.io/#!index.md  — télécharger Get-ZimmermanTools.ps1',
    sections: [
      {
        label: 'MFTECmd — Master File Table',
        cmds: [
          'MFTECmd.exe -f "$MFT" --csv C:\\output\\ --csvf mft.csv',
          'MFTECmd.exe -f "$MFT" --csv C:\\output\\ --csvf mft.csv --vss  # inclure VSS',
          '# Analyser le CSV : comparer timestamps $SI vs $FN (timestomping)',
          'MFTECmd.exe -f "$MFT" --de <MFT_ENTRY_NUMBER>  # entrée spécifique',
        ],
      },
      {
        label: 'PECmd — Prefetch Files',
        cmds: [
          'PECmd.exe -d "C:\\Windows\\Prefetch" --csv C:\\output\\ --csvf prefetch.csv',
          'PECmd.exe -f "C:\\Windows\\Prefetch\\EVIL.EXE-XXXXXXXX.pf" -q',
          '# Output : nom exe, hash, date dernière exécution, run count, fichiers liés',
        ],
      },
      {
        label: 'LECmd — LNK Files',
        cmds: [
          'LECmd.exe -d "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent" --csv C:\\output\\',
          'LECmd.exe -f "C:\\path\\to\\file.lnk" -q',
          '# Révèle : fichier source, timestamps, volume info, MAC address',
        ],
      },
      {
        label: 'RECmd — Registry',
        cmds: [
          'RECmd.exe -d "C:\\Windows\\System32\\config" --bn BatchExamples\\Kroll_Batch.reb --csv C:\\output\\',
          'RECmd.exe -f "C:\\Windows\\System32\\config\\SYSTEM" --kn "SYSTEM\\CurrentControlSet\\Services" --csv C:\\output\\',
          '# Batch files disponibles : Kroll_Batch.reb, RECmd_Batch_All.reb',
        ],
      },
      {
        label: 'SBECmd — ShellBags',
        cmds: [
          'SBECmd.exe -d "C:\\Users\\user\\NTUSER.DAT" --csv C:\\output\\',
          '# Révèle : dossiers accédés (locaux + réseau), ordre d\'accès, timestamps',
        ],
      },
      {
        label: 'AppCompatCacheParser — ShimCache',
        cmds: [
          'AppCompatCacheParser.exe -f "C:\\Windows\\System32\\config\\SYSTEM" --csv C:\\output\\',
          '# Révèle : tous les exécutables connus du système, dernière modification',
        ],
      },
      {
        label: 'AmcacheParser — AmCache',
        cmds: [
          'AmcacheParser.exe -f "C:\\Windows\\appcompat\\Programs\\Amcache.hve" --csv C:\\output\\',
          '# Révèle : SHA1 des binaires exécutés, chemin, publisher, version',
        ],
      },
      {
        label: 'JLECmd — Jump Lists',
        cmds: [
          'JLECmd.exe -d "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations" --csv C:\\output\\',
          '# Révèle : fichiers récemment ouverts par application, timestamps',
        ],
      },
    ],
  },
  {
    id: 'hayabusa',
    name: 'Hayabusa',
    icon: '🦅',
    category: 'Log Analysis',
    version: 'v2.x',
    desc: "Outil d'analyse EVTX Sigma-based. Détecte les TTPs MITRE ATT&CK dans les Event Logs Windows. Génère des timelines, des résumés et des alertes basées sur des règles Sigma.",
    install: 'https://github.com/Yamato-Security/hayabusa — binaire Windows/Linux disponible',
    sections: [
      {
        label: 'Analyse rapide',
        cmds: [
          '# Analyse d\'un répertoire d\'EVTX',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ -o timeline.csv',
          '# Analyse avec sortie JSON',
          'hayabusa.exe json-timeline -d C:\\EVTX\\ -o timeline.jsonl',
          '# Vue rapide des alertes critiques uniquement',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ -l critical -o critical.csv',
          '# Résumé statistique',
          'hayabusa.exe logon-summary -d C:\\EVTX\\ -o logon_summary.html',
        ],
      },
      {
        label: 'Filtres et recherche',
        cmds: [
          '# Filtrer par niveau de sévérité',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ -m low -o timeline.csv  # min level',
          '# Filtrer par tags MITRE',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ --include-tag lateral-movement',
          '# Filtrer par plage temporelle',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ --start "2024-01-01 00:00:00" --end "2024-01-02 23:59:59"',
          '# Recherche par EventID',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ --eid 4624,4625,4648',
        ],
      },
      {
        label: 'Mise à jour des règles Sigma',
        cmds: [
          'hayabusa.exe update-rules',
          '# Les règles sont dans ./rules/hayabusa/ et ./rules/sigma/builtin/',
          '# Ajouter règles Sigma custom',
          'hayabusa.exe csv-timeline -d C:\\EVTX\\ --rules-dir custom_rules/',
        ],
      },
    ],
  },
  {
    id: 'chainsaw',
    name: 'Chainsaw',
    icon: '⛓️',
    category: 'Log Analysis',
    version: 'v2.x',
    desc: "Outil d'analyse EVTX basé sur Sigma et des règles maison. Plus rapide que Hayabusa sur les grands volumes. Idéal pour la triage initiale lors d'un incident.",
    install: 'https://github.com/WithSecureLabs/chainsaw — binaire Windows/Linux',
    sections: [
      {
        label: 'Hunting EVTX',
        cmds: [
          '# Hunt avec règles Sigma et mapping EVTX',
          'chainsaw hunt "C:\\EVTX\\" -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/',
          '# Hunt avec sortie JSON',
          'chainsaw hunt "C:\\EVTX\\" -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o results.json --json',
          '# Hunt ciblé sur une catégorie',
          'chainsaw hunt "C:\\EVTX\\" -s sigma/rules/windows/process_creation/ --mapping mappings/sigma-event-logs-all.yml',
        ],
      },
      {
        label: 'Recherche de patterns',
        cmds: [
          '# Chercher un pattern dans les EVTX',
          'chainsaw search "mimikatz" "C:\\EVTX\\"',
          'chainsaw search -e 4624 "C:\\EVTX\\"  # par EventID',
          'chainsaw search --timestamp "2024-01-15T00:00:00" -t "2024-01-15T23:59:59" "C:\\EVTX\\"',
          '# Afficher résumé timeline',
          'chainsaw analyse timeline "C:\\EVTX\\" --output timeline/ --format json',
        ],
      },
    ],
  },
  {
    id: 'kape',
    name: 'KAPE (Kroll Artifact Parser and Extractor)',
    icon: '📥',
    category: 'Acquisition',
    version: 'v1.x',
    desc: "Outil de collecte et de traitement d'artefacts forensiques Windows. Définit des targets (fichiers à collecter) et des modules (outils à exécuter). Idéal pour la collecte rapide en réponse à incident.",
    install: 'https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape',
    sections: [
      {
        label: 'Collecte d\'artefacts (Targets)',
        cmds: [
          '# Collecte complète Windows (EVTX, Registry, MFT, Prefetch...)',
          'kape.exe --tsource C:\\ --tdest D:\\evidence\\ --target WindowsEvidenceCollection',
          '# Collecte MFT seulement',
          'kape.exe --tsource C:\\ --tdest D:\\evidence\\ --target MFT',
          '# Collecte logs seulement',
          'kape.exe --tsource C:\\ --tdest D:\\evidence\\ --target EventLogs',
          '# Mode VSS (Volume Shadow Copy)',
          'kape.exe --tsource C:\\ --tdest D:\\evidence\\ --target EventLogs --vss',
          '# Collecte depuis image montée',
          'kape.exe --tsource F:\\ --tdest D:\\evidence\\ --target WindowsEvidenceCollection',
        ],
      },
      {
        label: 'Traitement (Modules)',
        cmds: [
          '# Exécuter EZTools sur les artefacts collectés',
          'kape.exe --msource D:\\evidence\\ --mdest D:\\processed\\ --module !EZParser',
          '# Traitement Hayabusa',
          'kape.exe --msource D:\\evidence\\ --mdest D:\\processed\\ --module Hayabusa',
          '# Tout traiter (collecte + traitement)',
          'kape.exe --tsource C:\\ --tdest D:\\evidence\\ --target WindowsEvidenceCollection --module !EZParser --mdest D:\\processed\\',
        ],
      },
      {
        label: 'Artefacts collectés par WindowsEvidenceCollection',
        cmds: [
          '# EVTX : C:\\Windows\\System32\\winevt\\Logs\\',
          '# Registry : NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY',
          '# Prefetch : C:\\Windows\\Prefetch\\',
          '# MFT : $MFT, $LogFile, $UsnJrnl',
          '# LNK : %APPDATA%\\Recent\\',
          '# Jump Lists : AutomaticDestinations, CustomDestinations',
          '# ShimCache, AmCache',
          '# Browser history (Chrome, Firefox, Edge)',
          '# Thumbcache, Recycle Bin',
        ],
      },
    ],
  },
  {
    id: 'velociraptor',
    name: 'Velociraptor',
    icon: '🦖',
    category: 'DFIR Platform',
    version: 'v0.7.x',
    desc: "Plateforme DFIR endpoint de collecte et d'investigation à distance. Utilise VQL (Velociraptor Query Language) pour des investigations sur des parcs de milliers de machines simultanément.",
    install: 'https://github.com/Velocidex/velociraptor — binaire serveur + client',
    sections: [
      {
        label: 'VQL — Requêtes essentielles',
        cmds: [
          '# Lister les processus en cours',
          'SELECT Pid, Ppid, Name, Exe, CommandLine FROM pslist()',
          '# Connexions réseau',
          'SELECT Pid, Family, Type, Status, Laddr, Lport, Raddr, Rport FROM netstat()',
          '# Fichiers récemment modifiés dans System32',
          'SELECT FullPath, Mtime, Size FROM glob(globs="C:/Windows/System32/**") WHERE Mtime > "2024-01-01"',
          '# Parser EVTX',
          'SELECT * FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx") WHERE System.EventID.Value = 4624 LIMIT 100',
          '# Hashes fichiers suspects dans temp',
          'SELECT FullPath, hash(path=FullPath).MD5 AS MD5 FROM glob(globs=["C:/Temp/**","C:/Windows/Temp/**"]) WHERE Size > 1000',
        ],
      },
      {
        label: 'Artifacts prédéfinis (hunt)',
        cmds: [
          '# Windows.EventLogs.Hayabusa — analyse EVTX avec Hayabusa',
          '# Windows.Forensics.KAPE — collecte artefacts KAPE',
          '# Windows.Memory.Acquisition — dump mémoire RAM',
          '# Windows.Detection.Autoruns — analyse autoruns',
          '# Windows.Forensics.Timeline — timeline MFT',
          '# Generic.Collectors.File — collecte de fichiers',
          '# Exchange.Windows.EventLogs.AlternateDataStreams — ADS hunting',
          '# Server side: hunt → new hunt → sélectionner artifact → déployer sur tous les endpoints',
        ],
      },
    ],
  },
  {
    id: 'sysmon',
    name: 'Sysmon (System Monitor)',
    icon: '👁️',
    category: 'Monitoring',
    version: 'v15.x',
    desc: "Service système Windows de logging avancé. Journalise les créations de processus, les connexions réseau, les accès fichiers, le chargement de DLLs, les injections. Base de toute détection moderne.",
    install: 'sysmon64.exe -accepteula -i sysmonconfig.xml',
    sections: [
      {
        label: 'EventIDs Sysmon clés',
        cmds: [
          '# Event 1 : ProcessCreate — cmdline complet + hashes',
          '# Event 2 : FileCreationTimeChanged — timestomping',
          '# Event 3 : NetworkConnect — connexion TCP/UDP sortante',
          '# Event 5 : ProcessTerminate',
          '# Event 6 : DriverLoad — chargement driver kernel',
          '# Event 7 : ImageLoad — DLL chargée dans processus',
          '# Event 8 : CreateRemoteThread — injection de thread',
          '# Event 10 : ProcessAccess — accès handle à un autre processus (LSASS dump)',
          '# Event 11 : FileCreate',
          '# Event 12/13/14 : Registry — create/set/rename',
          '# Event 15 : FileCreateStreamHash — Alternate Data Streams',
          '# Event 17/18 : PipeCreate/PipeConnect — named pipes (C2 SMB)',
          '# Event 19/20/21 : WMIActivity — abonnements WMI',
          '# Event 22 : DNSQuery — requêtes DNS par processus',
          '# Event 23 : FileDelete',
          '# Event 25 : ProcessTampering — process hollowing détecté',
          '# Event 26 : FileDeleteDetected',
        ],
      },
      {
        label: 'Configurations recommandées',
        cmds: [
          '# SwiftOnSecurity config (comprehensive)',
          'https://github.com/SwiftOnSecurity/sysmon-config',
          '# Olaf Hartong modular config (par tactic MITRE)',
          'https://github.com/olafhartong/sysmon-modular',
          '# Neo23x0 config (balanced)',
          'https://github.com/Neo23x0/sysmon-config',
          '# Appliquer nouvelle config sans redémarrage',
          'sysmon64.exe -c new_config.xml',
        ],
      },
      {
        label: 'Requêtes Sigma → EVTX',
        cmds: [
          '# LSASS access — Event 10',
          "Get-WinEvent -Path Security.evtx | Where {$_.Id -eq 10 -and $_.Message -match 'lsass'}",
          '# Process injection — Event 8',
          "Get-WinEvent -Path Security.evtx | Where {$_.Id -eq 8}",
          '# Suspicious network — Event 3',
          "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Where {$_.Id -eq 3 -and $_.Message -match 'powershell'}",
        ],
      },
    ],
  },
  {
    id: 'plaso',
    name: 'Plaso / log2timeline',
    icon: '📅',
    category: 'Timeline',
    version: 'v20240101',
    desc: "Outil de super-timeline forensique. Agrège des centaines de sources d'artefacts en une timeline unifiée. Essentiel pour reconstruire la séquence d'événements lors d'un incident.",
    install: 'pip install plaso  # ou via docker : docker pull log2timeline/plaso',
    sections: [
      {
        label: 'Création de la super-timeline',
        cmds: [
          '# Analyser une image disque',
          'log2timeline.py evidence.plaso /dev/sdb',
          '# Analyser un dossier',
          'log2timeline.py evidence.plaso /path/to/evidence/',
          '# Analyser seulement certains parsers',
          'log2timeline.py --parsers winevtx,mft,prefetch,registry evidence.plaso /evidence/',
          '# Analyser image E01',
          'log2timeline.py evidence.plaso evidence.E01',
          '# Avec timezone',
          'log2timeline.py --timezone UTC evidence.plaso /evidence/',
        ],
      },
      {
        label: 'Export et filtrage',
        cmds: [
          '# Export en CSV',
          'psort.py -o l2tcsv evidence.plaso -w timeline.csv',
          '# Export en JSON',
          'psort.py -o json evidence.plaso -w timeline.jsonl',
          '# Filtrer par plage temporelle',
          'psort.py evidence.plaso -w output.csv "date > \'2024-01-15 00:00:00\' AND date < \'2024-01-16 23:59:59\'"',
          '# Filtrer par hostname',
          'psort.py evidence.plaso -w output.csv "hostname is \'WORKSTATION01\'"',
          '# Chercher un pattern',
          'psort.py evidence.plaso -w output.csv "message contains \'mimikatz\'"',
        ],
      },
      {
        label: 'Visualisation',
        cmds: [
          '# Timesketch (UI web pour Plaso)',
          '# Import dans Timesketch',
          'timesketch_import_client.py --sketch_id 1 evidence.plaso',
          '# Analyser avec pinfo',
          'pinfo.py evidence.plaso  # stats sur les sources parsées',
          '# Ouvrir dans Splunk',
          '# Import CSV Plaso → Sourcetype manual_csv',
        ],
      },
    ],
  },
];

const CATEGORIES = ['Tous', 'Mémoire', 'Windows Artifacts', 'Log Analysis', 'Acquisition', 'DFIR Platform', 'Monitoring', 'Timeline'];

function ToolCard({ tool, search }) {
  const T = useTheme();
  const [open, setOpen] = useState(false);
  const [activeSection, setActiveSection] = useState(0);

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return tool.name.toLowerCase().includes(q) ||
      tool.desc.toLowerCase().includes(q) ||
      tool.sections.some(s => s.label.toLowerCase().includes(q) || s.cmds.some(c => c.toLowerCase().includes(q)));
  }, [search, tool]);

  if (!matches) return null;

  return (
    <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginBottom: 10 }}>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left"
        style={{ padding: '12px 16px', background: 'var(--fl-card)', border: 'none', cursor: 'pointer', display: 'block', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 15 }}>{tool.icon}</span>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: T.text }}>{tool.name}</span>
            <span style={{ fontFamily: 'monospace', fontSize: 8, padding: '1px 5px', borderRadius: 3,
              background: 'var(--fl-panel)', color: T.dim, border: '1px solid var(--fl-border)' }}>{tool.version}</span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, padding: '1px 6px', borderRadius: 3,
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)' }}>
              {tool.category}
            </span>
          </div>
          {open ? <ChevronDown size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} /> : <ChevronRight size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} />}
        </div>
        <p style={{ fontSize: 11, marginTop: 5, marginLeft: 22, color: T.muted, fontFamily: 'monospace', lineHeight: 1.5 }}>{tool.desc}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '14px 16px' }}>
          {/* Install */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>Installation / Référence</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 9px', borderRadius: 4, background: T.panel, border: '1px solid var(--fl-border)' }}>
              <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-ok)', flex: 1, lineHeight: 1.5 }}>{tool.install}</code>
              <CopyBtn text={tool.install} />
            </div>
          </div>

          {/* Section tabs */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 12 }}>
            {tool.sections.map((s, i) => (
              <button key={i} onClick={() => setActiveSection(i)}
                style={{
                  fontFamily: 'monospace', fontSize: 9, padding: '2px 8px', borderRadius: 4,
                  cursor: 'pointer', border: '1px solid',
                  background: activeSection === i ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'var(--fl-card)',
                  color: activeSection === i ? 'var(--fl-accent)' : T.dim,
                  borderColor: activeSection === i ? 'color-mix(in srgb, var(--fl-accent) 40%, transparent)' : T.border,
                }}>
                {s.label}
              </button>
            ))}
          </div>

          {/* Active section commands */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {tool.sections[activeSection].cmds.map((cmd, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '5px 9px', borderRadius: 4,
                background: T.panel, border: '1px solid var(--fl-border)' }}>
                <code style={{ fontFamily: 'monospace', fontSize: 11, color: cmd.startsWith('#') ? T.dim : 'var(--fl-ok)', wordBreak: 'break-all', flex: 1, lineHeight: 1.5 }}>{cmd}</code>
                {!cmd.startsWith('#') && !cmd.startsWith('https://') && <CopyBtn text={cmd} />}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ToolsCheatsheetsDoc({ search }) {
  const T = useTheme();
  const [catFilter, setCatFilter] = useState('Tous');

  const filtered = useMemo(() => {
    return TOOLS.filter(t => {
      if (catFilter !== 'Tous' && t.category !== catFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return t.name.toLowerCase().includes(q) ||
        t.desc.toLowerCase().includes(q) ||
        t.sections.some(s => s.label.toLowerCase().includes(q) || s.cmds.some(c => c.toLowerCase().includes(q)));
    });
  }, [search, catFilter]);

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      <div style={{ marginBottom: 14 }}>
        <h1 style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: T.text, marginBottom: 3 }}>Cheatsheets Outils DFIR</h1>
        <p style={{ fontFamily: 'monospace', fontSize: 11, color: T.muted }}>
          {search || catFilter !== 'Tous'
            ? `${filtered.length} outil${filtered.length !== 1 ? 's' : ''} trouvé${filtered.length !== 1 ? 's' : ''}`
            : `${TOOLS.length} outils — Volatility · EZTools · Hayabusa · Chainsaw · KAPE · Velociraptor · Sysmon · Plaso`}
        </p>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 16 }}>
        {CATEGORIES.map(c => {
          const active = catFilter === c;
          const count = c === 'Tous' ? TOOLS.length : TOOLS.filter(t => t.category === c).length;
          return (
            <button key={c} onClick={() => setCatFilter(c)}
              style={{
                fontFamily: 'monospace', fontSize: 10, padding: '3px 8px', borderRadius: 4,
                cursor: 'pointer', border: '1px solid',
                background: active ? 'color-mix(in srgb, var(--fl-gold) 18%, transparent)' : 'var(--fl-card)',
                color: active ? 'var(--fl-gold)' : T.dim,
                borderColor: active ? 'color-mix(in srgb, var(--fl-gold) 45%, transparent)' : T.border,
              }}>
              {c} ({count})
            </button>
          );
        })}
      </div>

      {filtered.map(t => <ToolCard key={t.id} tool={t} search={search} />)}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.muted }}>
          <p style={{ fontFamily: 'monospace', fontSize: 13 }}>Aucun outil ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
