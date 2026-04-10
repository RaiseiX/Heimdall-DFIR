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

const PATTERNS = [
  {
    id: 'phishing',
    title: 'Phishing → Compromission endpoint',
    icon: '📧',
    severity: 'critical',
    ttps: ['T1566.001', 'T1059.001', 'T1059.005'],
    summary: 'Email avec pièce jointe malveillante (macro Office, PDF, ISO) ou lien vers site de phishing. L\'utilisateur exécute le payload qui s\'installe sur la machine.',
    artifacts: [
      { type: 'EVTX', items: ['4688 (nouveau processus — chercher WINWORD.EXE → cmd.exe)', '4104 (PowerShell script block — contenu du payload)'] },
      { type: 'Prefetch', items: ['Nom de l\'exécutable suspect, date première exécution'] },
      { type: 'AmCache', items: ['SHA1 du binaire déposé — recherche VirusTotal'] },
      { type: 'LNK', items: ['Raccourci créé vers la pièce jointe'] },
      { type: 'MFT', items: ['Fichier créé dans %TEMP%, %APPDATA%, %USERPROFILE%\\Downloads'] },
    ],
    iocs: ['Processus parent anormal (WINWORD.EXE → cmd.exe, EXCEL.EXE → powershell.exe)', 'Fichier .exe dans %TEMP%', 'Connexion réseau depuis un processus Office'],
  },
  {
    id: 'persistence-task',
    title: 'Persistance via tâche planifiée',
    icon: '⏰',
    severity: 'high',
    ttps: ['T1053.005'],
    summary: 'Création d\'une tâche planifiée pour maintenir l\'accès après redémarrage. Mécanisme de persistance fréquemment utilisé car peu surveillé par les équipes défensives.',
    artifacts: [
      { type: 'EVTX Security', items: ['4698 (tâche planifiée créée)', '4699 (supprimée)', '4702 (modifiée)'] },
      { type: 'EVTX TaskScheduler', items: ['106 (tâche enregistrée)', '200 (action lancée)', '201 (complétée)'] },
      { type: 'Fichiers', items: ['%SystemRoot%\\System32\\Tasks\\<nom de la tâche>'] },
      { type: 'Registre', items: ['HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache'] },
    ],
    iocs: ['Nom de tâche inhabituel (GUID, nom système)', 'Chemin d\'exécution dans %TEMP% ou %APPDATA%', 'Fréquence d\'exécution anormalement élevée'],
  },
  {
    id: 'persistence-service',
    title: 'Persistance via service Windows',
    icon: '⚙️',
    severity: 'high',
    ttps: ['T1543.003'],
    summary: 'Installation d\'un nouveau service Windows pour maintenir la persistance avec des privilèges élevés. SYSTEM par défaut.',
    artifacts: [
      { type: 'EVTX Security', items: ['4697 (service installé — contient le chemin du binaire)'] },
      { type: 'EVTX System', items: ['7045 (nouveau service installé)', '7034 (service crashé — signe d\'un service malveillant instable)'] },
      { type: 'Registre', items: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\<nom_service>'] },
    ],
    iocs: ['Nom de service aléatoire ou imitant un service légitime (svchost32.exe)', 'Chemin vers %TEMP% ou répertoire non-système', 'ServiceType = 0x10 (standalone service)'],
  },
  {
    id: 'credential-dump',
    title: 'Credential Dumping (LSASS)',
    icon: '🔑',
    severity: 'critical',
    ttps: ['T1003', 'T1003.001', 'T1550.002'],
    summary: 'Extraction des credentials (hashes NTLM, tickets Kerberos, mots de passe en clair) depuis le processus LSASS. Étape clé avant le mouvement latéral.',
    artifacts: [
      { type: 'EVTX Security', items: ['4688 (chercher procdump.exe, mimikatz.exe, lsass.dmp, comsvcs.dll)', '10 Sysmon (accès handle LSASS — GrantedAccess 0x1fffff)'] },
      { type: 'MFT', items: ['Fichier .dmp créé dans %TEMP% ou %USERPROFILE%'] },
      { type: 'Mémoire', items: ['malfind → accès handle LSASS', 'ldrmodules → DLLs non légitimes injectées'] },
      { type: 'Prefetch', items: ['procdump.exe, mimikatz.exe, sqldumper.exe, createdump.exe'] },
    ],
    commands: [
      'procdump.exe -ma lsass.exe lsass.dmp',
      'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> lsass.dmp full',
      'mimikatz.exe "sekurlsa::logonpasswords"',
    ],
    iocs: ['Accès au processus LSASS (PID variable)', 'Fichier .dmp créé dans un répertoire temporaire', 'comsvcs.dll exécuté via rundll32'],
  },
  {
    id: 'pass-the-hash',
    title: 'Pass the Hash / Pass the Ticket',
    icon: '🎭',
    severity: 'critical',
    ttps: ['T1550.002', 'T1558', 'T1021'],
    summary: 'Utilisation du hash NTLM (PtH) ou d\'un ticket Kerberos volé (PtT) pour s\'authentifier sans connaître le mot de passe en clair. Permet le mouvement latéral sans brute-force.',
    artifacts: [
      { type: 'EVTX Security', items: [
        '4624 Type 3 (Network logon depuis source inattendue)',
        '4648 (credentials explicites — RunAs ou PtH)',
        '4768/4769 (TGT/TGS demandé — PtT)',
        '4771 (Kerberos pre-auth échouée — ticket invalide)',
      ]},
      { type: 'Réseau', items: ['Connexions NTLM type 3 depuis des machines inhabituelles', 'TGS demandés pour des services non utilisés normalement'] },
      { type: 'Mémoire', items: ['Tickets Kerberos en cache dans la mémoire LSASS'] },
    ],
    iocs: ['Logon Type 3 depuis une source inhabituelle', 'Même hash utilisé sur plusieurs machines en quelques secondes', 'TGT demandé à des heures anormales'],
  },
  {
    id: 'lateral-rdp',
    title: 'Déplacement latéral via RDP / SMB',
    icon: '↔️',
    severity: 'high',
    ttps: ['T1021', 'T1021.001', 'T1021.002'],
    summary: 'Utilisation de comptes valides (légitimes ou volés) pour se connecter à d\'autres machines via RDP, SMB, WMI ou PsExec. Objectif : accéder aux données ou rebondir vers d\'autres cibles.',
    artifacts: [
      { type: 'EVTX Security', items: ['4624 Type 10 (RemoteInteractive = RDP)', '4624 Type 3 (Network = SMB)', '4648 (credentials explicites)'] },
      { type: 'EVTX RDP', items: ['1149 (authentification réussie)', '21 (session ouverte)', '24 (session déconnectée)', '1024-1025 (connexion client RDP)'] },
      { type: 'EVTX SMB', items: ['31001 (logon SMB échoué vers destination)'] },
      { type: 'Prefetch', items: ['mstsc.exe (client RDP utilisé)', 'psexec.exe, wmic.exe'] },
      { type: 'ShellBags', items: ['Dossiers réseau accédés via \\\\machine\\partage'] },
      { type: 'LNK', items: ['Fichiers récents sur partage réseau'] },
    ],
    iocs: ['mstsc.exe exécuté avec arguments de connexion', 'Connexion RDP depuis une machine qui n\'est pas un poste administrateur', 'PsExec sur plusieurs machines en quelques minutes'],
  },
  {
    id: 'wmi-persistence',
    title: 'WMI — Persistance et exécution distante',
    icon: '🕷️',
    severity: 'critical',
    ttps: ['T1047', 'T1546.003'],
    summary: 'Utilisation de WMI pour exécuter des commandes à distance, maintenir la persistance via des abonnements d\'événements, effectuer la collecte d\'informations et le mouvement latéral. Vecteur très discret.',
    artifacts: [
      { type: 'WMI Repository', items: ['C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA'] },
      { type: 'EVTX', items: [
        'WMIActivity/Operational — abonnements WMI',
        'DistributedCOM — connexions DCOM',
        'WinRM/Operational — exécution distante',
        '4688 : wmic.exe → wmiprvse.exe (child de WMIC)',
      ]},
      { type: 'Mémoire', items: ['wmiprvse.exe avec handles inattendus vers d\'autres processus'] },
    ],
    commands: [
      'wmic process call create "cmd /c whoami > C:\\\\temp\\\\out.txt"',
      'wmic /node:<IP> /user:<domain\\\\user> /password:<pass> process call create "cmd /c ..."',
      'wmic startup get Command,Location,User',
      'wmic /authority:"kerberos:domain\\\\hostname" /node:<IP> process call create "svchost"',
    ],
    iocs: ['wmiprvse.exe spawne cmd.exe ou powershell.exe', 'wmic.exe avec argument /node: (connexion distante)', 'mofcomp.exe exécuté par powershell.exe'],
  },
];

const SEV_STYLE = {
  critical: { bg: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)', color: 'var(--fl-danger)' },
  high:     { bg: 'color-mix(in srgb, var(--fl-warn) 8%, transparent)',   border: 'color-mix(in srgb, var(--fl-warn) 30%, transparent)',   color: 'var(--fl-warn)' },
};

const KILL_CHAIN = ['Initial Access', 'Execution', 'Persistence', 'Priv. Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'C2', 'Exfiltration', 'Impact'];

function PatternCard({ pattern, search, defaultOpen }) {
  const T = useTheme();
  const [open, setOpen] = useState(defaultOpen);
  const sev = SEV_STYLE[pattern.severity] || SEV_STYLE.high;

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return pattern.title.toLowerCase().includes(q) ||
      pattern.summary.toLowerCase().includes(q) ||
      pattern.ttps.some(t => t.toLowerCase().includes(q)) ||
      pattern.artifacts.some(a => a.items.some(i => i.toLowerCase().includes(q))) ||
      (pattern.commands || []).some(c => c.toLowerCase().includes(q)) ||
      (pattern.iocs || []).some(ioc => ioc.toLowerCase().includes(q));
  }, [search, pattern]);

  if (!matches) return null;

  return (
    <div style={{ border: `1px solid ${sev.border}`, borderRadius: 10, overflow: 'hidden', marginBottom: 12 }}>
      
      <button onClick={() => setOpen(o => !o)}
        className="w-full text-left"
        style={{ padding: '14px 18px', background: sev.bg, border: 'none', cursor: 'pointer' }}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 flex-wrap">
            <span style={{ fontSize: 18 }}>{pattern.icon}</span>
            <span className="font-mono font-bold text-sm" style={{ color: T.text }}>{pattern.title}</span>
            <div className="flex flex-wrap gap-1">
              {pattern.ttps.map(t => <MitreBadge key={t} id={t} />)}
            </div>
          </div>
          {open ? <ChevronDown size={16} style={{ color: T.dim, flexShrink: 0 }} /> : <ChevronRight size={16} style={{ color: T.dim, flexShrink: 0 }} />}
        </div>
        <p className="text-xs mt-2 ml-9" style={{ color: T.muted }}>{pattern.summary}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '16px 18px' }}>
          
          <div className="mb-4">
            <div className="text-xs font-mono font-bold uppercase tracking-widest mb-3"
              style={{ color: T.accent }}>Artefacts à rechercher</div>
            <div className="space-y-3">
              {pattern.artifacts.map(a => (
                <div key={a.type}>
                  <span style={{
                    fontSize: 10, fontFamily: 'monospace', fontWeight: 700, padding: '2px 7px',
                    borderRadius: 3, background: 'var(--fl-card)', color: T.text,
                    border: `1px solid ${T.border}`, display: 'inline-block', marginBottom: 6,
                  }}>{a.type}</span>
                  <ul className="space-y-1 ml-1">
                    {a.items.map((item, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs" style={{ color: T.text }}>
                        <span style={{ color: sev.color, marginTop: 1, flexShrink: 0 }}>›</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {pattern.commands && (
            <div className="mb-4">
              <div className="text-xs font-mono font-bold uppercase tracking-widest mb-2"
                style={{ color: T.accent }}>Commandes malveillantes connues</div>
              <div className="space-y-2">
                {pattern.commands.map((cmd, i) => (
                  <div key={i} className="flex items-center justify-between gap-3 p-2 rounded"
                    style={{ background: T.panel, border: `1px solid ${T.border}` }}>
                    <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-warn)',
                      wordBreak: 'break-all', flex: 1 }}>{cmd}</code>
                    <CopyBtn text={cmd} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {pattern.iocs && (
            <div>
              <div className="text-xs font-mono font-bold uppercase tracking-widest mb-2"
                style={{ color: T.accent }}>Indicateurs de compromission</div>
              <ul className="space-y-1">
                {pattern.iocs.map((ioc, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs p-2 rounded"
                    style={{ background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)',
                      color: T.text }}>
                    <AlertTriangle size={11} style={{ color: 'var(--fl-danger)', flexShrink: 0, marginTop: 1 }} />
                    {ioc}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackPatternsDoc({ search }) {
  const T = useTheme();

  const visibleCount = useMemo(() => {
    if (!search) return PATTERNS.length;
    const q = search.toLowerCase();
    return PATTERNS.filter(p =>
      p.title.toLowerCase().includes(q) ||
      p.summary.toLowerCase().includes(q) ||
      p.ttps.some(t => t.toLowerCase().includes(q)) ||
      p.artifacts.some(a => a.items.some(i => i.toLowerCase().includes(q))) ||
      (p.commands || []).some(c => c.toLowerCase().includes(q)) ||
      (p.iocs || []).some(ioc => ioc.toLowerCase().includes(q))
    ).length;
  }, [search]);

  return (
    <div style={{ padding: '24px 32px', maxWidth: 920 }}>
      <div className="mb-5">
        <h1 className="text-lg font-mono font-bold mb-1" style={{ color: T.text }}>
          Patterns d'Attaques
        </h1>
        <p className="text-sm" style={{ color: T.muted }}>
          {search ? `${visibleCount} pattern${visibleCount > 1 ? 's' : ''} trouvé${visibleCount > 1 ? 's' : ''}` : `${PATTERNS.length} scénarios — artefacts + TTPs + IOCs`}
        </p>
      </div>

      
      {!search && (
        <div className="mb-6 overflow-x-auto">
          <div className="flex items-center gap-0 min-w-max">
            {KILL_CHAIN.map((phase, i) => (
              <div key={phase} className="flex items-center">
                <div style={{
                  padding: '4px 10px', fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                  background: `color-mix(in srgb, var(--fl-accent) ${Math.max(8, 20 - i * 1)}%, transparent)`,
                  color: 'var(--fl-accent)',
                  border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)',
                  borderRadius: i === 0 ? '4px 0 0 4px' : i === KILL_CHAIN.length - 1 ? '0 4px 4px 0' : 0,
                  borderLeft: i > 0 ? 'none' : undefined,
                  whiteSpace: 'nowrap',
                }}>{phase}</div>
                {i < KILL_CHAIN.length - 1 && (
                  <div style={{ width: 0, height: 0, flexShrink: 0,
                    borderTop: '12px solid transparent', borderBottom: '12px solid transparent',
                    borderLeft: '7px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)',
                  }} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      
      {PATTERNS.map(p => (
        <PatternCard key={p.id} pattern={p} search={search} defaultOpen={false} />
      ))}

      {visibleCount === 0 && (
        <div className="text-center py-16" style={{ color: T.muted }}>
          <p className="text-sm font-mono">Aucun pattern ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
