import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight } from 'lucide-react';
import { useTheme } from '../../utils/theme';

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1800); }); }}
      title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        width: 20, height: 20, borderRadius: 4, cursor: 'pointer', flexShrink: 0,
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
      }}>
      {ok ? <CheckCheck size={10} /> : <Copy size={10} />}
    </button>
  );
}

function MitreBadge({ id }) {
  if (!id) return null;
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

const SEV_COLORS = {
  '🔴 CRITICAL': { bg: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', color: 'var(--fl-danger)', border: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' },
  '🟠 HIGH':     { bg: 'color-mix(in srgb, var(--fl-warn) 10%, transparent)',   color: 'var(--fl-warn)',   border: 'color-mix(in srgb, var(--fl-warn) 30%, transparent)' },
  '🟡 MEDIUM':   { bg: 'color-mix(in srgb, var(--fl-gold) 10%, transparent)',   color: 'var(--fl-gold)',   border: 'color-mix(in srgb, var(--fl-gold) 30%, transparent)' },
  '🟢 INFO':     { bg: 'color-mix(in srgb, #22c55e 8%, transparent)',           color: '#22c55e',          border: 'color-mix(in srgb, #22c55e 25%, transparent)' },
};

function SevBadge({ level }) {
  const c = SEV_COLORS[level] || SEV_COLORS['🟢 INFO'];
  return (
    <span style={{
      fontSize: 9, fontFamily: 'monospace', fontWeight: 700, whiteSpace: 'nowrap',
      padding: '2px 6px', borderRadius: 3,
      background: c.bg, color: c.color, border: `1px solid ${c.border}`,
    }}>{level}</span>
  );
}

const EVTX_FILES = [
  { file: 'Security.evtx', desc: 'Événements de sécurité' },
  { file: 'System.evtx', desc: 'Activité système' },
  { file: 'Microsoft-Windows-Powershell%4Operational.evtx', desc: 'Activité PowerShell' },
  { file: 'Microsoft-Windows-TaskScheduler%4Operational.evtx', desc: 'Tâches planifiées' },
  { file: 'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx', desc: 'Terminal Services (session locale)' },
  { file: 'Microsoft-Windows-TerminalServicesRDPClient%4Operational.evtx', desc: 'Terminal Services (client RDP)' },
  { file: 'Microsoft-Windows-TerminalServicesRemoteConnectionManager%4Operational.evtx', desc: 'Terminal Services (remote)' },
  { file: 'Microsoft-Windows-SmbClient%4Security.evtx', desc: 'Activité SMB' },
  { file: 'Microsoft-Windows-WinRM%4Operational.evtx', desc: 'Activité WinRM' },
  { file: 'Microsoft-Windows-WMIActivity/Operational.evtx', desc: 'Activité WMI' },
];

const SECURITY_EVENTS = [
  { id: '1102', desc: 'Journal d\'audit effacé', mitre: 'T1070.001', sev: '🔴 CRITICAL' },
  { id: '4624', desc: 'Logon réussi', mitre: 'T1078', sev: '🟡 HIGH' },
  { id: '4625', desc: 'Logon échoué', mitre: 'T1110', sev: '🟡 HIGH' },
  { id: '4634', desc: 'Logoff', mitre: null, sev: '🟢 INFO' },
  { id: '4647', desc: 'User initiated logoff', mitre: null, sev: '🟢 INFO' },
  { id: '4648', desc: 'Logon avec credentials explicites (RunAs / Pass-the-Hash)', mitre: 'T1550.002', sev: '🔴 CRITICAL' },
  { id: '4662', desc: 'Accès à objet AD (DCSync)', mitre: 'T1003.006', sev: '🔴 CRITICAL' },
  { id: '4672', desc: 'Privilège spécial assigné', mitre: 'T1078.003', sev: '🟠 HIGH' },
  { id: '4674', desc: 'Opération sur objet privilégié', mitre: 'T1078', sev: '🟡 MEDIUM' },
  { id: '4688', desc: 'Nouveau processus créé', mitre: 'T1059', sev: '🟡 HIGH' },
  { id: '4697', desc: 'Service installé', mitre: 'T1543.003', sev: '🔴 CRITICAL' },
  { id: '4698', desc: 'Tâche planifiée créée', mitre: 'T1053.005', sev: '🔴 CRITICAL' },
  { id: '4699', desc: 'Tâche planifiée supprimée', mitre: 'T1070', sev: '🟠 HIGH' },
  { id: '4700', desc: 'Tâche planifiée activée', mitre: 'T1053', sev: '🟡 MEDIUM' },
  { id: '4701', desc: 'Tâche planifiée désactivée', mitre: 'T1053', sev: '🟡 MEDIUM' },
  { id: '4702', desc: 'Tâche planifiée modifiée', mitre: 'T1053', sev: '🟠 HIGH' },
  { id: '4720', desc: 'Compte utilisateur créé', mitre: 'T1136', sev: '🔴 CRITICAL' },
  { id: '4722', desc: 'Compte utilisateur activé', mitre: 'T1078', sev: '🟠 HIGH' },
  { id: '4724', desc: 'Tentative reset mot de passe', mitre: 'T1531', sev: '🟠 HIGH' },
  { id: '4725', desc: 'Compte désactivé', mitre: 'T1531', sev: '🟡 MEDIUM' },
  { id: '4726', desc: 'Compte supprimé', mitre: 'T1070', sev: '🟠 HIGH' },
  { id: '4728', desc: 'Membre ajouté à groupe global', mitre: 'T1098', sev: '🔴 CRITICAL' },
  { id: '4732', desc: 'Membre ajouté à groupe local', mitre: 'T1098', sev: '🔴 CRITICAL' },
  { id: '4756', desc: 'Membre ajouté à groupe universel', mitre: 'T1098', sev: '🔴 CRITICAL' },
  { id: '4768', desc: 'Kerberos TGT demandé (AS-REQ)', mitre: 'T1558.003', sev: '🟡 MEDIUM' },
  { id: '4769', desc: 'Kerberos TGS demandé', mitre: 'T1558.003', sev: '🟠 HIGH' },
  { id: '4771', desc: 'Kerberos pre-auth échouée', mitre: 'T1110', sev: '🟠 HIGH' },
  { id: '4776', desc: 'NTLM authentication', mitre: 'T1550.002', sev: '🟡 MEDIUM' },
  { id: '4798', desc: 'Groupe local d\'un user énuméré', mitre: 'T1087', sev: '🟡 MEDIUM' },
  { id: '4799', desc: 'Groupe local énuméré', mitre: 'T1087', sev: '🟡 MEDIUM' },
];

const SYSTEM_EVENTS = [
  { id: '104',  desc: 'Journal de log effacé',                     mitre: null,       sev: '🔴 CRITICAL' },
  { id: '1074', desc: 'Redémarrage initié par un processus',        mitre: null,       sev: '🟡 MEDIUM' },
  { id: '6005', desc: 'Service Event Log démarré (= boot système)', mitre: null,       sev: '🟢 INFO' },
  { id: '6006', desc: 'Service Event Log arrêté (= shutdown)',      mitre: null,       sev: '🟢 INFO' },
  { id: '6013', desc: 'Uptime système',                             mitre: null,       sev: '🟢 INFO' },
  { id: '7030', desc: 'Erreur création service',                    mitre: null,       sev: '🟡 MEDIUM' },
  { id: '7034', desc: 'Service crashé de manière inattendue',       mitre: null,       sev: '🟠 HIGH' },
  { id: '7035', desc: 'Start/Stop d\'un service',                   mitre: null,       sev: '🟢 INFO' },
  { id: '7036', desc: 'Service démarré ou arrêté',                  mitre: null,       sev: '🟢 INFO' },
  { id: '7045', desc: 'Nouveau service installé',                   mitre: 'T1543.003',sev: '🔴 CRITICAL' },
];

const PS_EVENTS = [
  { id: '4103',  desc: 'Script Block Logging — contenu du bloc PS exécuté', mitre: 'T1059.001', sev: '🔴 CRITICAL' },
  { id: '4104',  desc: 'Creating Scriptblock text — code PowerShell complet', mitre: 'T1059.001', sev: '🔴 CRITICAL' },
  { id: '8193',  desc: 'Session PowerShell créée',       mitre: null, sev: '🟡 MEDIUM' },
  { id: '8194',  desc: 'Session PowerShell créée',       mitre: null, sev: '🟡 MEDIUM' },
  { id: '8197',  desc: 'Session PowerShell fermée',      mitre: null, sev: '🟢 INFO' },
  { id: '40961', desc: 'Console PS démarrée (initiation)', mitre: null, sev: '🟡 MEDIUM' },
  { id: '40962', desc: 'Console PS démarrée (compte)',   mitre: null, sev: '🟡 MEDIUM' },
  { id: '53504', desc: 'Authentification utilisateur via PS IPC thread', mitre: null, sev: '🟡 MEDIUM' },
];

const TASK_EVENTS = [
  { id: '106', desc: 'Tâche planifiée enregistrée',         mitre: 'T1053.005', sev: '🔴 CRITICAL' },
  { id: '140', desc: 'Tâche planifiée mise à jour',         mitre: 'T1053',     sev: '🟠 HIGH' },
  { id: '141', desc: 'Tâche planifiée supprimée',           mitre: 'T1070',     sev: '🟠 HIGH' },
  { id: '200', desc: 'Action de tâche lancée',              mitre: null,        sev: '🟡 MEDIUM' },
  { id: '201', desc: 'Tâche complétée avec succès',         mitre: null,        sev: '🟢 INFO' },
  { id: '310', desc: 'Task engine démarré',                 mitre: null,        sev: '🟢 INFO' },
  { id: '319', desc: 'Message de lancement reçu',           mitre: null,        sev: '🟢 INFO' },
];

const RDP_EVENTS = [
  { id: '21',    canal: 'LocalSessionManager',    desc: 'Session logon succeeded',               mitre: 'T1021.001', sev: '🟡 HIGH' },
  { id: '22',    canal: 'LocalSessionManager',    desc: 'Shell start notification received',     mitre: null,        sev: '🟢 INFO' },
  { id: '24',    canal: 'LocalSessionManager',    desc: 'Session disconnected',                  mitre: null,        sev: '🟢 INFO' },
  { id: '25',    canal: 'LocalSessionManager',    desc: 'Session reconnection succeeded',        mitre: null,        sev: '🟡 MEDIUM' },
  { id: '40',    canal: 'LocalSessionManager',    desc: 'Session disconnected (code raison)',    mitre: null,        sev: '🟡 MEDIUM' },
  { id: '91',    canal: 'WinRM',                  desc: 'WinRM Session creation',                mitre: 'T1021.006', sev: '🟠 HIGH' },
  { id: '168',   canal: 'WinRM',                  desc: 'WinRM Session creation — user authenticated', mitre: 'T1021.006', sev: '🟠 HIGH' },
  { id: '1024',  canal: 'RDPClient',              desc: 'Tentative de connexion vers serveur',   mitre: 'T1021.001', sev: '🟡 MEDIUM' },
  { id: '1025',  canal: 'RDPClient',              desc: 'Connexion RDP établie',                 mitre: 'T1021.001', sev: '🟡 MEDIUM' },
  { id: '1026',  canal: 'RDPClient',              desc: 'Connexion RDP fermée',                  mitre: null,        sev: '🟢 INFO' },
  { id: '1149',  canal: 'RemoteConnectionManager',desc: 'User authentication succeeded',         mitre: 'T1021.001', sev: '🟠 HIGH' },
  { id: '31001', canal: 'SMBClient',              desc: 'Logon SMB échoué vers destination',     mitre: 'T1021.002', sev: '🟠 HIGH' },
];

const LOGON_TYPES = [
  { type: '2',  name: 'Interactive',       desc: 'Connexion physique clavier',                       signal: 'Normal' },
  { type: '3',  name: 'Network',           desc: 'Accès réseau (SMB, WMI)',                          signal: '⚠️ Surveiller sources inhabituelles' },
  { type: '4',  name: 'Batch',             desc: 'Tâche planifiée',                                  signal: 'Vérifier la tâche associée' },
  { type: '5',  name: 'Service',           desc: 'Service Windows',                                  signal: 'Vérifier le service' },
  { type: '7',  name: 'Unlock',            desc: 'Déverrouillage écran',                             signal: '—' },
  { type: '8',  name: 'NetworkCleartext',  desc: 'Credentials en clair sur le réseau',               signal: '🔴 Alerte immédiate' },
  { type: '9',  name: 'NewCredentials',    desc: 'RunAs /netonly',                                   signal: '⚠️ Surveiller' },
  { type: '10', name: 'RemoteInteractive', desc: 'RDP / Terminal Services',                          signal: '⚠️ Surveiller sources externes' },
  { type: '11', name: 'CachedInteractive', desc: 'Connexion hors ligne (cache)',                     signal: '—' },
];

function EventTable({ events, search, showCanal }) {
  const T = useTheme();
  const filtered = useMemo(() => {
    if (!search) return events;
    const q = search.toLowerCase();
    return events.filter(e =>
      e.id.includes(q) ||
      e.desc.toLowerCase().includes(q) ||
      (e.mitre || '').toLowerCase().includes(q) ||
      (e.canal || '').toLowerCase().includes(q) ||
      (e.sev || '').toLowerCase().includes(q)
    );
  }, [events, search]);

  if (!filtered.length) return null;

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
      <thead>
        <tr style={{ background: 'var(--fl-card)' }}>
          <th style={{ padding: '8px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
            color: T.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
            borderBottom: `1px solid ${T.border}`, width: 90 }}>Event ID</th>
          {showCanal && (
            <th style={{ padding: '8px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
              color: T.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
              borderBottom: `1px solid ${T.border}`, width: 180 }}>Canal</th>
          )}
          <th style={{ padding: '8px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
            color: T.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
            borderBottom: `1px solid ${T.border}` }}>Description</th>
          <th style={{ padding: '8px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
            color: T.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
            borderBottom: `1px solid ${T.border}`, width: 100 }}>MITRE</th>
          <th style={{ padding: '8px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
            color: T.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
            borderBottom: `1px solid ${T.border}`, width: 120 }}>Criticité</th>
        </tr>
      </thead>
      <tbody>
        {filtered.map((e, i) => (
          <tr key={e.id}
            style={{ background: i % 2 === 0 ? 'transparent' : `${T.panel}88`,
              borderBottom: `1px solid ${T.border}22` }}>
            <td style={{ padding: '8px 10px' }}>
              <div className="flex items-center gap-2">
                <code style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700,
                  color: T.accent }}>{e.id}</code>
                <CopyBtn text={e.id} />
              </div>
            </td>
            {showCanal && (
              <td style={{ padding: '8px 10px' }}>
                <code style={{ fontFamily: 'monospace', fontSize: 10, color: T.muted }}>{e.canal}</code>
              </td>
            )}
            <td style={{ padding: '8px 10px', color: T.text }}>{e.desc}</td>
            <td style={{ padding: '8px 10px' }}>
              {e.mitre && <MitreBadge id={e.mitre} />}
            </td>
            <td style={{ padding: '8px 10px' }}>
              <SevBadge level={e.sev} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Section({ title, subtitle, children, defaultOpen = true }) {
  const T = useTheme();
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="mb-6" style={{ border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden' }}>
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between text-left"
        style={{ padding: '14px 18px', background: T.panel, border: 'none', cursor: 'pointer' }}>
        <div>
          <span className="font-mono font-bold text-sm" style={{ color: T.text }}>{title}</span>
          {subtitle && <span className="text-xs ml-2" style={{ color: T.muted }}>{subtitle}</span>}
        </div>
        {open ? <ChevronDown size={14} style={{ color: T.dim }} /> : <ChevronRight size={14} style={{ color: T.dim }} />}
      </button>
      {open && (
        <div style={{ background: T.bg }}>
          {children}
        </div>
      )}
    </div>
  );
}

export default function EventIdsDoc({ search }) {
  const T = useTheme();

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1000 }}>
      <div className="mb-6">
        <h1 className="text-lg font-mono font-bold mb-1" style={{ color: T.text }}>
          Event IDs Windows
        </h1>
        <p className="text-sm" style={{ color: T.muted }}>
          Référence complète des Event IDs forensiques · 5 sources EVTX
        </p>
      </div>

      <Section title="Fichiers EVTX — Priorité de collecte" subtitle={`${EVTX_FILES.length} fichiers`}>
        <div style={{ padding: '16px 18px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr>
                <th style={{ padding: '6px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
                  color: T.muted, fontWeight: 700, textTransform: 'uppercase',
                  borderBottom: `1px solid ${T.border}` }}>Description</th>
                <th style={{ padding: '6px 10px', textAlign: 'left', fontFamily: 'monospace', fontSize: 10,
                  color: T.muted, fontWeight: 700, textTransform: 'uppercase',
                  borderBottom: `1px solid ${T.border}` }}>Fichier EVTX</th>
              </tr>
            </thead>
            <tbody>
              {EVTX_FILES.filter(f => !search || f.file.toLowerCase().includes(search.toLowerCase()) || f.desc.toLowerCase().includes(search.toLowerCase())).map((f, i) => (
                <tr key={f.file} style={{ background: i % 2 === 0 ? 'transparent' : `${T.panel}88`,
                  borderBottom: `1px solid ${T.border}22` }}>
                  <td style={{ padding: '8px 10px', color: T.text }}>{f.desc}</td>
                  <td style={{ padding: '8px 10px' }}>
                    <div className="flex items-center gap-2">
                      <code style={{ fontFamily: 'monospace', fontSize: 11, color: T.dim,
                        wordBreak: 'break-all' }}>{f.file}</code>
                      <CopyBtn text={f.file} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Security.evtx" subtitle="Événements de sécurité">
        <div style={{ overflowX: 'auto' }}>
          <EventTable events={SECURITY_EVENTS} search={search} />
        </div>
        
        <div style={{ padding: '16px 18px', borderTop: `1px solid ${T.border}` }}>
          <div className="text-xs font-mono font-bold uppercase tracking-widest mb-3"
            style={{ color: T.accent }}>Logon Types (4624 / 4625)</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'var(--fl-card)' }}>
                {['Type', 'Nom', 'Description', 'Signal'].map(h => (
                  <th key={h} style={{ padding: '6px 10px', textAlign: 'left', fontFamily: 'monospace',
                    fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase',
                    borderBottom: `1px solid ${T.border}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {LOGON_TYPES.filter(lt => !search ||
                lt.type.includes(search) ||
                lt.name.toLowerCase().includes(search.toLowerCase()) ||
                lt.desc.toLowerCase().includes(search.toLowerCase())
              ).map((lt, i) => (
                <tr key={lt.type} style={{ background: i % 2 === 0 ? 'transparent' : `${T.panel}88`,
                  borderBottom: `1px solid ${T.border}22` }}>
                  <td style={{ padding: '7px 10px' }}>
                    <div className="flex items-center gap-2">
                      <code style={{ fontFamily: 'monospace', fontWeight: 700, color: T.accent }}>
                        Type {lt.type}
                      </code>
                      <CopyBtn text={lt.type} />
                    </div>
                  </td>
                  <td style={{ padding: '7px 10px', fontFamily: 'monospace', fontSize: 11, color: T.text }}>{lt.name}</td>
                  <td style={{ padding: '7px 10px', color: T.text }}>{lt.desc}</td>
                  <td style={{ padding: '7px 10px', color: lt.signal.includes('🔴') ? 'var(--fl-danger)' : lt.signal.includes('⚠️') ? 'var(--fl-warn)' : T.muted, fontSize: 11 }}>{lt.signal}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="System.evtx" subtitle="Événements système">
        <div style={{ overflowX: 'auto' }}>
          <EventTable events={SYSTEM_EVENTS} search={search} />
        </div>
      </Section>

      <Section title="Microsoft-Windows-Powershell%4Operational.evtx" subtitle="Activité PowerShell">
        <div style={{ overflowX: 'auto' }}>
          <EventTable events={PS_EVENTS} search={search} />
        </div>
      </Section>

      <Section title="Microsoft-Windows-TaskScheduler%4Operational.evtx" subtitle="Tâches planifiées">
        <div style={{ overflowX: 'auto' }}>
          <EventTable events={TASK_EVENTS} search={search} />
        </div>
      </Section>

      <Section title="Terminal Services / RDP / WinRM / SMB" subtitle="Mouvements latéraux">
        <div style={{ overflowX: 'auto' }}>
          <EventTable events={RDP_EVENTS} search={search} showCanal />
        </div>
      </Section>
    </div>
  );
}
