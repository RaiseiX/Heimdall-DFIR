import { useState, useMemo } from 'react';
import { Copy, CheckCheck } from 'lucide-react';
import { useTheme } from '../../utils/theme';

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1800); }); }}
      title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 7px', borderRadius: 4, cursor: 'pointer',
        fontSize: 10, fontFamily: 'monospace', flexShrink: 0,
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
      }}>
      {ok ? <CheckCheck size={10} /> : <Copy size={10} />}
      {ok ? 'Copié' : 'Copier'}
    </button>
  );
}

function CodeBlock({ cmd, desc }) {
  const T = useTheme();
  return (
    <div style={{
      background: T.panel, border: `1px solid ${T.border}`, borderRadius: 6,
      padding: '10px 14px', display: 'flex', alignItems: 'flex-start',
      justifyContent: 'space-between', gap: 12,
    }}>
      <div>
        <code style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--fl-accent)', display: 'block' }}>
          {cmd}
        </code>
        {desc && <p style={{ fontSize: 11, color: T.muted, marginTop: 3 }}>{desc}</p>}
      </div>
      <CopyBtn text={cmd} />
    </div>
  );
}

const RESIDUAL_FILES = [
  { file: 'C:\\hiberfil.sys',  desc: 'Image d\'hibernation — snapshot RAM complet (si hibernation activée)' },
  { file: 'C:\\pagefile.sys',  desc: 'Mémoire virtuelle paginée — fragments de processus, strings, parfois clés' },
  { file: 'C:\\swapfile.sys',  desc: 'Swap Windows 8+ pour apps Modern UI (Store)' },
];

const ACQ_TOOLS = [
  { tool: 'FTK Imager',       os: 'Windows', note: 'Gratuit — collecte RAM + artefacts disque' },
  { tool: 'DumpIt (Magnet)',   os: 'Windows', note: 'Gratuit — résultats équivalents à FTK Imager' },
  { tool: 'KAPE',              os: 'Windows', note: 'Peut collecter RAM en même temps que les artefacts' },
  { tool: 'LiME',              os: 'Linux',   note: 'Module kernel — collecte RAM Linux' },
  { tool: 'AVML (Microsoft)',  os: 'Linux',   note: 'Compatible Azure Blob, open source' },
  { tool: 'EDR / XDR',        os: 'Win/Lin', note: 'Acquisition partielle — premiers éléments rapides' },
  { tool: 'dd',               os: 'Linux',   note: 'Commande native — copie volume/mémoire' },
];

const USE_CASES = [
  { obj: 'Clés de déchiffrement', desc: 'Récupérer les clés en mémoire pour déchiffrer des données ransomware' },
  { obj: 'Malware fileless',      desc: 'Extraire un exécutable suspect absent du disque dur' },
  { obj: 'Connexions actives',    desc: 'Identifier des connexions réseau au moment du dump (exfiltration)' },
  { obj: 'Anti-analyse',          desc: 'Détecter process hollowing, injection de code, contre-mesures forensiques' },
];

const VOL3_PROCESS = [
  { cmd: 'windows.pslist',       desc: 'Liste les processus depuis la structure EPROCESS en mémoire' },
  { cmd: 'windows.psscan',       desc: 'Scanne la mémoire physique (détecte processus cachés non listés dans pslist)' },
  { cmd: 'windows.pstree',       desc: 'Arborescence parent/enfant — détecter les parents anormaux' },
  { cmd: 'windows.malprocfind',  desc: 'Détection automatique de processus système suspects (parent anormal)' },
  { cmd: 'windows.processbl',    desc: 'Comparaison processus + DLLs chargés avec une baseline légitime' },
  { cmd: 'windows.servicebl',    desc: 'Baseline des services' },
  { cmd: 'windows.driverbl',     desc: 'Baseline des drivers/pilotes' },
];

const VOL3_INJECTION = [
  { cmd: 'windows.ldrmodules',  desc: 'Détecte les DLLs non liées et fichiers non mappés en mémoire' },
  { cmd: 'windows.malfind',     desc: 'Recherche injections de code cachées + dump des sections affectées' },
  { cmd: 'windows.hollowfind', desc: 'Traces de techniques de process hollowing connues' },
  { cmd: 'windows.threadmap',   desc: 'Analyse threads pour contre-mesures forensiques (process hollowing)' },
];

const VOL3_NETWORK = [
  { cmd: 'windows.netstat', desc: 'Connexions réseau actives au moment du dump' },
  { cmd: 'windows.netscan', desc: 'Scan élargi (inclut connexions récemment terminées)' },
];

const VOL3_EXTRA = [
  { cmd: 'windows.cmdline',        desc: 'Ligne de commande de chaque processus en mémoire' },
  { cmd: 'windows.dlllist',        desc: 'DLLs chargées par processus' },
  { cmd: 'windows.handles',        desc: 'Handles ouverts par processus (fichiers, registre, objets)' },
  { cmd: 'windows.filescan',       desc: 'Scan des objets FILE_OBJECT en mémoire' },
  { cmd: 'windows.dumpfiles',      desc: 'Extraire des fichiers depuis la mémoire' },
  { cmd: 'windows.registry.hivelist', desc: 'Liste les ruches registre chargées en mémoire' },
  { cmd: 'windows.hashdump',       desc: 'Extraire les hashes NTLM depuis la mémoire (LSASS)' },
  { cmd: 'windows.cachedump',      desc: 'Extraire les credentials mis en cache' },
  { cmd: 'windows.lsadump',        desc: 'Extraire les secrets LSA' },
];

const EPROCESS_DIAGRAM = `KDBG
  └─ EPROCESS
       ├─ Process Environment Block (PEB) → .exe + .dll chargés
       ├─ Handles → Object 1, Object 2...
       ├─ Access Token → SID, Group SID
       └─ Threads → Thread 1, Thread 2...`;

function SectionTitle({ children }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <h2 className="text-sm font-mono font-bold uppercase tracking-widest"
        style={{ color: 'var(--fl-accent)' }}>{children}</h2>
      <div style={{ flex: 1, height: 1, background: 'var(--fl-border)' }} />
    </div>
  );
}

export default function MemoryForensicsDoc({ search }) {
  const T = useTheme();

  const filter = (str) => !search || str.toLowerCase().includes(search.toLowerCase());

  return (
    <div style={{ padding: '24px 32px', maxWidth: 900 }}>
      <div className="mb-6">
        <h1 className="text-lg font-mono font-bold mb-1" style={{ color: T.text }}>
          Analyse Mémoire Forensique
        </h1>
        <p className="text-sm" style={{ color: T.muted }}>
          Acquisition RAM · Volatility 3 · Fichiers résiduels
        </p>
      </div>

      <div className="mb-8">
        <SectionTitle>Quand collecter la RAM ?</SectionTitle>
        <div className="space-y-2">
          {[
            { icon: '✅', text: 'Machine NON éteinte — les données volatiles sont perdues à l\'extinction' },
            { icon: '✅', text: 'Machine virtuelle mise en pause / snapshot' },
            { icon: '⚠️', text: 'Si machine éteinte : chercher les fichiers résiduels sur disque (hiberfil.sys, pagefile.sys)' },
          ].filter(i => filter(i.text)).map((item, i) => (
            <div key={i} className="flex items-start gap-3 p-3 rounded-lg"
              style={{ background: T.panel, border: `1px solid ${T.border}` }}>
              <span>{item.icon}</span>
              <span className="text-sm" style={{ color: T.text }}>{item.text}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="mb-8">
        <SectionTitle>Fichiers mémoire résiduels sur disque</SectionTitle>
        <div className="space-y-2">
          {RESIDUAL_FILES.filter(f => filter(f.file) || filter(f.desc)).map(f => (
            <div key={f.file} className="p-3 rounded-lg"
              style={{ background: T.panel, border: `1px solid ${T.border}` }}>
              <div className="flex items-center gap-2 mb-1">
                <code style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700,
                  color: 'var(--fl-accent)' }}>{f.file}</code>
                <CopyBtn text={f.file} />
              </div>
              <p className="text-xs" style={{ color: T.muted }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="mb-8">
        <SectionTitle>Cas d'usage justifiant une analyse mémoire</SectionTitle>
        <div className="grid grid-cols-2 gap-3">
          {USE_CASES.filter(u => filter(u.obj) || filter(u.desc)).map(u => (
            <div key={u.obj} className="p-3 rounded-lg"
              style={{ background: T.panel, border: `1px solid color-mix(in srgb, var(--fl-accent) 25%, var(--fl-border))` }}>
              <p className="text-sm font-mono font-semibold mb-1" style={{ color: T.accent }}>{u.obj}</p>
              <p className="text-xs" style={{ color: T.muted }}>{u.desc}</p>
            </div>
          ))}
        </div>
      </div>

      
      <div className="mb-8">
        <SectionTitle>Outils d'acquisition RAM</SectionTitle>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: 'var(--fl-card)' }}>
              {['Outil', 'OS', 'Notes'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontFamily: 'monospace',
                  fontSize: 10, color: T.muted, fontWeight: 700, textTransform: 'uppercase',
                  borderBottom: `1px solid ${T.border}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ACQ_TOOLS.filter(t => filter(t.tool) || filter(t.os) || filter(t.note)).map((t, i) => (
              <tr key={t.tool} style={{ background: i % 2 === 0 ? 'transparent' : `${T.panel}88`,
                borderBottom: `1px solid ${T.border}22` }}>
                <td style={{ padding: '8px 12px' }}>
                  <span className="font-mono font-semibold" style={{ color: T.text }}>{t.tool}</span>
                </td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 10, padding: '1px 6px',
                    borderRadius: 3, background: 'var(--fl-card)', color: T.muted,
                    border: `1px solid ${T.border}` }}>{t.os}</span>
                </td>
                <td style={{ padding: '8px 12px', color: T.muted }}>{t.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filter('EPROCESS') && filter('pslist') ? (
        <div className="mb-8">
          <SectionTitle>Structure EPROCESS — pslist vs psscan</SectionTitle>
          <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
            <pre style={{
              fontFamily: 'monospace', fontSize: 12, padding: '16px',
              background: T.panel, color: T.text, margin: 0, overflowX: 'auto',
              lineHeight: 1.7,
            }}>{EPROCESS_DIAGRAM}</pre>
          </div>
          <div className="mt-3 space-y-2">
            <div className="flex items-start gap-2 p-3 rounded-lg"
              style={{ background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)' }}>
              <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-accent)', flexShrink: 0 }}>pslist</code>
              <span className="text-xs" style={{ color: T.text }}>Parcourt la liste chaînée EPROCESS → un rootkit peut se cacher en se détachant de cette liste</span>
            </div>
            <div className="flex items-start gap-2 p-3 rounded-lg"
              style={{ background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)' }}>
              <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-danger)', flexShrink: 0 }}>psscan</code>
              <span className="text-xs" style={{ color: T.text }}>Scanne la mémoire physique brute → détecte les processus cachés même s'ils sont absents de la liste chaînée</span>
            </div>
          </div>
        </div>
      ) : null}

      
      <div className="mb-8">
        <SectionTitle>Volatility 3 — Processus suspects (Rogue Processes)</SectionTitle>
        <div className="space-y-2">
          {VOL3_PROCESS.filter(c => filter(c.cmd) || filter(c.desc)).map(c => (
            <CodeBlock key={c.cmd} cmd={`vol.py -f dump.mem ${c.cmd}`} desc={c.desc} />
          ))}
        </div>
      </div>

      <div className="mb-8">
        <SectionTitle>Volatility 3 — Injection de code</SectionTitle>
        <div className="space-y-2">
          {VOL3_INJECTION.filter(c => filter(c.cmd) || filter(c.desc)).map(c => (
            <CodeBlock key={c.cmd} cmd={`vol.py -f dump.mem ${c.cmd}`} desc={c.desc} />
          ))}
        </div>
      </div>

      <div className="mb-8">
        <SectionTitle>Volatility 3 — Réseau</SectionTitle>
        <div className="space-y-2">
          {VOL3_NETWORK.filter(c => filter(c.cmd) || filter(c.desc)).map(c => (
            <CodeBlock key={c.cmd} cmd={`vol.py -f dump.mem ${c.cmd}`} desc={c.desc} />
          ))}
        </div>
      </div>

      <div className="mb-8">
        <SectionTitle>Volatility 3 — Credentials & Fichiers</SectionTitle>
        <div className="space-y-2">
          {VOL3_EXTRA.filter(c => filter(c.cmd) || filter(c.desc)).map(c => (
            <CodeBlock key={c.cmd} cmd={`vol.py -f dump.mem ${c.cmd}`} desc={c.desc} />
          ))}
        </div>
      </div>
    </div>
  );
}
