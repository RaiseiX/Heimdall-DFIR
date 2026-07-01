import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, Star, Sparkles, ArrowDownUp, Search } from 'lucide-react';
import { useTheme } from '../../utils/theme';

// Open the global AI chat pre-filled with a question about an artifact.
function askAi(artifact) {
  const prompt = `Explique l'artefact forensique Windows « ${artifact.name} »`
    + (artifact.mitre?.length ? ` (MITRE ${artifact.mitre.join(', ')})` : '')
    + ` : ce qu'il contient, où le trouver, et comment l'exploiter dans une investigation DFIR.`;
  window.dispatchEvent(new CustomEvent('heimdall:ai-open', { detail: { prompt } }));
}

// MITRE technique → attack.mitre.org (handles sub-techniques like T1059.001).
function mitreUrl(id) {
  const [base, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${base}${sub ? `/${sub}` : ''}/`;
}

function CopyBtn({ text, small }) {
  const [ok, setOk] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setOk(true);
      setTimeout(() => setOk(false), 1800);
    });
  };
  const size = small ? 10 : 11;
  return (
    <button onClick={copy} title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: small ? '1px 5px' : '2px 7px',
        borderRadius: 4, fontSize: small ? 9 : 10,
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
        background: ok ? 'color-mix(in srgb, var(--fl-ok) 9%, transparent)' : 'var(--fl-card)',
        color: ok ? 'var(--fl-ok)' : 'var(--fl-dim)',
        border: `1px solid ${ok ? 'color-mix(in srgb, var(--fl-ok) 25%, transparent)' : 'var(--fl-border)'}`,
        transition: 'all .15s', flexShrink: 0,
      }}>
      {ok ? <CheckCheck size={size} /> : <Copy size={size} />}
      {!small && (ok ? 'Copié' : 'Copier')}
    </button>
  );
}

function MitreBadge({ id }) {
  return (
    <a
      href={mitreUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={e => e.stopPropagation()}
      title={`Voir ${id} sur attack.mitre.org`}
      style={{
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, fontWeight: 700,
        padding: '1px 5px', borderRadius: 3, textDecoration: 'none', cursor: 'pointer',
        background: 'color-mix(in srgb, var(--fl-accent) 15%, transparent)',
        color: 'var(--fl-accent)',
        border: '1px solid color-mix(in srgb, var(--fl-accent) 35%, transparent)',
        transition: 'background 0.12s',
      }}
      onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 28%, transparent)'; }}
      onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 15%, transparent)'; }}
    >{id}</a>
  );
}

function ToolBadge({ name }) {
  return (
    <span style={{
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9,
      padding: '1px 6px', borderRadius: 3,
      background: 'color-mix(in srgb, var(--fl-gold) 12%, transparent)',
      color: 'var(--fl-gold)',
      border: '1px solid color-mix(in srgb, var(--fl-gold) 30%, transparent)',
    }}>{name}</span>
  );
}

function Path({ value }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6,
      flexWrap: 'wrap', rowGap: 4 }}>
      <code style={{
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
        background: 'var(--fl-card)', padding: '2px 6px', borderRadius: 4,
        color: 'var(--fl-text)', border: '1px solid var(--fl-border)',
        wordBreak: 'break-all',
      }}>{value}</code>
      <CopyBtn text={value} small />
    </span>
  );
}

const ARTIFACTS = [

  {
    cat: 'Exécution de programme',
    name: 'AmCache',
    star: true,
    mitre: ['T1059'],
    tools: ['AmCacheParser (EZTools)', 'RegRipper', 'Autopsy'],
    paths: ['%SystemRoot%\\AppCompat\\Programs\\Amcache.hve'],
    content: [
      'Chemin complet de l\'exécutable',
      'Hash SHA1 de l\'exécutable',
      'Date/heure première exécution',
      'Date/heure suppression et première installation',
    ],
    note: 'Ajouté Windows 7. Depuis Windows 8 : fichier Amcache.hve',
    trigger: 'Application GUI exécutée, exécutable copié lors d\'une exécution, exécutable présent dans Program Files / Desktop',
  },
  {
    cat: 'Exécution de programme',
    name: 'ShimCache (AppCompatCache)',
    star: true,
    mitre: ['T1059'],
    tools: ['AppCompatCacheParser (EZTools)', 'ShimCacheParser (Mandiant)', 'Autopsy'],
    paths: ['HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\\AppCompatCache'],
    content: [
      'Chemin de l\'exécutable',
      'Taille et date/heure dernière modification',
      'Date/heure dernière mise à jour du cache (depuis dernier démarrage)',
    ],
    note: 'Les nouvelles entrées sont enregistrées UNIQUEMENT à l\'extinction. Limite : 1024 entrées (Win7-10), 96 (WinXP). Depuis Win10 : chemin + date modif uniquement.',
    forensic: 'Preuves de renommage de fichier ou altération du temps système',
  },
  {
    cat: 'Exécution de programme',
    name: 'Prefetch',
    star: true,
    mitre: ['T1059'],
    tools: ['PECmd (EZTools)', 'Autopsy'],
    paths: [
      '%SystemRoot%\\Prefetch\\*.pf',
      'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters',
    ],
    content: [
      'Nom de l\'exécutable (limité à 29 caractères)',
      'Nombre d\'exécutions du programme',
      'Depuis Windows 8 : 8 dernières dates d\'exécution',
      'Date/heure première exécution (≈ date création .pf ± 10s)',
      'Liste des fichiers/répertoires accédés au lancement (10 premières secondes)',
    ],
    note: 'Windows 10 conserve les 1024 derniers programmes exécutés',
  },
  {
    cat: 'Exécution de programme',
    name: 'UserAssist',
    mitre: [],
    tools: ['RECmd (EZTools)', 'RegRipper', 'Registry Explorer', 'Autopsy'],
    paths: ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist'],
    content: [
      'Date/heure de la dernière exécution d\'un programme',
      'Nombre d\'exécutions / fréquence d\'utilisation',
    ],
    note: 'Concerne uniquement les applications GUI lancées par l\'utilisateur',
  },
  {
    cat: 'Exécution de programme',
    name: 'Jump Lists',
    mitre: [],
    tools: ['JLECmd (EZTools)', 'Autopsy'],
    paths: [
      'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticdestinations-ms',
      'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.customdestinations-ms',
    ],
    content: [
      'AutomaticDestinations : généré automatiquement à chaque interaction',
      'CustomDestinations : généré quand un fichier est épinglé dans la barre des tâches',
      'Fichiers et répertoires récemment accédés par application',
    ],
    note: 'Introduit dans Windows 7',
  },
  {
    cat: 'Exécution de programme',
    name: 'RecentApps',
    mitre: [],
    tools: ['RegRipper', 'Registry Explorer'],
    paths: ['NTUSER.DAT (registre)'],
    content: ['Applications récemment utilisées par l\'utilisateur'],
    note: '',
  },

  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'ShellBags',
    star: true,
    mitre: ['T1083'],
    tools: ['ShellBags Explorer (EZTools)', 'Autopsy'],
    paths: [
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\Bags',
      'NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
      'USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',
      'USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
    ],
    content: [
      'Répertoires accédés (local, support amovible/externe, réseau)',
      'Préférences d\'affichage et position des dossiers',
      'Informations sur des répertoires supprimés (dates/heures d\'accès)',
    ],
    forensic: 'Prouve l\'accès à un dossier même après suppression',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'LastVisitedMRU',
    mitre: [],
    tools: ['Regedit', 'RegRipper', 'Registry Explorer (EZTools)'],
    paths: ['NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU'],
    content: [
      'Exécutables utilisés pour ouvrir les fichiers listés dans OpenSaveMRU',
      'Derniers chemins d\'accès accédés via boîtes de dialogue',
    ],
    note: '',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'OpenSaveMRU',
    mitre: [],
    tools: ['Regedit', 'RegRipper', 'Registry Explorer (EZTools)'],
    paths: ['NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU'],
    content: ['Fichiers récemment ouverts ou enregistrés depuis une boîte de dialogue Windows'],
    note: '',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'MFT ($MFT — Master File Table)',
    star: true,
    mitre: ['T1070.004'],
    tools: ['MFTExplorer', 'MFTECmd (EZTools)', 'Autopsy', 'FTK Imager'],
    paths: ['<Lettre de partition>:\\$MFT'],
    content: [
      'Nom et chemin complet de chaque fichier/dossier',
      'Timestamps MACB (Modified, Accessed, Changed, Born)',
      'Taille, extension, numéro d\'entrée MFT',
      'Carving possible si l\'entrée MFT et les clusters n\'ont pas été écrasés',
    ],
    note: 'Fichier supprimé → entrée marquée "unused". Référence absolue pour reconstituer l\'historique filesystem.',
    forensic: 'Référence absolue pour reconstituer l\'historique filesystem',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'RecentDocs',
    mitre: [],
    tools: ['Regedit', 'RegRipper', 'Registry Explorer (EZTools)'],
    paths: ['NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs'],
    content: [
      'Fichiers récemment ouverts depuis l\'explorateur Windows',
      'Date/heure du dernier accès/ouverture',
    ],
    note: 'Correspond aux "Éléments récents" / "Accès rapide" du menu démarrer',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'LNK (Raccourcis)',
    star: true,
    mitre: ['T1547.009'],
    tools: ['LnkExplorer (EZTools)', 'Exiftool', 'Autopsy'],
    paths: [
      'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent',
      'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Office\\Recent',
    ],
    content: [
      'Date/heure première ouverture (= date de création du fichier .lnk)',
      'Date/heure dernière ouverture (= date de modification du fichier .lnk)',
      'Nom, chemin, horodatage, taille du fichier source',
      'Numéro d\'entrée MFT du fichier source',
      'Nom du système source + informations volume / partage réseau',
    ],
    note: 'Généré automatiquement par Windows ou manuellement par l\'utilisateur',
  },
  {
    cat: 'Accès aux fichiers / répertoires',
    name: 'WebCache',
    mitre: [],
    tools: ['ESEDatabaseView (NirSoft)', 'Autopsy'],
    paths: ['C:\\Users\\<UserProfile>\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat'],
    content: [
      'Ensemble des éléments accédés depuis explorer.exe',
      'Historique de navigation IE/Edge',
    ],
    note: 'Un navigateur web est aussi un explorateur de fichiers — tout accès local y est tracé',
  },

  {
    cat: 'Autres artefacts',
    name: 'Tâches planifiées (Scheduled Tasks)',
    star: true,
    mitre: ['T1053', 'T1053.005'],
    tools: ['JobParser', 'Autopsy', 'EvtxECmd'],
    paths: [
      '%SystemRoot%\\System32\\Tasks',
      '%SystemRoot%\\SysWow64\\Tasks',
      '%SystemRoot%\\Tasks (fichiers .job)',
    ],
    content: [
      'Utilisateur ayant créé la tâche',
      'Temps de déclenchement / fréquence',
      'Programme ou commande à exécuter',
    ],
    note: 'EVTX associé : Microsoft-Windows-TaskScheduler%4Operational.evtx',
    forensic: 'Mécanisme de persistance fréquemment abusé',
  },
  {
    cat: 'Autres artefacts',
    name: 'Corbeille ($Recycle.Bin)',
    mitre: ['T1070'],
    tools: ['RBCmd (EZTools)', 'Autopsy'],
    paths: ['C:\\$Recycle.Bin\\{SID}'],
    content: [
      '$I : taille du fichier, date/heure suppression, nom original, chemin initial, SID',
      '$R : contenu réel du fichier supprimé',
    ],
    note: 'Fichier restaurable tant que la corbeille n\'est pas vidée',
  },
  {
    cat: 'Autres artefacts',
    name: 'WMI Repository',
    star: true,
    mitre: ['T1047', 'T1546.003'],
    tools: ['LogParser', 'Volatility/VolWeb', 'PowerShell', 'Sysinternals Autoruns'],
    paths: [
      'C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA',
      'C:\\Windows\\System32\\wbem\\Repository\\FS\\OBJECTS.DATA',
    ],
    content: [
      'Référentiel des abonnements WMI (persistance, exécution distante)',
      'EVTX : Microsoft-Windows-WMIActivity/Operational, DistributedCOM, WinRM/Operational',
    ],
    forensic: 'WMI = vecteur d\'attaque discret — persistence, lateral movement, exécution sans fichier sur disque',
    indicators: [
      'wmic.exe → connexion avec privilèges (Event ID 4688)',
      'mofcomp.exe utilisé par powershell.exe',
      'wmic.exe → wmiprvse.exe : usage WMI via PowerShell',
    ],
  },
];

function ArtifactCard({ artifact, search, defaultOpen, compact }) {
  const T = useTheme();
  const [open, setOpen] = useState(defaultOpen);
  const [hover, setHover] = useState(false);
  const highValue = !!artifact.forensic;

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      artifact.name.toLowerCase().includes(q) ||
      artifact.cat.toLowerCase().includes(q) ||
      artifact.paths.some(p => p.toLowerCase().includes(q)) ||
      artifact.content.some(c => c.toLowerCase().includes(q)) ||
      (artifact.note || '').toLowerCase().includes(q) ||
      (artifact.forensic || '').toLowerCase().includes(q) ||
      artifact.tools.some(t => t.toLowerCase().includes(q)) ||
      (artifact.mitre || []).some(m => m.toLowerCase().includes(q))
    );
  }, [search, artifact]);

  if (!matches) return null;

  const pad = compact ? '8px 14px' : '12px 16px';

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        border: `1px solid ${open || hover ? 'color-mix(in srgb, var(--fl-accent) 30%, var(--fl-border))' : 'var(--fl-border)'}`,
        borderRadius: 10,
        background: 'var(--fl-panel)',
        overflow: 'hidden',
        transition: 'border-color 0.14s',
      }}
    >
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full text-left"
        style={{ padding: pad, background: 'transparent', border: 'none', cursor: 'pointer' }}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            {open
              ? <ChevronDown size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
              : <ChevronRight size={14} style={{ color: hover ? 'var(--fl-dim)' : 'var(--fl-muted)', flexShrink: 0, transition: 'color 0.12s' }} />}
            <span className="font-mono font-semibold" style={{ color: 'var(--fl-text)', fontSize: compact ? 12.5 : 13.5 }}>
              {artifact.name}
            </span>
            {(artifact.mitre || []).map(m => <MitreBadge key={m} id={m} />)}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {highValue && (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600,
                padding: '1px 6px', borderRadius: 999, letterSpacing: '0.02em',
                background: 'color-mix(in srgb, var(--fl-gold) 11%, transparent)',
                color: 'var(--fl-gold)',
                border: '1px solid color-mix(in srgb, var(--fl-gold) 26%, transparent)',
              }}>
                <Star size={9} fill="currentColor" /> Haute valeur
              </span>
            )}
            {/* Ask AI — opens the global chat pre-filled */}
            <button
              onClick={(e) => { e.stopPropagation(); askAi(artifact); }}
              title="Demander à l'IA d'expliquer cet artefact"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 6,
                fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                background: 'transparent', color: hover ? 'var(--fl-accent)' : 'var(--fl-muted)',
                border: `1px solid ${hover ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
                transition: 'all 0.12s', opacity: hover || open ? 1 : 0.55,
              }}
            >
              <Sparkles size={10} /> IA
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-1 mt-2" style={{ paddingLeft: 22 }}>
          {artifact.tools.map(t => <ToolBadge key={t} name={t} />)}
        </div>
      </button>

      {open && (
        <div style={{ padding: '0 16px 16px', borderTop: `1px solid ${T.border}` }}>

          <div className="mt-3">
            <div className="text-xs font-mono font-bold uppercase tracking-widest mb-2"
              style={{ color: T.muted }}>Emplacement</div>
            <div className="space-y-1.5">
              {artifact.paths.map((p, i) => <Path key={i} value={p} />)}
            </div>
          </div>

          <div className="mt-3">
            <div className="text-xs font-mono font-bold uppercase tracking-widest mb-2"
              style={{ color: T.muted }}>Contenu</div>
            <ul className="space-y-1">
              {artifact.content.map((c, i) => (
                <li key={i} className="flex items-start gap-2 text-sm" style={{ color: T.text }}>
                  <span style={{ color: 'var(--fl-accent)', marginTop: 2, flexShrink: 0 }}>›</span>
                  {c}
                </li>
              ))}
            </ul>
          </div>

          {artifact.forensic && (
            <div className="mt-3 flex items-start gap-2 rounded-md p-2"
              style={{ background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)' }}>
              <span style={{ fontSize: 13 }}>🔎</span>
              <p className="text-xs font-mono" style={{ color: 'color-mix(in srgb, var(--fl-danger) 90%, var(--fl-text))' }}>
                {artifact.forensic}
              </p>
            </div>
          )}

          {artifact.indicators && (
            <div className="mt-3">
              <div className="text-xs font-mono font-bold uppercase tracking-widest mb-2"
                style={{ color: T.muted }}>Indicateurs clés</div>
              <ul className="space-y-1">
                {artifact.indicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2" style={{ color: T.text }}>
                    <code style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>→</code>
                    <span className="text-xs font-mono">{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {artifact.trigger && (
            <div className="mt-3">
              <div className="text-xs font-mono font-bold uppercase tracking-widest mb-1"
                style={{ color: T.muted }}>Déclencheur</div>
              <p className="text-xs" style={{ color: T.dim }}>{artifact.trigger}</p>
            </div>
          )}

          {artifact.note && (
            <div className="mt-3 flex items-start gap-2">
              <span style={{ fontSize: 11, flexShrink: 0 }}>ℹ️</span>
              <p className="text-xs" style={{ color: T.muted }}>{artifact.note}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function matchesArtifact(a, q) {
  if (!q) return true;
  q = q.toLowerCase();
  return a.name.toLowerCase().includes(q) ||
    a.cat.toLowerCase().includes(q) ||
    a.paths.some(p => p.toLowerCase().includes(q)) ||
    a.content.some(c => c.toLowerCase().includes(q)) ||
    (a.note || '').toLowerCase().includes(q) ||
    (a.forensic || '').toLowerCase().includes(q) ||
    a.tools.some(t => t.toLowerCase().includes(q)) ||
    (a.mitre || []).some(m => m.toLowerCase().includes(q));
}

export const DOC_INDEX = ARTIFACTS.map(a => ({ title: a.name, sub: a.cat }));

export default function WindowsArtifactsDoc({ search }) {
  const [hidden, setHidden] = useState(() => new Set());
  const [compact, setCompact] = useState(false);
  const [sortValue, setSortValue] = useState(false);

  const categories = useMemo(() => {
    const cats = {};
    for (const a of ARTIFACTS) {
      if (!cats[a.cat]) cats[a.cat] = [];
      cats[a.cat].push(a);
    }
    return cats;
  }, []);
  const catNames = Object.keys(categories);

  const totalVisible = useMemo(
    () => ARTIFACTS.filter(a => matchesArtifact(a, search)).length,
    [search],
  );

  const toggleCat = (cat) => setHidden(h => {
    const n = new Set(h);
    n.has(cat) ? n.delete(cat) : n.add(cat);
    return n;
  });

  // Premium toggle button used for density / sort controls.
  const Toggle = ({ active, onClick, icon: Icon, children, title }) => (
    <button onClick={onClick} title={title} style={{
      display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 11px', borderRadius: 8, cursor: 'pointer',
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
      background: active ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
      border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
      color: active ? 'var(--fl-accent)' : 'var(--fl-dim)', transition: 'all 0.12s',
    }}>
      {Icon && <Icon size={12} />} {children}
    </button>
  );

  return (
    <div style={{ padding: '26px 34px', maxWidth: 920 }}>

      {/* Editorial header */}
      <div style={{ marginBottom: 18 }}>
        <h1 style={{ fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontSize: 26, fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--fl-text)', margin: 0 }}>
          Artefacts Windows
        </h1>
        <p style={{ fontSize: 13, color: 'var(--fl-dim)', marginTop: 5, fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
          {search
            ? `${totalVisible} artefact${totalVisible > 1 ? 's' : ''} trouvé${totalVisible > 1 ? 's' : ''} pour « ${search} »`
            : `${ARTIFACTS.length} artefacts · ${catNames.length} catégories`}
          {' · '}
          <span style={{ color: 'var(--fl-gold)' }}>★ valeur forensique</span>
        </p>
      </div>

      {/* Controls: category chips + density + sort */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 22, paddingBottom: 16, borderBottom: '1px solid var(--fl-border)' }}>
        {catNames.map(cat => {
          const on = !hidden.has(cat);
          return (
            <button key={cat} onClick={() => toggleCat(cat)} style={{
              padding: '5px 11px', borderRadius: 999, cursor: 'pointer',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, letterSpacing: '0.02em',
              background: on ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
              border: `1px solid ${on ? 'color-mix(in srgb, var(--fl-accent) 28%, transparent)' : 'var(--fl-border)'}`,
              color: on ? 'var(--fl-accent)' : 'var(--fl-muted)',
              textDecoration: on ? 'none' : 'line-through', opacity: on ? 1 : 0.7, transition: 'all 0.12s',
            }}>{cat}</button>
          );
        })}
        <div style={{ flex: 1 }} />
        <Toggle active={sortValue} onClick={() => setSortValue(v => !v)} icon={ArrowDownUp} title="Trier par valeur forensique (haute valeur en premier)">Valeur</Toggle>
        <Toggle active={compact} onClick={() => setCompact(v => !v)} title="Affichage compact">{compact ? 'Compact' : 'Confort'}</Toggle>
      </div>

      {Object.entries(categories).map(([cat, items]) => {
        if (hidden.has(cat)) return null;
        const shown = items.filter(a => matchesArtifact(a, search));
        if (shown.length === 0) return null;
        const ordered = sortValue
          ? [...shown].sort((a, b) => (b.forensic ? 1 : 0) - (a.forensic ? 1 : 0))
          : shown;
        return (
          <div key={cat} style={{ marginBottom: compact ? 22 : 32 }}>
            <div className="flex items-center gap-3" style={{ marginBottom: 12 }}>
              <h2 style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.14em', color: 'var(--fl-accent)' }}>
                {cat}
              </h2>
              <div style={{ flex: 1, height: 1, background: 'var(--fl-border)' }} />
              <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)' }}>
                {shown.length}/{items.length}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: compact ? 6 : 8 }}>
              {ordered.map(a => (
                <ArtifactCard
                  key={a.name}
                  artifact={a}
                  search={search}
                  defaultOpen={false}
                  compact={compact}
                />
              ))}
            </div>
          </div>
        );
      })}

      {totalVisible === 0 && (
        <div style={{ textAlign: 'center', padding: '64px 0', color: 'var(--fl-muted)' }}>
          <Search size={28} style={{ opacity: 0.35, marginBottom: 10 }} />
          <p style={{ fontSize: 13, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Aucun artefact ne correspond à « {search} »</p>
        </div>
      )}
    </div>
  );
}
