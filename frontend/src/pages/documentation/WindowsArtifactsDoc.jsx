import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, Star } from 'lucide-react';
import { useTheme } from '../../utils/theme';

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
        fontFamily: 'monospace', cursor: 'pointer',
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
        transition: 'all .15s', flexShrink: 0,
      }}>
      {ok ? <CheckCheck size={size} /> : <Copy size={size} />}
      {!small && (ok ? 'Copié' : 'Copier')}
    </button>
  );
}

function MitreBadge({ id }) {
  return (
    <span style={{
      fontFamily: 'monospace', fontSize: 9, fontWeight: 700,
      padding: '1px 5px', borderRadius: 3,
      background: 'color-mix(in srgb, var(--fl-accent) 15%, transparent)',
      color: 'var(--fl-accent)',
      border: '1px solid color-mix(in srgb, var(--fl-accent) 35%, transparent)',
    }}>{id}</span>
  );
}

function ToolBadge({ name }) {
  return (
    <span style={{
      fontFamily: 'monospace', fontSize: 9,
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
        fontFamily: 'monospace', fontSize: 11,
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

function ArtifactCard({ artifact, search, defaultOpen }) {
  const T = useTheme();
  const [open, setOpen] = useState(defaultOpen);

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

  return (
    <div style={{
      border: `1px solid ${artifact.star ? 'color-mix(in srgb, var(--fl-accent) 35%, var(--fl-border))' : T.border}`,
      borderRadius: 8,
      background: T.panel,
      overflow: 'hidden',
    }}>
      
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full text-left"
        style={{ padding: '12px 16px', background: 'transparent', border: 'none', cursor: 'pointer' }}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            {artifact.star && (
              <Star size={12} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} fill="currentColor" />
            )}
            <span className="font-mono font-semibold text-sm" style={{ color: T.text }}>
              {artifact.name}
            </span>
            {(artifact.mitre || []).map(m => <MitreBadge key={m} id={m} />)}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {artifact.forensic && (
              <span style={{
                fontSize: 9, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)',
                color: 'var(--fl-danger)',
                border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)',
              }}>Haute valeur</span>
            )}
            {open ? <ChevronDown size={14} style={{ color: T.dim }} /> : <ChevronRight size={14} style={{ color: T.dim }} />}
          </div>
        </div>
        
        <div className="flex flex-wrap gap-1 mt-2">
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
                    <code style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-warn)' }}>→</code>
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

export default function WindowsArtifactsDoc({ search }) {
  const T = useTheme();

  const categories = useMemo(() => {
    const cats = {};
    for (const a of ARTIFACTS) {
      if (!cats[a.cat]) cats[a.cat] = [];
      cats[a.cat].push(a);
    }
    return cats;
  }, []);

  const totalVisible = useMemo(() => {
    if (!search) return ARTIFACTS.length;
    const q = search.toLowerCase();
    return ARTIFACTS.filter(a =>
      a.name.toLowerCase().includes(q) ||
      a.cat.toLowerCase().includes(q) ||
      a.paths.some(p => p.toLowerCase().includes(q)) ||
      a.content.some(c => c.toLowerCase().includes(q)) ||
      (a.note || '').toLowerCase().includes(q) ||
      a.tools.some(t => t.toLowerCase().includes(q)) ||
      (a.mitre || []).some(m => m.toLowerCase().includes(q))
    ).length;
  }, [search]);

  return (
    <div style={{ padding: '24px 32px', maxWidth: 900 }}>
      
      <div className="mb-6">
        <h1 className="text-lg font-mono font-bold mb-1" style={{ color: T.text }}>
          Artefacts Windows
        </h1>
        <p className="text-sm" style={{ color: T.muted }}>
          {search ? `${totalVisible} artefact${totalVisible > 1 ? 's' : ''} trouvé${totalVisible > 1 ? 's' : ''}` : `${ARTIFACTS.length} artefacts — 3 catégories`}
          {' '}·{' '}
          <span style={{ color: 'var(--fl-gold)', fontSize: 11 }}>
            ★ Haute valeur forensique
          </span>
        </p>
      </div>

      {Object.entries(categories).map(([cat, items]) => {
        const visibleCount = items.filter(a => {
          if (!search) return true;
          const q = search.toLowerCase();
          return a.name.toLowerCase().includes(q) ||
            a.paths.some(p => p.toLowerCase().includes(q)) ||
            a.content.some(c => c.toLowerCase().includes(q)) ||
            (a.note || '').toLowerCase().includes(q) ||
            a.tools.some(t => t.toLowerCase().includes(q)) ||
            (a.mitre || []).some(m => m.toLowerCase().includes(q));
        }).length;
        if (visibleCount === 0) return null;
        return (
          <div key={cat} className="mb-8">
            <div className="flex items-center gap-3 mb-3">
              <h2 className="text-sm font-mono font-bold uppercase tracking-widest"
                style={{ color: T.accent }}>
                {cat}
              </h2>
              <div style={{ flex: 1, height: 1, background: T.border }} />
              <span className="text-xs font-mono" style={{ color: T.muted }}>
                {visibleCount}/{items.length}
              </span>
            </div>
            <div className="space-y-2">
              {items.map(a => (
                <ArtifactCard
                  key={a.name}
                  artifact={a}
                  search={search}
                  defaultOpen={false}
                />
              ))}
            </div>
          </div>
        );
      })}

      {totalVisible === 0 && (
        <div className="text-center py-16" style={{ color: T.muted }}>
          <p className="text-sm font-mono">Aucun artefact ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
