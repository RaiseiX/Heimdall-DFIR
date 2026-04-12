import { useState, useCallback } from 'react';
import { Shield, Terminal, Cpu, AlertTriangle, Search, BookMarked, X } from 'lucide-react';
import { useTheme } from '../utils/theme';
import WindowsArtifactsDoc from './documentation/WindowsArtifactsDoc';
import EventIdsDoc from './documentation/EventIdsDoc';
import MemoryForensicsDoc from './documentation/MemoryForensicsDoc';
import AttackPatternsDoc from './documentation/AttackPatternsDoc';

const SECTIONS = [
  {
    id: 'artifacts',
    label: 'Artefacts Windows',
    icon: Shield,
    desc: '15 artefacts — exécution, accès fichiers, persistance',
  },
  {
    id: 'event-ids',
    label: 'Event IDs Windows',
    icon: Terminal,
    desc: 'Security, System, PowerShell, RDP, WMI…',
  },
  {
    id: 'memory',
    label: 'Analyse Mémoire',
    icon: Cpu,
    desc: 'Volatility 3, acquisition RAM, fichiers résiduels',
  },
  {
    id: 'attacks',
    label: "Patterns d'Attaques",
    icon: AlertTriangle,
    desc: '7 scénarios — TTPs + artefacts + IOCs',
  },
];

export default function DocumentationPage() {
  const T = useTheme();
  const [activeSection, setActiveSection] = useState('artifacts');
  const [search, setSearch] = useState('');

  const clearSearch = useCallback(() => setSearch(''), []);

  const renderContent = () => {
    const props = { search };
    switch (activeSection) {
      case 'artifacts': return <WindowsArtifactsDoc {...props} />;
      case 'event-ids': return <EventIdsDoc {...props} />;
      case 'memory':    return <MemoryForensicsDoc {...props} />;
      case 'attacks':   return <AttackPatternsDoc {...props} />;
      default:          return null;
    }
  };

  return (
    <div className="flex h-full overflow-hidden" style={{ background: T.bg }}>

      <aside className="flex flex-col flex-shrink-0 overflow-y-auto"
        style={{ width: 240, background: T.panel, borderRight: `1px solid ${T.border}` }}>

        <div className="px-4 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
          <div className="flex items-center gap-2 mb-1">
            <BookMarked size={15} style={{ color: T.accent }} />
            <span className="font-mono font-semibold text-sm" style={{ color: T.text }}>
              Documentation
            </span>
          </div>
          <p className="text-xs" style={{ color: T.muted }}>
            Référence forensique intégrée
          </p>
        </div>

        <div className="px-3 py-3" style={{ borderBottom: `1px solid ${T.border}` }}>
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2"
              style={{ color: T.dim }} />
            <input
              type="text"
              placeholder="Rechercher…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{
                width: '100%', padding: '6px 28px 6px 28px',
                background: T.bg, border: `1px solid ${T.border}`,
                borderRadius: 6, fontSize: 12, fontFamily: 'monospace',
                color: T.text, outline: 'none',
              }}
            />
            {search && (
              <button onClick={clearSearch} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X size={11} style={{ color: T.dim }} />
              </button>
            )}
          </div>
        </div>

        <nav className="flex-1 p-2 space-y-1">
          {SECTIONS.map(s => {
            const active = activeSection === s.id;
            return (
              <button
                key={s.id}
                onClick={() => { setActiveSection(s.id); setSearch(''); }}
                className="w-full text-left rounded-lg transition-all"
                style={{
                  padding: '10px 12px',
                  background: active ? `${T.accent}14` : 'transparent',
                  border: `1px solid ${active ? T.accent + '40' : 'transparent'}`,
                  borderLeft: `3px solid ${active ? T.accent : 'transparent'}`,
                }}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <s.icon size={13} style={{ color: active ? T.accent : T.dim, flexShrink: 0 }} />
                  <span className="text-sm font-medium font-mono"
                    style={{ color: active ? T.accent : T.text }}>
                    {s.label}
                  </span>
                </div>
                <p className="text-xs ml-5" style={{ color: T.muted }}>{s.desc}</p>
              </button>
            );
          })}
        </nav>

        <div className="px-4 py-3" style={{ borderTop: `1px solid ${T.border}` }}>
          <p className="text-xs font-mono" style={{ color: T.muted }}>
            📋 Cliquer pour copier<br />
            🔍 Recherche en temps réel
          </p>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto" style={{ background: T.bg }}>
        {renderContent()}
      </main>
    </div>
  );
}
