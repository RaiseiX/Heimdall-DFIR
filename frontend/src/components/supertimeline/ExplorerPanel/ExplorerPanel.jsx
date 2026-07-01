import { useEffect, useState } from 'react';
import { Layers, X } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import ArtifactsTab from './ArtifactsTab';
import TimelineTab  from './TimelineTab';
import EntitiesTab  from './EntitiesTab';
import TipsTab      from './TipsTab';

const TABS = [
  { key: 'artifacts', icon: '◈', label: 'Artifacts' },
  { key: 'timeline',  icon: '⊟', label: 'Timeline'  },
  { key: 'entities',  icon: '⊕', label: 'Entities'  },
  { key: 'tips',      icon: '?', label: 'Tips'       },
];

export default function ExplorerPanel() {
  const { explorerOpen, toggleExplorer } = useTimelineStore();
  const [activeTab, setActiveTab] = useState(() => {
    try { return localStorage.getItem('supertl.navTab') || 'artifacts'; } catch { return 'artifacts'; }
  });

  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable) return;
      if (e.key === 'e' || e.key === 'E') toggleExplorer();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [toggleExplorer]);

  function switchTab(key) {
    setActiveTab(key);
    try { localStorage.setItem('supertl.navTab', key); } catch { /**/ }
  }

  if (!explorerOpen) {
    return (
      <div style={{ width: 24, flexShrink: 0, background: 'var(--fl-bg)', borderRight: '1px solid var(--fl-raised)',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: 8, cursor: 'pointer' }}
        onClick={toggleExplorer} title="Open Navigator (E)">
        <Layers size={12} style={{ color: 'var(--fl-subtle)' }} />
      </div>
    );
  }

  return (
    <div style={{ width: 220, flexShrink: 0, background: 'var(--fl-bg)', borderRight: '1px solid var(--fl-raised)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* Tab bar */}
      <div style={{ height: 32, background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-raised)',
        display: 'flex', alignItems: 'stretch', flexShrink: 0 }}>
        {TABS.map(t => {
          const active = activeTab === t.key;
          return (
            <button key={t.key} onClick={() => switchTab(t.key)} style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 3,
              background: active ? 'var(--fl-panel)' : 'transparent',
              border: 'none',
              borderBottom: active ? '2px solid var(--fl-accent)' : '2px solid transparent',
              borderRight: '1px solid var(--fl-raised)',
              cursor: 'pointer', padding: 0,
            }}>
              <span style={{ fontSize: 9, color: active ? 'var(--fl-accent)' : 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                fontWeight: active ? 700 : 400, letterSpacing: '0.05em' }}>
                {t.icon} {t.label}
              </span>
            </button>
          );
        })}
        <button onClick={toggleExplorer} title="Close (E)"
          style={{ width: 24, flexShrink: 0, background: 'none', border: 'none', borderLeft: '1px solid var(--fl-raised)',
            color: 'var(--fl-subtle)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onMouseEnter={e => { e.currentTarget.style.color = '#7a8ba0'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
          <X size={10} />
        </button>
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {activeTab === 'artifacts' && <ArtifactsTab />}
        {activeTab === 'timeline'  && <TimelineTab  />}
        {activeTab === 'entities'  && <EntitiesTab  />}
        {activeTab === 'tips'      && <TipsTab      />}
      </div>
    </div>
  );
}
