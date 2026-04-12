
import { useState, useEffect, useRef, useMemo } from 'react';

export default function CommandPalette({ onClose, onCommand, recordCount, availTypes }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const COMMANDS = useMemo(() => [
    { id: 'view:timeline',  label: 'Afficher vue Timeline',        icon: '⏱',  group: 'Vues' },
    { id: 'view:gantt',     label: 'Afficher vue Gantt',           icon: '📊', group: 'Vues' },
    { id: 'view:heatmap',   label: 'Afficher Heatmap temporelle',  icon: '🔥', group: 'Vues' },
    { id: 'view:mitre',     label: 'Afficher MITRE ATT&CK Live',   icon: '🎯', group: 'Vues' },
    { id: 'view:playback',  label: 'Lancer la lecture chronologique', icon: '▶', group: 'Vues' },
    { id: 'tab:timeline',   label: 'Onglet Timeline',              icon: '🕐', group: 'Navigation' },
    { id: 'tab:persistence',label: 'Onglet Persistance',           icon: '🛡', group: 'Navigation' },
    { id: 'tab:dissim',     label: 'Onglet Dissimulation',         icon: '👁', group: 'Navigation' },
    { id: 'filter:critical',label: 'Filtrer Hayabusa critical',    icon: '🔴', group: 'Filtres' },
    { id: 'filter:high',    label: 'Filtrer Hayabusa high',        icon: '🟠', group: 'Filtres' },
    { id: 'filter:malware', label: 'Rechercher "malware"',         icon: '🔍', group: 'Filtres' },
    { id: 'filter:lsass',   label: 'Rechercher "lsass"',           icon: '🔍', group: 'Filtres' },
    { id: 'filter:powershell', label: 'Rechercher "powershell"',  icon: '🔍', group: 'Filtres' },
    ...(availTypes || []).map(t => ({
      id: `type:${t}`,
      label: `Filtrer par type: ${t}`,
      icon: '🏷',
      group: 'Types',
    })),
    { id: 'copy:all',       label: `Copier ${recordCount ?? 0} événements en CSV`, icon: '📋', group: 'Actions' },
    { id: 'export:stix',    label: 'Exporter STIX 2.1',            icon: '📦', group: 'Actions' },
    { id: 'exit',           label: 'Quitter le mode Investigation', icon: '✕',  group: 'Navigation' },
  ], [availTypes, recordCount]);

  const filtered = useMemo(() => {
    if (!query.trim()) return COMMANDS;
    const q = query.toLowerCase();
    return COMMANDS.filter(c => c.label.toLowerCase().includes(q) || c.group.toLowerCase().includes(q) || c.id.toLowerCase().includes(q));
  }, [query, COMMANDS]);

  const grouped = useMemo(() => {
    const map = new Map();
    for (const c of filtered) {
      if (!map.has(c.group)) map.set(c.group, []);
      map.get(c.group).push(c);
    }
    return [...map.entries()];
  }, [filtered]);

  const [selected, setSelected] = useState(0);
  const flat = filtered;

  function handleKey(e) {
    if (e.key === 'Escape') { onClose(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, flat.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
    if (e.key === 'Enter' && flat[selected]) { onCommand?.(flat[selected].id); onClose(); }
  }

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: 'rgba(0,0,0,0.7)',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
        paddingTop: '18vh',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: 520, background: '#0a1520', border: '1px solid var(--fl-accent)',
          borderRadius: 10, boxShadow: '0 20px 60px rgba(0,0,0,0.8)',
          overflow: 'hidden',
        }}
        onClick={e => e.stopPropagation()}
      >
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 14px', borderBottom: '1px solid var(--fl-bg)' }}>
          <span style={{ fontSize: 14, color: '#2a5a8a' }}>⌕</span>
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setSelected(0); }}
            onKeyDown={handleKey}
            placeholder="Commande ou filtre…"
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-on-dark)',
            }}
          />
          <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-accent)', border: '1px solid var(--fl-accent)', borderRadius: 3, padding: '1px 5px' }}>
            ESC
          </span>
        </div>

        <div style={{ maxHeight: 360, overflowY: 'auto', padding: '4px 0' }}>
          {grouped.length === 0 && (
            <div style={{ padding: '16px 14px', fontFamily: 'monospace', fontSize: 11, color: '#2a5a8a', textAlign: 'center' }}>
              Aucune commande trouvée
            </div>
          )}
          {grouped.map(([group, cmds]) => (
            <div key={group}>
              <div style={{ padding: '4px 14px 2px', fontFamily: 'monospace', fontSize: 8, color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                {group}
              </div>
              {cmds.map(cmd => {
                const idx = flat.indexOf(cmd);
                const isSel = idx === selected;
                return (
                  <div key={cmd.id}
                    onClick={() => { onCommand?.(cmd.id); onClose(); }}
                    onMouseEnter={() => setSelected(idx)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '7px 14px', cursor: 'pointer',
                      background: isSel ? '#0d1f35' : 'transparent',
                      borderLeft: `2px solid ${isSel ? 'var(--fl-accent)' : 'transparent'}`,
                    }}
                  >
                    <span style={{ fontSize: 12, flexShrink: 0 }}>{cmd.icon}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 11, color: isSel ? 'var(--fl-on-dark)' : '#7abfff' }}>
                      {cmd.label}
                    </span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        <div style={{ padding: '6px 14px', borderTop: '1px solid var(--fl-bg)', display: 'flex', gap: 12 }}>
          {[['↑↓', 'naviguer'], ['↵', 'exécuter'], ['Esc', 'fermer']].map(([k, l]) => (
            <div key={k} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
              <span style={{ fontSize: 8, fontFamily: 'monospace', border: '1px solid var(--fl-accent)', borderRadius: 2, padding: '1px 4px', color: '#2a5a8a' }}>{k}</span>
              <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)' }}>{l}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
